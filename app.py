#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo


HOST = os.environ.get("PANEL_HOST", "127.0.0.1")
PORT = int(os.environ.get("PANEL_PORT", "8443"))
DATA_DIR = os.environ.get("PANEL_DATA_DIR", "/var/lib/incus-cn-panel")
PANEL_USER = os.environ.get("PANEL_USER", "admin")
PASSWORD_SALT = os.environ.get("PANEL_PASSWORD_SALT", "")
PASSWORD_HASH = os.environ.get("PANEL_PASSWORD_HASH", "")
PASSWORD_ITERATIONS = int(os.environ.get("PANEL_PASSWORD_ITERATIONS", "0"))
PANEL_CONFIG_FILE = os.environ.get(
    "PANEL_PASSWORD_CONFIG_FILE", os.path.join(DATA_DIR, "password.env")
)
TLS_CERT = os.environ.get("TLS_CERT", "/etc/incus-cn-panel/panel.crt")
TLS_KEY = os.environ.get("TLS_KEY", "/etc/incus-cn-panel/panel.key")
OPERATIONS_FILE = os.path.join(DATA_DIR, "operations.jsonl")
CREDENTIALS_FILE = os.path.join(DATA_DIR, "credentials.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
NOTIFICATION_CONFIG_FILE = os.path.join(DATA_DIR, "notification-config.json")
NOTIFICATIONS_FILE = os.path.join(DATA_DIR, "notifications.json")
TRAFFIC_FILE = os.path.join(DATA_DIR, "traffic-usage.json")
BACKUPS_FILE = os.path.join(DATA_DIR, "backups.json")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
DOMAINS_FILE = os.path.join(DATA_DIR, "domain-routes.json")
CADDY_ROUTES_FILE = os.path.join(DATA_DIR, "Caddyfile.routes")
ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
UPDATE_STATUS_FILE = os.path.join(DATA_DIR, "update-status.json")
TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")
NODE_HEALTH_FILE = os.path.join(DATA_DIR, "node-health.json")
RECONCILE_FILE = os.path.join(DATA_DIR, "reconcile-status.json")
UPDATER_PATH = os.environ.get("PANEL_UPDATER_PATH", "/usr/local/sbin/incus-cn-panel-update")
UPDATE_VERSION_URL = os.environ.get(
    "PANEL_UPDATE_VERSION_URL",
    "https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/VERSION",
)
UPDATE_REPOSITORY_URL = "https://github.com/NorwayXZ/incus-cn-panel"
SESSIONS = {}
LOGIN_ATTEMPTS = {}
REMOTE_CONFIG_LOCK = threading.Lock()
INSTANCE_MUTATION_LOCK = threading.RLock()
OPERATION_LOCK = threading.Lock()
CREDENTIALS_LOCK = threading.Lock()
USERS_LOCK = threading.Lock()
NOTIFICATION_LOCK = threading.RLock()
TRAFFIC_LOCK = threading.RLock()
BACKUP_LOCK = threading.RLock()
DOMAIN_LOCK = threading.RLock()
UPDATE_LOCK = threading.RLock()
TASK_LOCK = threading.RLock()
NODE_HEALTH_LOCK = threading.RLock()
RECONCILE_LOCK = threading.RLock()
PASSWORD_CONFIG_LOCK = threading.Lock()
NODE_LIVE_LOCK = threading.Lock()
MONITOR_SCAN_LOCK = threading.Lock()
MONITOR_WAKE_EVENT = threading.Event()
TASK_FUTURES = {}
TASK_EXECUTOR = None
TASK_RUNNERS = {}
LAST_RECONCILE_AT = 0.0
BACKUP_WAKE_EVENT = threading.Event()
SESSION_TTL = 12 * 60 * 60
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,31}$")
SIZE_RE = re.compile(r"^[1-9][0-9]*(MiB|GiB)$")
SIZE_VALUE_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([KMGTPE]?i?B)$", re.IGNORECASE)
RATE_RE = re.compile(r"^[1-9][0-9]*(kbit|Mbit|Gbit)$")
IMAGE_ALIAS_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$")
FINGERPRINT_RE = re.compile(r"^[a-fA-F0-9]{12,64}$")
SNAPSHOT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
BACKUP_ID_RE = re.compile(r"^[a-f0-9]{16}$")
SSH_PORT_MIN = 22000
SSH_PORT_MAX = 59999
HOST_PORT_MIN = 1024
HOST_PORT_MAX = 65535
MAX_PORTS_PER_INSTANCE = 1000
USER_PASSWORD_ITERATIONS = 260000
MAX_USER_ASSIGNMENTS = 500
MAX_JSON_BODY_BYTES = 128 * 1024
MAX_NOTIFICATION_EVENTS = 500
MAX_TRAFFIC_LIMIT_BYTES = 1024**5
MAX_TASKS = 300
RECONCILE_INTERVAL_SECONDS = 10 * 60
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PANEL_TIMEZONE = ZoneInfo(os.environ.get("PANEL_TIMEZONE", "Asia/Shanghai"))
MAX_IMAGE_UPLOAD_BYTES = int(os.environ.get("MAX_IMAGE_UPLOAD_BYTES", str(8 * 1024**3)))
NODE_LIVE_SAMPLES = {}
NODE_LIVE_INTERVAL_SECONDS = 5
MIB_BYTES = 1024**2
GIB_BYTES = 1024**3


def read_panel_version(path=VERSION_FILE):
    try:
        with open(path, encoding="utf-8") as handle:
            version = handle.read(64).strip()
    except OSError:
        return "0.0.0"
    return version if VERSION_RE.fullmatch(version) else "0.0.0"


APP_VERSION = read_panel_version()


RESOURCE_PROFILES = {
    "alpine": {
        "container": {"minimum_memory": "128MiB", "minimum_disk": "1GiB", "recommended_memory": "256MiB", "recommended_disk": "2GiB"},
        "virtual-machine": {"minimum_memory": "512MiB", "minimum_disk": "2GiB", "recommended_memory": "1GiB", "recommended_disk": "4GiB"},
    },
    "debian": {
        "container": {"minimum_memory": "256MiB", "minimum_disk": "3GiB", "recommended_memory": "512MiB", "recommended_disk": "5GiB"},
        "virtual-machine": {"minimum_memory": "1GiB", "minimum_disk": "5GiB", "recommended_memory": "2GiB", "recommended_disk": "10GiB"},
    },
    "ubuntu": {
        "container": {"minimum_memory": "512MiB", "minimum_disk": "4GiB", "recommended_memory": "1GiB", "recommended_disk": "8GiB"},
        "virtual-machine": {"minimum_memory": "1GiB", "minimum_disk": "6GiB", "recommended_memory": "2GiB", "recommended_disk": "12GiB"},
    },
    "rhel": {
        "container": {"minimum_memory": "512MiB", "minimum_disk": "5GiB", "recommended_memory": "1GiB", "recommended_disk": "8GiB"},
        "virtual-machine": {"minimum_memory": "2GiB", "minimum_disk": "10GiB", "recommended_memory": "4GiB", "recommended_disk": "20GiB"},
    },
    "generic": {
        "container": {"minimum_memory": "128MiB", "minimum_disk": "1GiB", "recommended_memory": "512MiB", "recommended_disk": "4GiB"},
        "virtual-machine": {"minimum_memory": "512MiB", "minimum_disk": "2GiB", "recommended_memory": "2GiB", "recommended_disk": "10GiB"},
    },
}
PUBLIC_IMAGES = (
    {"id": "images:alpine/3.22", "label": "Alpine 3.22", "family": "alpine", "release": "3.22", "channel": "稳定版"},
    {"id": "images:alpine/edge", "label": "Alpine Edge", "family": "alpine", "release": "edge", "channel": "滚动版"},
    {"id": "images:debian/12", "label": "Debian 12", "family": "debian", "release": "12", "channel": "稳定版"},
    {"id": "images:debian/13", "label": "Debian 13", "family": "debian", "release": "13", "channel": "稳定版"},
    {"id": "images:ubuntu/22.04", "label": "Ubuntu 22.04 LTS", "family": "ubuntu", "release": "22.04", "channel": "LTS"},
    {"id": "images:ubuntu/24.04", "label": "Ubuntu 24.04 LTS", "family": "ubuntu", "release": "24.04", "channel": "LTS"},
    {"id": "images:almalinux/9", "label": "AlmaLinux 9", "family": "rhel", "release": "9", "channel": "稳定版"},
    {"id": "images:rockylinux/9", "label": "Rocky Linux 9", "family": "rhel", "release": "9", "channel": "稳定版"},
)
PUBLIC_IMAGE_MAP = {image["id"]: image for image in PUBLIC_IMAGES}
ALERT_RULES = {
    "monitor_failure": {
        "label": "控制端巡检任务失败",
        "description": "控制端无法读取节点列表或完成本轮巡检。",
        "severity": "critical",
        "default_mode": "panel_telegram",
    },
    "node_offline": {
        "label": "宿主机离线或 Incus API 无法连接",
        "description": "连接超时、TLS/证书错误、Incus 服务停止或网络中断。",
        "severity": "critical",
        "default_mode": "panel_telegram",
    },
    "node_memory_high": {
        "label": "宿主机内存使用率过高",
        "description": "达到设定阈值后告警，恢复到阈值以下时自动解除。",
        "severity": "warning",
        "default_mode": "panel_telegram",
    },
    "node_disk_high": {
        "label": "宿主机存储池使用率过高",
        "description": "default 存储池达到设定阈值，可能导致实例写入失败。",
        "severity": "critical",
        "default_mode": "panel_telegram",
    },
    "node_load_high": {
        "label": "宿主机 1 分钟负载过高",
        "description": "按 1 分钟负载与 CPU 核心数的比例判断。",
        "severity": "warning",
        "default_mode": "panel",
    },
    "node_image_error": {
        "label": "宿主机镜像查询失败",
        "description": "Incus 在线，但本地镜像目录读取失败。",
        "severity": "warning",
        "default_mode": "panel",
    },
    "instance_memory_high": {
        "label": "实例内存使用率过高",
        "description": "按实例当前用量与 Incus 内存上限的比例判断。",
        "severity": "warning",
        "default_mode": "panel",
    },
    "instance_cpu_high": {
        "label": "实例持续 CPU 使用率过高",
        "description": "从相邻两次巡检的 CPU 时间差计算，首次巡检不会触发。",
        "severity": "warning",
        "default_mode": "off",
    },
    "instance_not_running": {
        "label": "实例不在运行状态",
        "description": "包括管理员主动停止，适合要求实例持续运行的场景。",
        "severity": "critical",
        "default_mode": "off",
    },
    "instance_no_ipv4": {
        "label": "运行中的实例没有 IPv4",
        "description": "可能是网桥、DHCP、系统网络或 Incus Agent 异常。",
        "severity": "warning",
        "default_mode": "off",
    },
    "instance_missing": {
        "label": "实例从在线宿主机消失",
        "description": "检测到实例被外部删除或未被 Incus 返回；首次巡检不会触发。",
        "severity": "critical",
        "default_mode": "off",
    },
    "instance_traffic_exceeded": {
        "label": "实例本月流量超过配额",
        "description": "按实例网卡接收与发送字节合计统计，超过配额后按实例设置处置。",
        "severity": "critical",
        "default_mode": "panel_telegram",
    },
}


def run_incus(*args, timeout=120):
    cache_dir = os.environ.get("XDG_CACHE_HOME") or os.path.join(DATA_DIR, "cache")
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    result = subprocess.run(
        ["/usr/bin/incus", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "LC_ALL": "C.UTF-8", "XDG_CACHE_HOME": cache_dir},
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "Incus 命令执行失败").strip()
        raise RuntimeError(message[-1000:])
    return result.stdout


def password_matches(password):
    if PASSWORD_ITERATIONS > 0:
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(PASSWORD_SALT), PASSWORD_ITERATIONS
        ).hex()
    else:
        candidate = hashlib.sha256(f"{PASSWORD_SALT}{password}".encode()).hexdigest()
    return hmac.compare_digest(candidate, PASSWORD_HASH)


def _write_password_config(path, values):
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        raise RuntimeError(f"无法读取面板账户配置: {exc}") from exc

    key_pattern = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
    seen = set()
    updated = []
    for line in lines:
        match = key_pattern.match(line)
        key = match.group(1) if match else ""
        if key not in values:
            updated.append(line)
            continue
        if key not in seen:
            updated.append(f"{key}={values[key]}\n")
            seen.add(key)

    if updated and not updated[-1].endswith(("\n", "\r")):
        updated[-1] += "\n"
    for key, value in values.items():
        if key not in seen:
            updated.append(f"{key}={value}\n")

    directory = os.path.dirname(path) or "."
    descriptor, temporary = tempfile.mkstemp(prefix=".config.env.", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.writelines(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def change_admin_password(current_password, new_password):
    global PASSWORD_SALT, PASSWORD_HASH, PASSWORD_ITERATIONS

    current_password = str(current_password)
    new_password = str(new_password)
    if not 10 <= len(new_password) <= 128:
        raise ValueError("新密码长度必须在 10 到 128 个字符之间")

    with PASSWORD_CONFIG_LOCK:
        if not password_matches(current_password):
            raise ValueError("当前密码错误")
        if hmac.compare_digest(current_password, new_password):
            raise ValueError("新密码不能与当前密码相同")

        salt = secrets.token_hex(16)
        iterations = USER_PASSWORD_ITERATIONS
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", new_password.encode(), bytes.fromhex(salt), iterations
        ).hex()
        _write_password_config(PANEL_CONFIG_FILE, {
            "PANEL_PASSWORD_SALT": salt,
            "PANEL_PASSWORD_HASH": password_hash,
            "PANEL_PASSWORD_ITERATIONS": str(iterations),
        })
        PASSWORD_SALT = salt
        PASSWORD_HASH = password_hash
        PASSWORD_ITERATIONS = iterations

        for token, session in list(SESSIONS.items()):
            if session.get("role") == "admin":
                SESSIONS.pop(token, None)


def _read_users_unlocked():
    try:
        with open(USERS_FILE, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"无法读取用户数据: {exc}") from exc
    users = data.get("users", {}) if isinstance(data, dict) else {}
    return users if isinstance(users, dict) else {}


def _write_users_unlocked(users):
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    temporary = f"{USERS_FILE}.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "users": users}, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, USERS_FILE)
        os.chmod(USERS_FILE, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _password_record(password):
    if not 10 <= len(password) <= 128:
        raise ValueError("密码长度必须在 10 到 128 个字符之间")
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), USER_PASSWORD_ITERATIONS
    ).hex()
    return {
        "password_salt": salt,
        "password_hash": password_hash,
        "password_iterations": USER_PASSWORD_ITERATIONS,
    }


def parse_assignment_expiry(value):
    text = str(value).strip()
    try:
        expires = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("授权到期时间无效") from exc
    if expires.tzinfo is None:
        raise ValueError("授权到期时间必须包含时区")
    return expires.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def assignment_is_active(expires_at, now=None):
    try:
        expires = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
    except ValueError:
        return False
    if expires.tzinfo is None:
        return False
    return expires > (now or datetime.now(timezone.utc))


def assignment_map(record):
    assignments = record.get("assignments", {}) if isinstance(record, dict) else {}
    return assignments if isinstance(assignments, dict) else {}


def _public_user(username, record):
    assignments = [
        {
            "instance": key,
            "expires_at": str(expires_at),
            "active": assignment_is_active(expires_at),
        }
        for key, expires_at in sorted(assignment_map(record).items())
    ]
    return {
        "username": username,
        "enabled": bool(record.get("enabled", True)),
        "assignments": assignments,
        "created_at": str(record.get("created_at", "")),
    }


def list_user_accounts():
    with USERS_LOCK:
        users = _read_users_unlocked()
        return [_public_user(username, users[username]) for username in sorted(users)]


def get_user_account(username):
    with USERS_LOCK:
        record = _read_users_unlocked().get(str(username).lower())
        return dict(record) if isinstance(record, dict) else None


def create_user_account(username, password):
    username = str(username).strip().lower()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("用户名需为 3-32 位字母、数字、点、下划线或连字符")
    if hmac.compare_digest(username.lower(), PANEL_USER.lower()):
        raise ValueError("该用户名与管理员账号冲突")
    record = {
        **_password_record(str(password)),
        "enabled": True,
        "assignments": {},
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with USERS_LOCK:
        users = _read_users_unlocked()
        if username in users:
            raise ValueError("用户名已经存在")
        users[username] = record
        _write_users_unlocked(users)
    return _public_user(username, record)


def normalize_assignments(value):
    if not isinstance(value, list) or len(value) > MAX_USER_ASSIGNMENTS:
        raise ValueError(f"实例授权必须是列表且不能超过 {MAX_USER_ASSIGNMENTS} 项")
    assignments = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("实例授权格式无效")
        key = str(item.get("instance", ""))
        if "/" not in key:
            raise ValueError("实例授权格式无效")
        node, name = key.split("/", 1)
        if not NAME_RE.fullmatch(node) or not NAME_RE.fullmatch(name):
            raise ValueError("实例授权格式无效")
        assignments[f"{node}/{name}"] = parse_assignment_expiry(item.get("expires_at", ""))
    return assignments


def invalidate_user_sessions(username):
    for token, session in list(SESSIONS.items()):
        if session.get("role") == "user" and session.get("username") == username:
            SESSIONS.pop(token, None)


def update_user_account(username, enabled=None, password=None, assignments=None):
    username = str(username).lower()
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("账户状态无效")
    with USERS_LOCK:
        users = _read_users_unlocked()
        record = users.get(username)
        if not isinstance(record, dict):
            raise ValueError("用户不存在")
        if enabled is not None:
            record["enabled"] = bool(enabled)
        if password:
            record.update(_password_record(str(password)))
        if assignments is not None:
            record["assignments"] = normalize_assignments(assignments)
        users[username] = record
        _write_users_unlocked(users)
    if enabled is False or password:
        invalidate_user_sessions(username)
    return _public_user(username, record)


def delete_user_account(username):
    username = str(username).lower()
    with USERS_LOCK:
        users = _read_users_unlocked()
        if username not in users:
            raise ValueError("用户不存在")
        users.pop(username)
        _write_users_unlocked(users)
    invalidate_user_sessions(username)


def remove_instance_assignments(node, name=None):
    prefix = f"{node}/"
    key = f"{node}/{name}" if name is not None else ""
    with USERS_LOCK:
        users = _read_users_unlocked()
        changed = False
        for record in users.values():
            assignments = assignment_map(record)
            filtered = {
                item: expires_at for item, expires_at in assignments.items()
                if item != key
            } if name is not None else {
                item: expires_at for item, expires_at in assignments.items()
                if not item.startswith(prefix)
            }
            if filtered != assignments:
                record["assignments"] = filtered
                changed = True
        if changed:
            _write_users_unlocked(users)


def account_password_matches(record, password):
    try:
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(str(record["password_salt"])),
            int(record["password_iterations"]),
        ).hex()
        return hmac.compare_digest(candidate, str(record["password_hash"]))
    except (KeyError, TypeError, ValueError):
        return False


def authenticate_account(username, password):
    username = str(username).strip()
    password = str(password)
    if hmac.compare_digest(username, PANEL_USER) and password_matches(password):
        return {"username": PANEL_USER, "role": "admin"}
    normalized = username.lower()
    record = get_user_account(normalized)
    if record and bool(record.get("enabled", True)) and account_password_matches(record, password):
        return {"username": normalized, "role": "user"}
    return None


def session_can_access_instance(session, node, name):
    if session.get("role") == "admin":
        return True
    record = get_user_account(session.get("username", ""))
    expires_at = assignment_map(record).get(f"{node}/{name}") if record else None
    return bool(record and record.get("enabled", True) and assignment_is_active(expires_at))


def clean_sessions():
    now = time.time()
    for token, data in list(SESSIONS.items()):
        if data["expires"] < now:
            SESSIONS.pop(token, None)


def record_operation(action, target, node="", status="success", message=""):
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "action": action,
        "target": str(target)[:128],
        "node": str(node)[:63],
        "status": status,
        "message": str(message).replace("\n", " ")[:500],
    }
    try:
        with OPERATION_LOCK:
            os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
            with open(OPERATIONS_FILE, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"无法写入操作日志: {exc}", flush=True)


def recent_operations(limit=50):
    try:
        with OPERATION_LOCK, open(OPERATIONS_FILE, encoding="utf-8") as handle:
            lines = deque(handle, maxlen=max(1, min(int(limit), 200)))
    except FileNotFoundError:
        return []
    entries = []
    for line in reversed(lines):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _read_credentials_unlocked():
    try:
        with open(CREDENTIALS_FILE, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"无法读取实例连接凭据: {exc}") from exc
    return data if isinstance(data, dict) else {}


def save_instance_credentials(node, name, access):
    key = f"{node}/{name}"
    with CREDENTIALS_LOCK:
        credentials = _read_credentials_unlocked()
        credentials[key] = access
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        temporary = f"{CREDENTIALS_FILE}.{os.getpid()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(credentials, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            os.replace(temporary, CREDENTIALS_FILE)
            os.chmod(CREDENTIALS_FILE, 0o600)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


def instance_credentials(node, name):
    with CREDENTIALS_LOCK:
        access = _read_credentials_unlocked().get(f"{node}/{name}")
    if not access:
        raise ValueError("该实例没有由面板生成的 SSH 连接凭据")
    return dict(access)


def delete_credentials(node, name=None):
    with CREDENTIALS_LOCK:
        credentials = _read_credentials_unlocked()
        if name is None:
            prefix = f"{node}/"
            keys = [key for key in credentials if key.startswith(prefix)]
            for key in keys:
                credentials.pop(key, None)
            changed = bool(keys)
        else:
            changed = credentials.pop(f"{node}/{name}", None) is not None
        if not changed:
            return
        temporary = f"{CREDENTIALS_FILE}.{os.getpid()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(credentials, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, CREDENTIALS_FILE)
        os.chmod(CREDENTIALS_FILE, 0o600)


def normalize_address(value):
    candidate = value.strip()
    if "://" not in candidate:
        if candidate.count(":") > 1 and not candidate.startswith("["):
            candidate = f"[{candidate}]"
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("节点地址必须是 IP、域名或 HTTPS 地址")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("节点地址不能包含账号、查询参数或片段")
    if parsed.path not in {"", "/"}:
        raise ValueError("节点地址不能包含路径")
    try:
        port = parsed.port or 8443
    except ValueError as exc:
        raise ValueError("节点端口无效") from exc
    if not 1 <= port <= 65535:
        raise ValueError("节点端口无效")
    hostname = parsed.hostname
    if ":" in hostname:
        hostname = f"[{hostname}]"
    return f"https://{hostname}:{port}"


def registered_remotes():
    raw = json.loads(run_incus("remote", "list", "--format=json", timeout=20))
    return {
        name: config
        for name, config in raw.items()
        if name != "local"
        and config.get("Protocol") == "incus"
        and not config.get("Public", False)
    }


def require_node(name):
    if not NAME_RE.fullmatch(name):
        raise ValueError("节点名称无效")
    if name not in registered_remotes():
        raise ValueError("节点不存在或尚未注册")
    return name


class NodeConnectionError(RuntimeError):
    def __init__(self, stage, summary, detail="", hints=None, status=502):
        super().__init__(summary)
        self.stage = stage
        self.summary = summary
        self.detail = detail
        self.hints = list(hints or [])
        self.status = status

    def payload(self):
        return {
            "error": self.summary,
            "stage": self.stage,
            "detail": self.detail,
            "hints": self.hints,
        }


def node_connection_failure(stage, exc, token="", address=""):
    detail = str(exc).strip() or "Incus 未返回具体错误"
    if token:
        detail = detail.replace(token, "***")
    detail = detail[-1000:]
    lowered = detail.lower()
    common_hints = [
        f"确认控制面板服务器能够访问 {address}",
        "确认宿主机防火墙和云安全组已放行 Incus TCP 端口",
    ]
    if isinstance(exc, subprocess.TimeoutExpired) or "timed out" in lowered or "timeout" in lowered:
        return NodeConnectionError(
            stage, "连接宿主机超时", detail,
            common_hints + ["确认 Incus 服务正在运行并监听外网地址"], 504,
        )
    if any(value in lowered for value in ("connection refused", "actively refused")):
        return NodeConnectionError(
            stage, "Incus 端口拒绝连接", detail,
            common_hints + ["在宿主机执行 systemctl status incus 检查服务状态"],
        )
    if any(value in lowered for value in ("no route to host", "network is unreachable")):
        return NodeConnectionError(
            stage, "控制面板无法到达宿主机", detail,
            common_hints + ["检查公网 IP、路由和服务商网络 ACL"],
        )
    if any(value in lowered for value in (
        "no such host", "name or service not known", "nodename nor servname provided",
    )):
        return NodeConnectionError(
            stage, "无法解析宿主机地址", detail,
            ["检查填写的域名或 IP 是否正确", "若使用域名，请确认控制面板服务器的 DNS 解析正常"],
        )
    if "certificate fingerprint mismatch" in lowered:
        return NodeConnectionError(
            stage, "Token 与目标宿主机的 TLS 证书不匹配", detail,
            ["确认填写的是生成该 Token 的同一台宿主机", "在目标宿主机重新生成 Trust Token 后重试"],
        )
    if any(value in lowered for value in (
        "invalid trust token", "token has expired", "token is expired",
        "certificate add token", "failed to create certificate", "not authorized",
        "authentication failure", "server doesn't trust us",
    )):
        return NodeConnectionError(
            stage, "Trust Token 已失效、已使用或不属于该宿主机", detail,
            ["Trust Token 通常只能使用一次，请在宿主机重新生成", "生成后尽快粘贴完整 Token 再试"],
        )
    summaries = {
        "控制端检查": "控制面板的 Incus 客户端不可用",
        "连接与信任": "无法连接宿主机或建立 TLS 信任",
        "API 验证": "已建立信任，但 Incus API 验证失败",
        "资源检查": "Incus 无法读取宿主机资源信息",
        "存储检查": "宿主机缺少可用的 default 存储池",
        "网络检查": "宿主机缺少可用的 incusbr0 实例网络",
    }
    hints = common_hints
    if stage == "存储检查":
        hints = ["在宿主机执行 incus storage list", "确认存在名为 default 且状态正常的存储池"]
    elif stage == "网络检查":
        hints = ["在宿主机执行 incus network list", "确认存在名为 incusbr0 的托管 NAT 网桥"]
    elif stage == "控制端检查":
        hints = ["检查控制面板服务日志", "确认 /usr/bin/incus 和面板 Incus 客户端配置可用"]
    return NodeConnectionError(stage, summaries.get(stage, "宿主机验证失败"), detail, hints)


def add_remote(name, address, token):
    with REMOTE_CONFIG_LOCK:
        try:
            remotes = registered_remotes()
        except Exception as exc:
            raise node_connection_failure("控制端检查", exc, token, address) from exc
        if name in remotes:
            raise ValueError("节点名称已经存在")
        try:
            run_incus(
                "remote", "add", name, address, "--token", token,
                "--accept-certificate", timeout=90,
            )
        except Exception as exc:
            try:
                run_incus("remote", "remove", name, timeout=20)
            except Exception:
                pass
            raise node_connection_failure("连接与信任", exc, token, address) from exc
        checks = (
            ("API 验证", ("query", f"{name}:/1.0")),
            ("资源检查", ("query", f"{name}:/1.0/resources")),
            ("存储检查", ("query", f"{name}:/1.0/storage-pools/default")),
            ("网络检查", ("query", f"{name}:/1.0/networks/incusbr0")),
        )
        for stage, command in checks:
            try:
                run_incus(*command, timeout=20)
            except Exception as exc:
                try:
                    run_incus("remote", "remove", name, timeout=20)
                except Exception:
                    pass
                raise node_connection_failure(stage, exc, token, address) from exc
        try:
            node_preflight(name)
        except Exception:
            # The trust relationship is valid at this point. A later health check can retry
            # optional capability discovery without discarding the newly added remote.
            pass


def format_bytes(value):
    value = int(value or 0)
    if value >= 1024**4:
        return f"{value / 1024**4:.2f} TiB"
    if value >= 1024**3:
        return f"{value / 1024**3:.1f} GiB"
    return f"{value / 1024**2:.0f} MiB"


def parse_size_bytes(value):
    candidate = str(value or "").strip()
    match = SIZE_VALUE_RE.fullmatch(candidate)
    if not match:
        return 0
    number = float(match.group(1))
    unit = match.group(2).upper()
    decimal = not unit.endswith("IB")
    prefix = unit[0] if len(unit) > 1 else ""
    exponent = {"": 0, "K": 1, "M": 2, "G": 3, "T": 4, "P": 5, "E": 6}.get(prefix)
    if exponent is None:
        return 0
    return int(number * ((1000 if decimal else 1024) ** exponent))


def host_memory_reserve(total):
    total = max(0, int(total or 0))
    if not total:
        return 0
    reserve_step = 512 * MIB_BYTES
    proportional = ((total // 10 + reserve_step - 1) // reserve_step) * reserve_step
    target = max(reserve_step, proportional)
    return min(target, total // 2)


def host_disk_reserve(total):
    total = max(0, int(total or 0))
    if not total:
        return 0
    proportional = ((total // 20 + GIB_BYTES - 1) // GIB_BYTES) * GIB_BYTES
    target = max(2 * GIB_BYTES, proportional)
    return min(target, max(512 * MIB_BYTES, total // 4))


def recommended_swap_bytes(memory, disk, kind="container"):
    if kind != "container":
        return 0
    memory_bytes = parse_size_bytes(memory)
    disk_bytes = parse_size_bytes(disk)
    if not memory_bytes or not disk_bytes:
        return 0
    if memory_bytes <= 512 * MIB_BYTES:
        target = 512 * MIB_BYTES
    elif memory_bytes <= GIB_BYTES:
        target = GIB_BYTES
    elif memory_bytes <= 2 * GIB_BYTES:
        target = 2 * GIB_BYTES
    elif memory_bytes <= 4 * GIB_BYTES:
        target = 2 * GIB_BYTES
    elif memory_bytes <= 8 * GIB_BYTES:
        target = 4 * GIB_BYTES
    else:
        target = 8 * GIB_BYTES
    disk_limit = disk_bytes // 2
    tiers = (128, 256, 512, 1024, 2048, 4096, 8192)
    eligible = [
        tier * MIB_BYTES
        for tier in tiers
        if tier * MIB_BYTES <= target and tier * MIB_BYTES <= disk_limit
    ]
    return max(eligible, default=0)


def format_binary_size(value):
    value = int(value or 0)
    if value and value % GIB_BYTES == 0:
        return f"{value // GIB_BYTES}GiB"
    return f"{value // MIB_BYTES}MiB"


def host_cpu_budget_percent(cpu_total):
    return max(0, int(cpu_total or 0) * 85)


def instance_cpu_commitment_percent(instance, cpu_total=0):
    cpu_value = str(instance.get("cpu", ""))
    cpu_percent = (
        int(cpu_value) * 100
        if cpu_value.isdigit()
        else max(0, int(cpu_total or 0)) * 100
    )
    if instance.get("type") == "virtual-machine":
        return cpu_percent
    allowance = str(instance.get("cpu_allowance", ""))
    hard = re.fullmatch(r"([0-9]+)ms/([1-9][0-9]*)ms", allowance)
    if hard:
        return (int(hard.group(1)) * 100 + int(hard.group(2)) - 1) // int(hard.group(2))
    # Percentage allowances are soft shares, so reserve all visible vCPUs.
    return cpu_percent


def allocation_summary(instances, memory_total=0, cpu_total=0):
    cpu = 0
    cpu_commitment_percent = 0
    memory = 0
    disk = 0
    unlimited = 0
    ssh_ports = 0
    forwarded_ports = 0
    for instance in instances:
        cpu_value = str(instance.get("cpu", ""))
        memory_value = str(instance.get("memory", ""))
        disk_value = str(instance.get("disk", ""))
        if cpu_value.isdigit():
            cpu += int(cpu_value)
        else:
            unlimited += 1
        cpu_commitment_percent += instance_cpu_commitment_percent(instance, cpu_total)
        if memory_value.endswith("%"):
            try:
                memory += int(memory_total * float(memory_value[:-1]) / 100)
            except ValueError:
                pass
        else:
            memory += parse_size_bytes(memory_value)
        disk += parse_size_bytes(disk_value)
        if str(instance.get("ssh_port", "")).isdigit():
            ssh_ports += 1
        start = str(instance.get("port_start", ""))
        end = str(instance.get("port_end", ""))
        if start.isdigit() and end.isdigit() and int(start) <= int(end):
            forwarded_ports += int(end) - int(start) + 1
    return {
        "cpu": cpu,
        "cpu_commitment_percent": cpu_commitment_percent,
        "memory": memory,
        "disk": disk,
        "unlimited_instances": unlimited,
        "ssh_ports": ssh_ports,
        "forwarded_ports": forwarded_ports,
    }


def parse_instances(node, raw):
    instances = []
    for item in raw:
        state = item.get("state") or {}
        memory_state = state.get("memory") or {}
        cpu_state = state.get("cpu") or {}
        network_rx_bytes = 0
        network_tx_bytes = 0
        ipv4 = ""
        for interface_name, interface in (state.get("network") or {}).items():
            if interface_name != "lo" and interface.get("type") != "loopback":
                counters = interface.get("counters") or {}
                network_rx_bytes += int(counters.get("bytes_received", 0) or 0)
                network_tx_bytes += int(counters.get("bytes_sent", 0) or 0)
            for address in interface.get("addresses", []):
                if not ipv4 and address.get("family") == "inet" and address.get("scope") == "global":
                    ipv4 = address.get("address", "")
                    break
        config = item.get("expanded_config") or item.get("config") or {}
        devices = item.get("expanded_devices") or item.get("devices") or {}
        root_device = next(
            (device for device in devices.values() if device.get("type") == "disk" and device.get("path") == "/"),
            {},
        )
        instances.append({
            "node": node,
            "name": item.get("name", ""),
            "type": item.get("type", "container"),
            "status": item.get("status", "Unknown"),
            "ipv4": ipv4,
            "cpu": config.get("limits.cpu", "不限"),
            "cpu_allowance": config.get("limits.cpu.allowance", "100%"),
            "memory": config.get("limits.memory", "不限"),
            "swap": config.get("limits.memory.swap", "未配置"),
            "disk": root_device.get("size", "不限"),
            "image": config.get("user.incus-cn-panel.image", "未知镜像"),
            "ssh_port": config.get("user.incus-cn-panel.ssh-port", ""),
            "port_start": config.get("user.incus-cn-panel.port-start", ""),
            "port_end": config.get("user.incus-cn-panel.port-end", ""),
            "traffic_limit_bytes": int(
                config.get("user.incus-cn-panel.traffic-limit-bytes", 0) or 0
            ),
            "traffic_action": config.get(
                "user.incus-cn-panel.traffic-action", "stop"
            ),
            "network_rx_bytes": network_rx_bytes,
            "network_tx_bytes": network_tx_bytes,
            "memory_used_bytes": int(memory_state.get("usage", 0) or 0),
            "memory_total_bytes": int(memory_state.get("total", 0) or 0),
            "cpu_usage_ns": int(cpu_state.get("usage", 0) or 0),
            "cpu_allocated_ns": int(cpu_state.get("allocated_time", 0) or 0),
        })
    return instances


def image_family(value):
    candidate = str(value or "").lower()
    if "alpine" in candidate:
        return "alpine"
    if "debian" in candidate:
        return "debian"
    if "ubuntu" in candidate:
        return "ubuntu"
    if any(name in candidate for name in ("almalinux", "rockylinux", "centos", "rhel")):
        return "rhel"
    return "generic"


def resource_profile(family, kind):
    if kind not in {"container", "virtual-machine"}:
        raise ValueError("实例类型无效")
    return dict(RESOURCE_PROFILES.get(family, RESOURCE_PROFILES["generic"])[kind])


def public_image_catalog():
    catalog = []
    for image in PUBLIC_IMAGES:
        item = dict(image)
        item["source"] = "public"
        item["profiles"] = {
            kind: resource_profile(item["family"], kind)
            for kind in ("container", "virtual-machine")
        }
        catalog.append(item)
    return catalog


def parse_node_images(node, raw):
    images = []
    for item in raw:
        fingerprint = str(item.get("fingerprint", ""))
        if not FINGERPRINT_RE.fullmatch(fingerprint):
            continue
        properties = item.get("properties") or {}
        aliases = sorted({
            str(alias.get("name", ""))
            for alias in item.get("aliases") or []
            if IMAGE_ALIAS_RE.fullmatch(str(alias.get("name", "")))
        })
        family = image_family(" ".join([
            properties.get("os", ""), properties.get("distribution", ""),
            properties.get("description", ""), *aliases,
        ]))
        kind = "virtual-machine" if item.get("type") == "virtual-machine" else "container"
        images.append({
            "id": f"local:{fingerprint}",
            "node": node,
            "fingerprint": fingerprint,
            "short_fingerprint": fingerprint[:12],
            "aliases": aliases,
            "label": aliases[0] if aliases else properties.get("description") or fingerprint[:12],
            "description": properties.get("description", ""),
            "family": family,
            "release": properties.get("release", ""),
            "architecture": item.get("architecture", ""),
            "kind": kind,
            "size": int(item.get("size", 0) or 0),
            "uploaded_at": item.get("uploaded_at", ""),
            "last_used_at": item.get("last_used_at", ""),
            "source": "local",
            "profiles": {kind: resource_profile(family, kind)},
        })
    return sorted(images, key=lambda item: (item["label"].lower(), item["fingerprint"]))


def list_node_images(node):
    node = require_node(node)
    raw = json.loads(run_incus("image", "list", f"{node}:", "--format=json", timeout=30))
    return parse_node_images(node, raw)


def resolve_image(node, image_id, kind):
    if image_id in PUBLIC_IMAGE_MAP:
        item = dict(PUBLIC_IMAGE_MAP[image_id])
        item.update({"source": "public", "reference": image_id})
    else:
        match = re.fullmatch(r"local:([a-fA-F0-9]{12,64})", image_id)
        if not match:
            raise ValueError("系统镜像无效")
        fingerprint = match.group(1).lower()
        matches = [
            image for image in list_node_images(node)
            if image["fingerprint"].lower().startswith(fingerprint)
        ]
        if len(matches) != 1:
            raise ValueError("本地镜像不存在或指纹不唯一")
        item = dict(matches[0])
        if item["kind"] != kind:
            expected = "KVM 虚拟机" if item["kind"] == "virtual-machine" else "LXC 容器"
            raise ValueError(f"该本地镜像仅支持 {expected}")
        item["reference"] = f"{node}:{item['fingerprint']}"
    item["profile"] = resource_profile(item.get("family", "generic"), kind)
    return item


def validate_minimum_resources(memory, disk, profile):
    if parse_size_bytes(memory) < parse_size_bytes(profile["minimum_memory"]):
        raise ValueError(f"该系统最低需要 {profile['minimum_memory']} 内存")
    if parse_size_bytes(disk) < parse_size_bytes(profile["minimum_disk"]):
        raise ValueError(f"该系统最低需要 {profile['minimum_disk']} 系统盘")


def copy_public_image(node, image_id, alias=""):
    node = require_node(node)
    if image_id not in PUBLIC_IMAGE_MAP:
        raise ValueError("公共镜像无效")
    if alias and not IMAGE_ALIAS_RE.fullmatch(alias):
        raise ValueError("镜像别名只能包含字母、数字、点、斜杠、下划线和连字符")
    args = ["image", "copy", image_id, f"{node}:"]
    if alias:
        args.extend(["--alias", alias])
    run_incus(*args, timeout=1800)
    return list_node_images(node)


def import_local_image(node, filename, alias=""):
    node = require_node(node)
    if alias and not IMAGE_ALIAS_RE.fullmatch(alias):
        raise ValueError("镜像别名只能包含字母、数字、点、斜杠、下划线和连字符")
    args = ["image", "import", filename, f"{node}:"]
    if alias:
        args.extend(["--alias", alias])
    run_incus(*args, timeout=1800)
    return list_node_images(node)


def delete_local_image(node, fingerprint):
    node = require_node(node)
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise ValueError("镜像指纹无效")
    run_incus("image", "delete", f"{node}:{fingerprint}", timeout=180)


def inspect_node(name, remote):
    address = (remote.get("Addrs") or [""])[0]
    try:
        resources = json.loads(run_incus("query", f"{name}:/1.0/resources", timeout=15))
        raw_instances = json.loads(run_incus("list", f"{name}:", "--format=json", timeout=20))
        instances = parse_instances(name, raw_instances)
        memory = resources.get("memory") or {}
        storage_disks = (resources.get("storage") or {}).get("disks") or []
        hardware_disk_total = sum(
            int(disk.get("size", 0))
            for disk in storage_disks
            if not disk.get("removable", False) and not disk.get("read_only", False)
        )
        disk_total = hardware_disk_total
        disk_used = 0
        try:
            pool_resources = json.loads(
                run_incus("query", f"{name}:/1.0/storage-pools/default/resources", timeout=15)
            )
            space = pool_resources.get("space") or {}
            disk_total = int(space.get("total", 0)) or hardware_disk_total
            disk_used = int(space.get("used", 0))
        except Exception:
            pass
        cpu_total = int((resources.get("cpu") or {}).get("total", 0))
        allocations = allocation_summary(
            instances, int(memory.get("total", 0)), cpu_total
        )
        occupied_ports = occupied_host_ports(instances)
        memory_total = int(memory.get("total", 0))
        memory_used = int(memory.get("used", 0))
        instance_memory_used = sum(
            int(instance.get("memory_used_bytes", 0) or 0)
            for instance in instances
        )
        host_memory_used = max(0, memory_used - instance_memory_used)
        memory_reserve = host_memory_reserve(memory_total)
        memory_committed = max(memory_used, host_memory_used + allocations["memory"])
        disk_reserve = host_disk_reserve(disk_total)
        disk_committed = max(disk_used, allocations["disk"])
        cpu_budget_percent = host_cpu_budget_percent(cpu_total)
        cpu_committed_percent = allocations["cpu_commitment_percent"]
        cpu_available_percent = max(0, cpu_budget_percent - cpu_committed_percent)
        load = resources.get("load") or {}
        try:
            images = parse_node_images(
                name,
                json.loads(run_incus("image", "list", f"{name}:", "--format=json", timeout=30)),
            )
            image_error = ""
        except Exception as exc:
            images = []
            image_error = str(exc)
        return {
            "name": name,
            "address": address,
            "status": "online",
            "cpu": cpu_total,
            "memory": memory_total,
            "memory_used": memory_used,
            "host_memory_used": host_memory_used,
            "memory_reserve": memory_reserve,
            "disk": disk_total,
            "disk_used": disk_used,
            "disk_reserve": disk_reserve,
            "allocated_cpu": allocations["cpu"],
            "cpu_budget_percent": cpu_budget_percent,
            "cpu_committed_percent": cpu_committed_percent,
            "cpu_available_percent": cpu_available_percent,
            "allocated_memory": allocations["memory"],
            "allocated_disk": allocations["disk"],
            "available_cpu": cpu_available_percent / 100,
            "available_memory": max(
                0, memory_total - memory_committed - memory_reserve
            ),
            "available_disk": max(0, disk_total - disk_committed - disk_reserve),
            "available_ssh_ports": sum(
                port not in occupied_ports
                for port in range(SSH_PORT_MIN, SSH_PORT_MAX + 1)
            ),
            "forwarded_ports": allocations["forwarded_ports"],
            "unlimited_instances": allocations["unlimited_instances"],
            "load": float(load.get("Average1Min", 0)),
            "architecture": (resources.get("cpu") or {}).get("architecture", ""),
            "instance_count": len(instances),
            "instances": instances,
            "images": images,
            "image_error": image_error,
            "preflight": read_node_health(name),
            "error": "",
        }
    except Exception as exc:
        return {
            "name": name,
            "address": address,
            "status": "offline",
            "cpu": 0,
            "memory": 0,
            "memory_used": 0,
            "host_memory_used": 0,
            "memory_reserve": 0,
            "disk": 0,
            "disk_used": 0,
            "disk_reserve": 0,
            "allocated_cpu": 0,
            "cpu_budget_percent": 0,
            "cpu_committed_percent": 0,
            "cpu_available_percent": 0,
            "allocated_memory": 0,
            "allocated_disk": 0,
            "available_cpu": 0,
            "available_memory": 0,
            "available_disk": 0,
            "available_ssh_ports": 0,
            "forwarded_ports": 0,
            "unlimited_instances": 0,
            "load": 0,
            "architecture": "",
            "instance_count": 0,
            "instances": [],
            "images": [],
            "image_error": "",
            "preflight": read_node_health(name),
            "error": str(exc),
        }


def inspect_node_live(name, remote):
    try:
        resources = json.loads(run_incus("query", f"{name}:/1.0/resources", timeout=15))
        raw_instances = json.loads(run_incus("list", f"{name}:", "--format=json", timeout=20))
        instances = parse_instances(name, raw_instances)
        memory = resources.get("memory") or {}
        load = resources.get("load") or {}
        storage_disks = (resources.get("storage") or {}).get("disks") or []
        disk_total = sum(
            int(disk.get("size", 0))
            for disk in storage_disks
            if not disk.get("removable", False) and not disk.get("read_only", False)
        )
        disk_used = 0
        try:
            pool_resources = json.loads(
                run_incus("query", f"{name}:/1.0/storage-pools/default/resources", timeout=15)
            )
            space = pool_resources.get("space") or {}
            disk_total = int(space.get("total", 0)) or disk_total
            disk_used = int(space.get("used", 0))
        except Exception:
            pass
        running_instances = sum(instance.get("status") == "Running" for instance in instances)
        return {
            "name": name,
            "status": "online",
            "cpu": int((resources.get("cpu") or {}).get("total", 0)),
            "load": float(load.get("Average1Min", 0)),
            "memory": int(memory.get("total", 0)),
            "memory_used": int(memory.get("used", 0)),
            "disk": disk_total,
            "disk_used": disk_used,
            "instance_count": len(instances),
            "running_instance_count": running_instances,
            "stopped_instance_count": len(instances) - running_instances,
            "instance_cpu_usage_ns": sum(
                int(instance.get("cpu_usage_ns", 0) or 0) for instance in instances
            ),
            "instance_network_rx_bytes": sum(
                int(instance.get("network_rx_bytes", 0) or 0) for instance in instances
            ),
            "instance_network_tx_bytes": sum(
                int(instance.get("network_tx_bytes", 0) or 0) for instance in instances
            ),
            "error": "",
        }
    except Exception as exc:
        return {
            "name": name,
            "status": "offline",
            "cpu": 0,
            "load": 0,
            "memory": 0,
            "memory_used": 0,
            "disk": 0,
            "disk_used": 0,
            "instance_count": 0,
            "running_instance_count": 0,
            "stopped_instance_count": 0,
            "instance_cpu_usage_ns": 0,
            "instance_network_rx_bytes": 0,
            "instance_network_tx_bytes": 0,
            "error": str(exc),
        }


def node_live_rates(sample, previous, elapsed_seconds):
    result = dict(sample)
    result.update({
        "sample_ready": False,
        "instance_cpu_percent": 0.0,
        "network_rx_bytes_per_second": 0.0,
        "network_tx_bytes_per_second": 0.0,
    })
    if (
        sample.get("status") != "online"
        or not previous
        or previous.get("status") != "online"
        or elapsed_seconds < 0.5
    ):
        return result
    counters = (
        "instance_cpu_usage_ns",
        "instance_network_rx_bytes",
        "instance_network_tx_bytes",
    )
    if any(int(sample.get(key, 0)) < int(previous.get(key, 0)) for key in counters):
        return result
    cpu_cores = max(1, int(sample.get("cpu", 0) or 0))
    cpu_delta = int(sample["instance_cpu_usage_ns"]) - int(previous["instance_cpu_usage_ns"])
    result.update({
        "sample_ready": True,
        "instance_cpu_percent": min(
            100.0, max(0.0, cpu_delta / 1_000_000_000 / elapsed_seconds / cpu_cores * 100)
        ),
        "network_rx_bytes_per_second": max(
            0.0,
            (int(sample["instance_network_rx_bytes"]) - int(previous["instance_network_rx_bytes"]))
            / elapsed_seconds,
        ),
        "network_tx_bytes_per_second": max(
            0.0,
            (int(sample["instance_network_tx_bytes"]) - int(previous["instance_network_tx_bytes"]))
            / elapsed_seconds,
        ),
    })
    return result


def node_live_payload():
    with NODE_LIVE_LOCK:
        remotes = registered_remotes()
        started = time.monotonic()
        if remotes:
            with ThreadPoolExecutor(max_workers=min(8, len(remotes))) as executor:
                samples = list(executor.map(lambda item: inspect_node_live(*item), remotes.items()))
        else:
            samples = []
        nodes = []
        active_names = set()
        for sample in samples:
            name = sample["name"]
            active_names.add(name)
            previous = NODE_LIVE_SAMPLES.get(name)
            elapsed = started - previous["sampled_at"] if previous else 0
            nodes.append(node_live_rates(sample, previous, elapsed))
            NODE_LIVE_SAMPLES[name] = {**sample, "sampled_at": started}
        for name in set(NODE_LIVE_SAMPLES) - active_names:
            NODE_LIVE_SAMPLES.pop(name, None)
        nodes.sort(key=lambda item: item["name"])
        return {
            "nodes": nodes,
            "interval_seconds": NODE_LIVE_INTERVAL_SECONDS,
            "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


def overview():
    remotes = registered_remotes()
    if not remotes:
        return [], []
    with ThreadPoolExecutor(max_workers=min(8, len(remotes))) as executor:
        nodes = list(executor.map(lambda item: inspect_node(*item), remotes.items()))
    nodes.sort(key=lambda item: item["name"])
    instances = [instance for node in nodes for instance in node.pop("instances")]
    attach_traffic_usage(instances)
    return nodes, instances


def default_notification_config():
    return {
        "enabled": True,
        "interval_seconds": 60,
        "thresholds": {
            "memory_percent": 90,
            "disk_percent": 90,
            "load_percent": 150,
            "instance_memory_percent": 90,
            "instance_cpu_percent": 90,
        },
        "rules": {
            key: definition["default_mode"] for key, definition in ALERT_RULES.items()
        },
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": "",
            "send_recovery": True,
        },
    }


def default_notification_data():
    return {
        "version": 1,
        "active": {},
        "events": [],
        "snapshot": {"initialized": False, "nodes": {}, "instances": {}},
        "last_check": "",
        "last_error": "",
        "telegram_last_error": "",
    }


def _read_private_json(path, default):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"无法读取 {os.path.basename(path)}: {exc}") from exc
    return data if isinstance(data, dict) else default


def _write_private_json(path, data):
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    temporary = f"{path}.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TaskCancelled(RuntimeError):
    pass


class TaskContext:
    def __init__(self, task_id):
        self.task_id = task_id

    def update(self, progress=None, stage=None, message=None, check_cancelled=True):
        update_task(self.task_id, progress=progress, stage=stage, message=message)
        if check_cancelled:
            self.check_cancelled()

    def check_cancelled(self):
        task = get_task(self.task_id, private=True)
        if task and task.get("cancel_requested"):
            raise TaskCancelled("任务已由管理员取消")


def default_tasks_data():
    return {"version": 1, "tasks": []}


def _read_tasks_unlocked():
    data = _read_private_json(TASKS_FILE, default_tasks_data())
    tasks = data.get("tasks", [])
    return tasks if isinstance(tasks, list) else []


def _write_tasks_unlocked(tasks):
    _write_private_json(TASKS_FILE, {"version": 1, "tasks": tasks[-MAX_TASKS:]})


def public_task(task):
    return {key: value for key, value in task.items() if key not in {"payload"}}


def list_tasks(session=None, limit=100):
    with TASK_LOCK:
        tasks = list(reversed(_read_tasks_unlocked()))
    if session and session.get("role") != "admin":
        tasks = [task for task in tasks if task.get("owner") == session.get("username")]
    return [public_task(task) for task in tasks[:max(1, min(int(limit), 200))]]


def get_task(task_id, private=False):
    with TASK_LOCK:
        task = next((item for item in _read_tasks_unlocked() if item.get("id") == task_id), None)
    if not task:
        return None
    return dict(task) if private else public_task(task)


def update_task(task_id, **changes):
    with TASK_LOCK:
        tasks = _read_tasks_unlocked()
        task = next((item for item in tasks if item.get("id") == task_id), None)
        if not task:
            return None
        for key, value in changes.items():
            if value is not None:
                task[key] = value
        task["updated_at"] = utc_now()
        _write_tasks_unlocked(tasks)
        return dict(task)


def _task_executor():
    global TASK_EXECUTOR
    with TASK_LOCK:
        if TASK_EXECUTOR is None:
            TASK_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="panel-task")
        return TASK_EXECUTOR


def _execute_task(task_id):
    task = get_task(task_id, private=True)
    if not task:
        return
    runner = TASK_RUNNERS.get(task.get("type"))
    if not runner:
        update_task(
            task_id, status="failed", stage="无法执行", progress=100,
            message="当前版本不支持恢复此任务", finished_at=utc_now(),
        )
        return
    update_task(
        task_id, status="running", stage="正在启动", progress=max(1, int(task.get("progress", 0))),
        started_at=utc_now(), message="任务已开始执行",
    )
    context = TaskContext(task_id)
    try:
        result = runner(context, dict(task.get("payload") or {})) or {}
        update_task(
            task_id, status="complete", stage="已完成", progress=100,
            message=str(result.get("message", "任务执行完成"))[:500],
            result={key: value for key, value in result.items() if key != "message"},
            finished_at=utc_now(),
        )
        record_operation(
            f"task_{task.get('type')}", task.get("target", task_id), task.get("node", ""),
            message=f"任务 {task_id} 已完成",
        )
    except TaskCancelled as exc:
        update_task(
            task_id, status="cancelled", stage="已取消", progress=100,
            message=str(exc), finished_at=utc_now(),
        )
    except Exception as exc:
        detail = str(exc).replace("\n", " ")[-1000:]
        update_task(
            task_id, status="failed", stage="执行失败", progress=100,
            message=detail, finished_at=utc_now(),
        )
        record_operation(
            f"task_{task.get('type')}", task.get("target", task_id), task.get("node", ""),
            "failed", detail,
        )
    finally:
        with TASK_LOCK:
            TASK_FUTURES.pop(task_id, None)


def enqueue_task(task_type, label, node="", target="", payload=None, owner="admin"):
    if task_type not in TASK_RUNNERS:
        raise ValueError("不支持的后台任务类型")
    task_id = secrets.token_hex(8)
    now = utc_now()
    task = {
        "id": task_id,
        "type": task_type,
        "label": str(label)[:120],
        "node": str(node)[:63],
        "target": str(target)[:128],
        "owner": str(owner)[:32],
        "status": "queued",
        "progress": 0,
        "stage": "等待执行",
        "message": "任务已进入后台队列",
        "created_at": now,
        "updated_at": now,
        "started_at": "",
        "finished_at": "",
        "cancel_requested": False,
        "payload": dict(payload or {}),
        "result": {},
    }
    with TASK_LOCK:
        tasks = _read_tasks_unlocked()
        duplicate = next((
            item for item in reversed(tasks)
            if item.get("status") in {"queued", "running"}
            and item.get("type") == task_type
            and item.get("node") == task["node"]
            and item.get("target") == task["target"]
        ), None)
        if duplicate:
            return public_task(duplicate)
        tasks.append(task)
        _write_tasks_unlocked(tasks)
        TASK_FUTURES[task_id] = _task_executor().submit(_execute_task, task_id)
    return public_task(task)


def cancel_task(task_id):
    task = get_task(task_id, private=True)
    if not task:
        raise ValueError("任务不存在")
    if task.get("status") not in {"queued", "running"}:
        raise ValueError("该任务当前不能取消")
    future = TASK_FUTURES.get(task_id)
    if task.get("status") == "queued" and future and future.cancel():
        return public_task(update_task(
            task_id, status="cancelled", stage="已取消", progress=100,
            message="任务在开始前已取消", cancel_requested=True, finished_at=utc_now(),
        ))
    return public_task(update_task(
        task_id, cancel_requested=True, stage="正在取消",
        message="当前步骤结束后将停止任务",
    ))


def retry_task(task_id, owner="admin"):
    task = get_task(task_id, private=True)
    if not task:
        raise ValueError("任务不存在")
    if task.get("status") not in {"failed", "cancelled", "interrupted"}:
        raise ValueError("只有失败、取消或中断的任务可以重试")
    return enqueue_task(
        task["type"], task.get("label", "重试任务"), task.get("node", ""),
        task.get("target", ""), task.get("payload") or {}, owner,
    )


def recover_interrupted_tasks():
    with TASK_LOCK:
        tasks = _read_tasks_unlocked()
        changed = False
        for task in tasks:
            if task.get("status") in {"queued", "running"}:
                task.update({
                    "status": "interrupted",
                    "stage": "服务曾重启",
                    "progress": 100,
                    "message": "面板服务重启导致任务中断，可以安全重试",
                    "finished_at": utc_now(),
                    "updated_at": utc_now(),
                })
                changed = True
        if changed:
            _write_tasks_unlocked(tasks)


def default_node_health_data():
    return {"version": 1, "nodes": {}}


def read_node_health(node=""):
    with NODE_HEALTH_LOCK:
        data = _read_private_json(NODE_HEALTH_FILE, default_node_health_data())
    nodes = data.get("nodes", {}) if isinstance(data.get("nodes"), dict) else {}
    return dict(nodes.get(node, {})) if node else nodes


def save_node_health(report):
    with NODE_HEALTH_LOCK:
        data = _read_private_json(NODE_HEALTH_FILE, default_node_health_data())
        nodes = data.setdefault("nodes", {})
        nodes[report["node"]] = report
        _write_private_json(NODE_HEALTH_FILE, data)
    return report


def node_preflight(node):
    node = require_node(node)
    checked_at = utc_now()
    checks = []

    def add(code, title, status, detail, remediation=""):
        checks.append({
            "code": code, "title": title, "status": status,
            "detail": detail, "remediation": remediation,
        })

    try:
        server = json.loads(run_incus("query", f"{node}:/1.0", timeout=20))
        resources = json.loads(run_incus("query", f"{node}:/1.0/resources", timeout=20))
        pool = json.loads(run_incus("query", f"{node}:/1.0/storage-pools/default", timeout=20))
        pool_resources = json.loads(
            run_incus("query", f"{node}:/1.0/storage-pools/default/resources", timeout=20)
        )
        network = json.loads(run_incus("query", f"{node}:/1.0/networks/incusbr0", timeout=20))
    except Exception as exc:
        report = {
            "node": node, "status": "failed", "score": 0, "checked_at": checked_at,
            "summary": "宿主机基础接口检查失败",
            "checks": [{
                "code": "connectivity", "title": "Incus API 与基础资源",
                "status": "failed", "detail": str(exc)[-500:],
                "remediation": "检查 Incus 服务、8443 端口、TLS 信任和宿主机网络",
            }],
            "capabilities": {"containers": False, "virtual_machines": False},
        }
        return save_node_health(report)

    environment = server.get("environment") or {}
    config = server.get("config") or {}
    cpu_total = int((resources.get("cpu") or {}).get("total", 0) or 0)
    memory_total = int((resources.get("memory") or {}).get("total", 0) or 0)
    space = pool_resources.get("space") or {}
    disk_total = int(space.get("total", 0) or 0)
    disk_used = int(space.get("used", 0) or 0)
    disk_free = max(0, disk_total - disk_used)
    version = str(environment.get("server_version", "未知"))
    add("api", "Incus API", "passed", f"Incus {version} 响应正常")
    add(
        "cpu", "CPU 资源", "passed" if cpu_total >= 1 else "failed",
        f"检测到 {cpu_total} 个逻辑核心",
        "宿主机至少需要 1 个可用 CPU 核心" if cpu_total < 1 else "",
    )
    memory_status = "passed" if memory_total >= GIB_BYTES else "warning"
    add(
        "memory", "内存容量", memory_status, f"物理内存 {format_bytes(memory_total)}",
        "低于 1 GiB 时仅建议运行少量 Alpine 容器" if memory_status == "warning" else "",
    )
    storage_driver = str(pool.get("driver", "未知"))
    storage_status = "passed" if disk_free >= 2 * GIB_BYTES else "failed"
    add(
        "storage", "default 存储池", storage_status,
        f"{storage_driver} · 可用 {format_bytes(disk_free)} / {format_bytes(disk_total)}",
        "释放磁盘空间，确保至少保留 2 GiB" if storage_status == "failed" else "",
    )
    network_status = "passed" if network.get("managed", True) else "warning"
    add(
        "network", "incusbr0 实例网络", network_status,
        "托管 NAT 网桥可用" if network_status == "passed" else "网桥存在但不由 Incus 管理",
        "建议使用 bootstrap-node.sh 重新创建托管 NAT 网桥" if network_status == "warning" else "",
    )
    kvm_value = str(config.get("user.incus-cn-panel.kvm", "unknown")).lower()
    vm_ready = kvm_value == "true"
    add(
        "kvm", "KVM 虚拟化", "passed" if vm_ready else "warning",
        "宿主机已确认提供 /dev/kvm" if vm_ready else "尚未确认 /dev/kvm，可正常创建 LXC",
        "升级节点脚本或在确认嵌套虚拟化后设置 Incus 服务器标记" if not vm_ready else "",
    )
    failed = sum(item["status"] == "failed" for item in checks)
    warnings = sum(item["status"] == "warning" for item in checks)
    status = "failed" if failed else "warning" if warnings else "healthy"
    score = max(0, 100 - failed * 35 - warnings * 10)
    report = {
        "node": node, "status": status, "score": score, "checked_at": checked_at,
        "summary": "存在阻断项" if failed else "可接入，存在建议项" if warnings else "全部检查通过",
        "checks": checks,
        "capabilities": {"containers": not failed, "virtual_machines": not failed and vm_ready},
        "facts": {
            "incus_version": version,
            "kernel": str(environment.get("kernel_version", "")),
            "architecture": str((resources.get("cpu") or {}).get("architecture", "")),
            "cpu": cpu_total,
            "memory": memory_total,
            "disk_free": disk_free,
            "storage_driver": storage_driver,
        },
    }
    return save_node_health(report)


def _resource_tier(value, minimum, tiers):
    candidates = [tier for tier in tiers if minimum <= tier <= value]
    return max(candidates) if candidates else 0


def scheduler_plan(node_info, count, kind, image_id, strategy="balanced"):
    try:
        count = int(count)
    except (TypeError, ValueError) as exc:
        raise ValueError("计划实例数量无效") from exc
    if not 1 <= count <= 10000:
        raise ValueError("计划实例数量必须在 1 到 10000 之间")
    if kind not in {"container", "virtual-machine"}:
        raise ValueError("实例类型无效")
    if strategy not in {"stable", "balanced", "density"}:
        raise ValueError("资源策略无效")
    image = PUBLIC_IMAGE_MAP.get(str(image_id))
    family = image["family"] if image else image_family(str(image_id))
    profile = resource_profile(family, kind)
    minimum_memory = parse_size_bytes(profile["minimum_memory"])
    minimum_disk = parse_size_bytes(profile["minimum_disk"])
    recommended_memory = parse_size_bytes(profile["recommended_memory"])
    recommended_disk = parse_size_bytes(profile["recommended_disk"])
    memory_share = int(node_info.get("available_memory", 0)) // count
    disk_share = int(node_info.get("available_disk", 0)) // count
    cpu_share = int(node_info.get("cpu_available_percent", 0)) // count
    memory_tiers = [128, 256, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536]
    memory_tiers = [value * MIB_BYTES for value in memory_tiers]
    disk_tiers = [1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 32, 40, 48, 64, 80, 100, 128, 160, 200, 256, 320, 512, 1024]
    disk_tiers = [value * GIB_BYTES for value in disk_tiers]
    factors = {"density": 0.35, "balanced": 0.60, "stable": 0.80}
    factor = factors[strategy]
    memory_target = minimum_memory if strategy == "density" else max(recommended_memory, int(memory_share * factor))
    disk_target = minimum_disk if strategy == "density" else max(recommended_disk, int(disk_share * factor))
    memory = _resource_tier(min(memory_share, memory_target), minimum_memory, memory_tiers)
    disk = _resource_tier(min(disk_share, disk_target), minimum_disk, disk_tiers)
    constrained = memory < minimum_memory or disk < minimum_disk or cpu_share < (100 if kind == "virtual-machine" else 5)
    cpu_factor = {"density": 0.50, "balanced": 0.70, "stable": 0.85}[strategy]
    cpu_commitment = max(1, int(cpu_share * cpu_factor / 5) * 5)
    host_cpu = max(1, int(node_info.get("cpu", 1) or 1))
    if kind == "virtual-machine":
        cpu = max(1, min(host_cpu, 8, cpu_commitment // 100))
        cpu_allowance = 0
    else:
        cpu = max(1, min(host_cpu, 4, (cpu_commitment + 99) // 100))
        cpu_allowance = min(cpu * 100, cpu_commitment)
    proposed = {
        "type": kind,
        "cpu": str(cpu),
        "cpu_allowance": str(cpu_allowance),
        "memory": format_binary_size(memory or minimum_memory),
        "disk": format_binary_size(disk or minimum_disk),
        "port_count": "0",
    }
    maximum, limits = maximum_instances(node_info, proposed)
    return {
        "node": node_info["name"], "count": count, "kind": kind,
        "image": str(image_id), "strategy": strategy,
        "cpu": cpu, "cpu_allowance": cpu_allowance,
        "memory": proposed["memory"], "memory_bytes": memory or minimum_memory,
        "disk": proposed["disk"], "disk_bytes": disk or minimum_disk,
        "swap_bytes": recommended_swap_bytes(
            proposed["memory"], proposed["disk"], kind
        ),
        "maximum": maximum, "limits": limits, "constrained": constrained or maximum < count,
        "profile": profile,
        "remaining": {
            "cpu_percent": max(0, int(node_info.get("cpu_available_percent", 0)) - (cpu_allowance if kind == "container" else cpu * 100) * count),
            "memory": max(0, int(node_info.get("available_memory", 0)) - (memory or minimum_memory) * count),
            "disk": max(0, int(node_info.get("available_disk", 0)) - (disk or minimum_disk) * count),
        },
    }


def default_reconcile_status():
    return {
        "status": "idle", "checked_at": "", "summary": "尚未执行状态核对",
        "issue_count": 0, "repaired_count": 0, "issues": [],
    }


def read_reconcile_status():
    with RECONCILE_LOCK:
        return _read_private_json(RECONCILE_FILE, default_reconcile_status())


def reconcile_state(nodes=None, instances=None, repair=False):
    if nodes is None or instances is None:
        nodes, instances = overview()
    actual = {f"{item['node']}/{item['name']}" for item in instances}
    issues = []
    with CREDENTIALS_LOCK:
        credential_keys = set(_read_credentials_unlocked())
    traffic_keys = set(read_traffic_data().get("instances", {}))
    with USERS_LOCK:
        users = _read_users_unlocked()
        assignment_keys = {
            key for record in users.values() for key in assignment_map(record)
        }
    stale_credentials = sorted(credential_keys - actual)
    stale_traffic = sorted(traffic_keys - actual)
    stale_assignments = sorted(assignment_keys - actual)
    for key in stale_credentials:
        issues.append({"kind": "credential_orphan", "target": key, "message": "实例已不存在，但 SSH 凭据仍在控制端"})
    for key in stale_traffic:
        issues.append({"kind": "traffic_orphan", "target": key, "message": "实例已不存在，但流量计数仍在控制端"})
    for key in stale_assignments:
        issues.append({"kind": "assignment_orphan", "target": key, "message": "实例已不存在，但用户授权仍然保留"})
    managed = {
        f"{item['node']}/{item['name']}" for item in instances
        if item.get("ssh_port")
    }
    for key in sorted(managed - credential_keys):
        issues.append({"kind": "credential_missing", "target": key, "message": "实例存在 SSH 端口配置，但控制端没有连接凭据"})
    offline_nodes = [node["name"] for node in nodes if node.get("status") != "online"]
    for node in offline_nodes:
        issues.append({"kind": "node_unverified", "target": node, "message": "宿主机离线，本轮无法验证其实例状态"})
    repaired = 0
    if repair:
        for key in stale_credentials:
            node, name = key.split("/", 1)
            delete_credentials(node, name)
            repaired += 1
        for key in stale_traffic:
            node, name = key.split("/", 1)
            remove_traffic_usage(node, name)
            repaired += 1
        for key in stale_assignments:
            node, name = key.split("/", 1)
            remove_instance_assignments(node, name)
            repaired += 1
    report = {
        "status": "warning" if issues else "healthy",
        "checked_at": utc_now(),
        "summary": f"发现 {len(issues)} 项状态差异" if issues else "面板状态与 Incus 一致",
        "issue_count": len(issues), "repaired_count": repaired,
        "issues": issues[:200],
    }
    with RECONCILE_LOCK:
        _write_private_json(RECONCILE_FILE, report)
    return report


def version_tuple(value):
    value = str(value).strip()
    if not VERSION_RE.fullmatch(value):
        raise ValueError("版本号格式无效")
    return tuple(int(part) for part in value.split("."))


def default_update_status():
    return {
        "status": "idle",
        "message": "尚未执行面板更新",
        "current_version": APP_VERSION,
        "target_version": "",
        "updated_at": "",
    }


def read_update_status():
    with UPDATE_LOCK:
        saved = _read_private_json(UPDATE_STATUS_FILE, default_update_status())
    status = default_update_status()
    if saved.get("status") in {"idle", "queued", "running", "complete", "failed"}:
        status["status"] = saved["status"]
    for key in ("message", "current_version", "target_version", "updated_at", "unit"):
        if key in saved:
            status[key] = str(saved.get(key, ""))[:256]
    return status


def fetch_latest_version():
    request = Request(
        UPDATE_VERSION_URL,
        headers={"Accept": "text/plain", "User-Agent": f"IncusCNPanel/{APP_VERSION}"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            version = response.read(64).decode("utf-8").strip()
    except (HTTPError, URLError, OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"无法连接 GitHub 检查版本: {exc}") from exc
    if not VERSION_RE.fullmatch(version):
        raise RuntimeError("GitHub 返回的版本号格式无效")
    return version


def panel_version_payload(refresh=False):
    update = read_update_status()
    target = update.get("target_version", "")
    latest = target if VERSION_RE.fullmatch(target) else APP_VERSION
    checked_at = ""
    if refresh:
        latest = fetch_latest_version()
        checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "current_version": APP_VERSION,
        "latest_version": latest,
        "update_available": version_tuple(latest) > version_tuple(APP_VERSION),
        "checked_at": checked_at,
        "repository_url": UPDATE_REPOSITORY_URL,
        "update": update,
    }


def _recent_update_in_progress(status):
    if status.get("status") not in {"queued", "running"}:
        return False
    try:
        updated_at = datetime.fromisoformat(status.get("updated_at", "").replace("Z", "+00:00"))
    except ValueError:
        return True
    return datetime.now(timezone.utc) - updated_at.astimezone(timezone.utc) < timedelta(minutes=30)


def start_panel_update(target_version):
    if version_tuple(target_version) <= version_tuple(APP_VERSION):
        raise ValueError("当前已经是最新版本")
    if not os.path.isfile(UPDATER_PATH) or not os.access(UPDATER_PATH, os.X_OK):
        raise RuntimeError("升级程序未安装，请先手动运行一次 bootstrap.sh")
    with UPDATE_LOCK:
        current = read_update_status()
        if _recent_update_in_progress(current):
            raise ValueError("已有版本更新任务正在执行")
        unit = f"incus-cn-panel-update-{int(time.time())}"
        queued = {
            "status": "queued",
            "message": "升级任务已提交，正在等待 systemd 执行",
            "current_version": APP_VERSION,
            "target_version": target_version,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "unit": unit,
        }
        _write_private_json(UPDATE_STATUS_FILE, queued)
        result = subprocess.run(
            [
                "systemd-run", "--quiet", "--collect", f"--unit={unit}",
                UPDATER_PATH,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "systemd 无法启动升级任务").strip()
            queued.update({
                "status": "failed",
                "message": message[:256],
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
            _write_private_json(UPDATE_STATUS_FILE, queued)
            raise RuntimeError(f"无法启动升级任务: {message}")
        return queued


def traffic_period(now=None):
    now = now or datetime.now(PANEL_TIMEZONE)
    return now.astimezone(PANEL_TIMEZONE).strftime("%Y-%m")


def default_traffic_data():
    return {"version": 1, "instances": {}}


def read_traffic_data():
    with TRAFFIC_LOCK:
        data = _read_private_json(TRAFFIC_FILE, default_traffic_data())
    if not isinstance(data.get("instances"), dict):
        data["instances"] = {}
    return data


def _write_traffic_data(data):
    data["version"] = 1
    _write_private_json(TRAFFIC_FILE, data)


def _traffic_key(node, name):
    return f"{node}/{name}"


def _counter_delta(current, previous):
    current = max(0, int(current or 0))
    previous = max(0, int(previous or 0))
    return current - previous if current >= previous else current


def validate_traffic_quota(limit_value, action="stop"):
    try:
        limit = int(str(limit_value or "0"))
    except (TypeError, ValueError) as exc:
        raise ValueError("月流量配额无效") from exc
    if limit and not 1024**3 <= limit <= MAX_TRAFFIC_LIMIT_BYTES:
        raise ValueError("月流量配额必须在 1 GiB 到 1 PiB 之间")
    action = str(action or "stop")
    if action not in {"stop", "notify"}:
        raise ValueError("流量超额处理方式无效")
    return limit, action


def attach_traffic_usage(instances):
    data = read_traffic_data()
    period = traffic_period()
    records = data["instances"]
    for instance in instances:
        limit = int(instance.get("traffic_limit_bytes", 0) or 0)
        record = records.get(_traffic_key(instance["node"], instance["name"]), {})
        used = int(record.get("used_bytes", 0) or 0) if record.get("period") == period else 0
        instance.update({
            "traffic_period": period,
            "traffic_used_bytes": used,
            "traffic_remaining_bytes": max(0, limit - used) if limit else 0,
            "traffic_exceeded": bool(limit and used >= limit),
            "traffic_enforced_at": record.get("enforced_at", "") if used >= limit else "",
            "traffic_error": record.get("last_error", "") if used >= limit else "",
        })
    return instances


def initialize_traffic_usage(node, name, limit, action, rx_bytes=0, tx_bytes=0, reset=True):
    key = _traffic_key(node, name)
    with TRAFFIC_LOCK:
        data = _read_private_json(TRAFFIC_FILE, default_traffic_data())
        records = data.setdefault("instances", {})
        existing = records.get(key, {})
        used = 0 if reset or existing.get("period") != traffic_period() else int(
            existing.get("used_bytes", 0) or 0
        )
        records[key] = {
            "period": traffic_period(),
            "used_bytes": used,
            "last_rx_bytes": max(0, int(rx_bytes or 0)),
            "last_tx_bytes": max(0, int(tx_bytes or 0)),
            "initialized": True,
            "limit_bytes": int(limit or 0),
            "action": action,
            "exceeded": bool(limit and used >= limit),
            "enforced_at": "",
            "last_error": "",
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        _write_traffic_data(data)


def remove_traffic_usage(node, name=None):
    with TRAFFIC_LOCK:
        data = _read_private_json(TRAFFIC_FILE, default_traffic_data())
        records = data.setdefault("instances", {})
        if name is None:
            prefix = f"{node}/"
            for key in [key for key in records if key.startswith(prefix)]:
                records.pop(key, None)
        else:
            records.pop(_traffic_key(node, name), None)
        _write_traffic_data(data)


def traffic_quota_status(node, name, config=None):
    config = config or {}
    limit = int(config.get("user.incus-cn-panel.traffic-limit-bytes", 0) or 0)
    action = config.get("user.incus-cn-panel.traffic-action", "stop")
    record = read_traffic_data()["instances"].get(_traffic_key(node, name), {})
    used = int(record.get("used_bytes", 0) or 0) if record.get("period") == traffic_period() else 0
    return {
        "period": traffic_period(),
        "limit_bytes": limit,
        "used_bytes": used,
        "remaining_bytes": max(0, limit - used) if limit else 0,
        "exceeded": bool(limit and used >= limit),
        "action": action,
        "enforced_at": record.get("enforced_at", ""),
        "last_error": record.get("last_error", ""),
    }


def update_instance_traffic_quota(node, name, limit_value, action="stop", reset_usage=False):
    node = require_node(node)
    if not NAME_RE.fullmatch(name):
        raise ValueError("实例名称无效")
    if not isinstance(reset_usage, bool):
        raise ValueError("流量归零参数无效")
    limit, action = validate_traffic_quota(limit_value, action)
    ref = f"{node}:{name}"
    with INSTANCE_MUTATION_LOCK:
        instance = json.loads(
            run_incus("query", f"{node}:/1.0/instances/{name}?recursion=1", timeout=20)
        )
        config = instance.get("config") or {}
        if limit:
            run_incus("config", "set", ref, "user.incus-cn-panel.traffic-limit-bytes", str(limit))
            run_incus("config", "set", ref, "user.incus-cn-panel.traffic-action", action)
        else:
            if config.get("user.incus-cn-panel.traffic-limit-bytes"):
                run_incus("config", "unset", ref, "user.incus-cn-panel.traffic-limit-bytes")
            if config.get("user.incus-cn-panel.traffic-action"):
                run_incus("config", "unset", ref, "user.incus-cn-panel.traffic-action")
            remove_traffic_usage(node, name)
            return traffic_quota_status(node, name, {})
        state = {}
        if instance.get("status") == "Running":
            state = json.loads(
                run_incus("query", f"{node}:/1.0/instances/{name}/state", timeout=20)
            )
        parsed = parse_instances(node, [{**instance, "state": state}])[0]
        initialize_traffic_usage(
            node, name, limit, action,
            parsed["network_rx_bytes"], parsed["network_tx_bytes"],
            reset=reset_usage or not config.get("user.incus-cn-panel.traffic-limit-bytes"),
        )
    updated_config = {
        "user.incus-cn-panel.traffic-limit-bytes": str(limit),
        "user.incus-cn-panel.traffic-action": action,
    }
    return traffic_quota_status(node, name, updated_config)


def update_traffic_usage(instances):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    period = traffic_period()
    enforcement = []
    with TRAFFIC_LOCK:
        data = _read_private_json(TRAFFIC_FILE, default_traffic_data())
        records = data.setdefault("instances", {})
        for instance in instances:
            limit = int(instance.get("traffic_limit_bytes", 0) or 0)
            if not limit:
                continue
            action = instance.get("traffic_action", "stop")
            key = _traffic_key(instance["node"], instance["name"])
            record = records.get(key, {})
            rx_bytes = int(instance.get("network_rx_bytes", 0) or 0)
            tx_bytes = int(instance.get("network_tx_bytes", 0) or 0)
            if record.get("period") != period:
                used = 0
                delta = 0
                enforced_at = ""
            elif record.get("initialized"):
                delta = _counter_delta(rx_bytes, record.get("last_rx_bytes", 0))
                delta += _counter_delta(tx_bytes, record.get("last_tx_bytes", 0))
                used = int(record.get("used_bytes", 0) or 0) + delta
                enforced_at = record.get("enforced_at", "")
            else:
                used = int(record.get("used_bytes", 0) or 0)
                delta = 0
                enforced_at = ""
            exceeded = used >= limit
            records[key] = {
                **record,
                "period": period,
                "used_bytes": used,
                "last_rx_bytes": rx_bytes,
                "last_tx_bytes": tx_bytes,
                "initialized": True,
                "limit_bytes": limit,
                "action": action,
                "exceeded": exceeded,
                "enforced_at": enforced_at if exceeded else "",
                "last_error": record.get("last_error", "") if exceeded else "",
                "updated_at": now,
            }
            if exceeded and action == "stop" and instance.get("status") == "Running":
                enforcement.append((key, instance["node"], instance["name"], used, limit))
        _write_traffic_data(data)
    for key, node, name, used, limit in enforcement:
        error = ""
        try:
            run_incus("stop", f"{node}:{name}", "--force", timeout=180)
            record_operation(
                "instance_traffic_stop", name, node,
                message=f"本月双向流量 {format_bytes(used)} / {format_bytes(limit)}",
            )
        except Exception as exc:
            error = str(exc)[:300]
        with TRAFFIC_LOCK:
            data = _read_private_json(TRAFFIC_FILE, default_traffic_data())
            record = data.setdefault("instances", {}).get(key)
            if record:
                record["enforced_at"] = now if not error else ""
                record["last_error"] = error
                _write_traffic_data(data)
    attach_traffic_usage(instances)
    return instances


def read_notification_config():
    with NOTIFICATION_LOCK:
        saved = _read_private_json(NOTIFICATION_CONFIG_FILE, {})
    config = default_notification_config()
    if not saved:
        return config
    config["enabled"] = bool(saved.get("enabled", config["enabled"]))
    config["interval_seconds"] = int(saved.get("interval_seconds", config["interval_seconds"]))
    config["thresholds"].update(saved.get("thresholds", {}))
    config["rules"].update(saved.get("rules", {}))
    config["telegram"].update(saved.get("telegram", {}))
    return config


def public_notification_config(config=None):
    config = config or read_notification_config()
    telegram = config["telegram"]
    return {
        "enabled": config["enabled"],
        "interval_seconds": config["interval_seconds"],
        "thresholds": dict(config["thresholds"]),
        "rules": dict(config["rules"]),
        "rule_definitions": [
            {"key": key, **definition} for key, definition in ALERT_RULES.items()
        ],
        "telegram": {
            "enabled": telegram["enabled"],
            "chat_id": telegram["chat_id"],
            "send_recovery": telegram["send_recovery"],
            "token_configured": bool(telegram["bot_token"]),
        },
    }


def normalize_notification_config(payload, existing=None):
    if not isinstance(payload, dict):
        raise ValueError("通知配置格式无效")
    config = existing or read_notification_config()
    config = json.loads(json.dumps(config))
    if "enabled" in payload:
        if not isinstance(payload["enabled"], bool):
            raise ValueError("巡检状态无效")
        config["enabled"] = payload["enabled"]
    if "interval_seconds" in payload:
        interval = int(payload["interval_seconds"])
        if not 30 <= interval <= 3600:
            raise ValueError("巡检间隔必须在 30 到 3600 秒之间")
        config["interval_seconds"] = interval
    thresholds = payload.get("thresholds")
    if thresholds is not None:
        if not isinstance(thresholds, dict):
            raise ValueError("告警阈值格式无效")
        limits = {
            "memory_percent": (50, 99),
            "disk_percent": (50, 99),
            "load_percent": (50, 1000),
            "instance_memory_percent": (50, 99),
            "instance_cpu_percent": (50, 1000),
        }
        for key, (minimum, maximum) in limits.items():
            if key not in thresholds:
                continue
            value = int(thresholds[key])
            if not minimum <= value <= maximum:
                raise ValueError(f"{key} 阈值必须在 {minimum} 到 {maximum} 之间")
            config["thresholds"][key] = value
    rules = payload.get("rules")
    if rules is not None:
        if not isinstance(rules, dict):
            raise ValueError("异常规则格式无效")
        for key, mode in rules.items():
            if key not in ALERT_RULES or mode not in {"off", "panel", "panel_telegram"}:
                raise ValueError("异常规则或通知方式无效")
            config["rules"][key] = mode
    telegram = payload.get("telegram")
    if telegram is not None:
        if not isinstance(telegram, dict):
            raise ValueError("Telegram 配置格式无效")
        for key in ("enabled", "send_recovery"):
            if key in telegram:
                if not isinstance(telegram[key], bool):
                    raise ValueError("Telegram 开关无效")
                config["telegram"][key] = telegram[key]
        if telegram.get("clear_token"):
            config["telegram"]["bot_token"] = ""
        token = str(telegram.get("bot_token", "")).strip()
        if token:
            if not re.fullmatch(r"[0-9]{5,15}:[A-Za-z0-9_-]{20,80}", token):
                raise ValueError("Telegram Bot Token 格式无效")
            config["telegram"]["bot_token"] = token
        if "chat_id" in telegram:
            chat_id = str(telegram["chat_id"]).strip()
            if chat_id and not re.fullmatch(r"(?:-?[0-9]{5,20}|@[A-Za-z0-9_]{5,32})", chat_id):
                raise ValueError("Telegram Chat ID 格式无效")
            config["telegram"]["chat_id"] = chat_id
    if config["telegram"]["enabled"] and (
        not config["telegram"]["bot_token"] or not config["telegram"]["chat_id"]
    ):
        raise ValueError("启用 Telegram 前必须填写 Bot Token 和 Chat ID")
    return config


def update_notification_config(payload):
    config = normalize_notification_config(payload)
    with NOTIFICATION_LOCK:
        _write_private_json(NOTIFICATION_CONFIG_FILE, config)
    MONITOR_WAKE_EVENT.set()
    return public_notification_config(config)


def read_notification_data():
    with NOTIFICATION_LOCK:
        data = _read_private_json(NOTIFICATIONS_FILE, default_notification_data())
    defaults = default_notification_data()
    for key, value in defaults.items():
        data.setdefault(key, value)
    if not isinstance(data["active"], dict):
        data["active"] = {}
    if not isinstance(data["events"], list):
        data["events"] = []
    if not isinstance(data["snapshot"], dict):
        data["snapshot"] = defaults["snapshot"]
    return data


def notification_payload():
    config = read_notification_config()
    data = read_notification_data()
    active = sorted(
        data["active"].values(),
        key=lambda item: (item.get("severity") != "critical", item.get("first_seen", "")),
    )
    events = data["events"][:200]
    return {
        "config": public_notification_config(config),
        "active": active,
        "events": events,
        "active_count": len(active),
        "unread_count": sum(
            not event.get("read", False) for event in data["events"]
        ),
        "last_check": data.get("last_check", ""),
        "last_error": data.get("last_error", ""),
        "telegram_last_error": data.get("telegram_last_error", ""),
    }


def mark_notifications_read():
    with NOTIFICATION_LOCK:
        data = _read_private_json(NOTIFICATIONS_FILE, default_notification_data())
        for event in data.get("events", []):
            event["read"] = True
        _write_private_json(NOTIFICATIONS_FILE, data)
    return notification_payload()


def rule_enabled(config, key):
    return config["rules"].get(key, "off") != "off"


def _anomaly(key, kind, target, node, title, message):
    definition = ALERT_RULES[kind]
    return {
        "key": key,
        "type": kind,
        "severity": definition["severity"],
        "target": target,
        "node": node,
        "title": title,
        "message": str(message).replace("\n", " ")[:500],
    }


def detect_anomalies(nodes, instances, config, previous_snapshot=None):
    anomalies = {}
    thresholds = config["thresholds"]
    node_statuses = {node["name"]: node["status"] for node in nodes}
    for node in nodes:
        name = node["name"]
        if node["status"] != "online":
            if rule_enabled(config, "node_offline"):
                anomalies[f"node_offline:{name}"] = _anomaly(
                    f"node_offline:{name}", "node_offline", name, name,
                    f"宿主机 {name} 离线", node.get("error") or "无法连接 Incus API",
                )
            continue
        memory_percent = node["memory_used"] / node["memory"] * 100 if node["memory"] else 0
        disk_percent = node["disk_used"] / node["disk"] * 100 if node["disk"] else 0
        load_percent = node["load"] / node["cpu"] * 100 if node["cpu"] else 0
        if rule_enabled(config, "node_memory_high") and memory_percent >= thresholds["memory_percent"]:
            key = f"node_memory_high:{name}"
            anomalies[key] = _anomaly(
                key, "node_memory_high", name, name, f"宿主机 {name} 内存使用率过高",
                f"当前 {memory_percent:.1f}%，阈值 {thresholds['memory_percent']}%",
            )
        if rule_enabled(config, "node_disk_high") and disk_percent >= thresholds["disk_percent"]:
            key = f"node_disk_high:{name}"
            anomalies[key] = _anomaly(
                key, "node_disk_high", name, name, f"宿主机 {name} 存储空间不足",
                f"当前 {disk_percent:.1f}%，阈值 {thresholds['disk_percent']}%",
            )
        if rule_enabled(config, "node_load_high") and load_percent >= thresholds["load_percent"]:
            key = f"node_load_high:{name}"
            anomalies[key] = _anomaly(
                key, "node_load_high", name, name, f"宿主机 {name} 负载过高",
                f"1 分钟负载 {node['load']:.2f} / {node['cpu']} 核，比例 {load_percent:.1f}%",
            )
        if rule_enabled(config, "node_image_error") and node.get("image_error"):
            key = f"node_image_error:{name}"
            anomalies[key] = _anomaly(
                key, "node_image_error", name, name, f"宿主机 {name} 镜像查询失败",
                node["image_error"],
            )
    previous_snapshot = previous_snapshot or {}
    previous_instances = previous_snapshot.get("instances", {})
    try:
        previous_check = datetime.fromisoformat(
            str(previous_snapshot.get("captured_at", "")).replace("Z", "+00:00")
        )
        elapsed = (datetime.now(timezone.utc) - previous_check).total_seconds()
    except ValueError:
        elapsed = 0
    current_instances = {}
    for instance in instances:
        node = instance["node"]
        name = instance["name"]
        instance_key = f"{node}/{name}"
        current_instances[instance_key] = {
            "status": instance["status"],
            "cpu_usage_ns": int(instance.get("cpu_usage_ns", 0) or 0),
        }
        memory_total = int(instance.get("memory_total_bytes", 0) or 0)
        memory_used = int(instance.get("memory_used_bytes", 0) or 0)
        memory_percent = memory_used / memory_total * 100 if memory_total else 0
        if rule_enabled(config, "instance_memory_high") and memory_percent >= thresholds["instance_memory_percent"]:
            key = f"instance_memory_high:{instance_key}"
            anomalies[key] = _anomaly(
                key, "instance_memory_high", name, node, f"实例 {name} 内存使用率过高",
                f"当前 {memory_percent:.1f}%，阈值 {thresholds['instance_memory_percent']}%",
            )
        previous = previous_instances.get(instance_key, {})
        if not isinstance(previous, dict):
            previous = {}
        cpu_usage = int(instance.get("cpu_usage_ns", 0) or 0)
        previous_cpu_usage = int(previous.get("cpu_usage_ns", 0) or 0)
        allocated_time = int(instance.get("cpu_allocated_ns", 0) or 0)
        cpu_percent = (
            (cpu_usage - previous_cpu_usage) / elapsed / allocated_time * 100
            if elapsed > 0 and allocated_time > 0 and cpu_usage >= previous_cpu_usage
            else 0
        )
        if rule_enabled(config, "instance_cpu_high") and cpu_percent >= thresholds["instance_cpu_percent"]:
            key = f"instance_cpu_high:{instance_key}"
            anomalies[key] = _anomaly(
                key, "instance_cpu_high", name, node, f"实例 {name} CPU 使用率过高",
                f"巡检周期平均 {cpu_percent:.1f}%，阈值 {thresholds['instance_cpu_percent']}%",
            )
        if rule_enabled(config, "instance_not_running") and instance["status"] != "Running":
            key = f"instance_not_running:{instance_key}"
            anomalies[key] = _anomaly(
                key, "instance_not_running", name, node, f"实例 {name} 未运行",
                f"宿主机 {node} 返回状态 {instance['status']}",
            )
        if rule_enabled(config, "instance_no_ipv4") and instance["status"] == "Running" and not instance.get("ipv4"):
            key = f"instance_no_ipv4:{instance_key}"
            anomalies[key] = _anomaly(
                key, "instance_no_ipv4", name, node, f"实例 {name} 没有 IPv4",
                f"实例正在 {node} 运行，但未检测到全局 IPv4 地址",
            )
        if rule_enabled(config, "instance_traffic_exceeded") and instance.get("traffic_exceeded"):
            key = f"instance_traffic_exceeded:{instance_key}"
            action = "已自动停止实例" if instance.get("traffic_action") == "stop" else "仅通知"
            anomalies[key] = _anomaly(
                key, "instance_traffic_exceeded", name, node,
                f"实例 {name} 本月流量已超额",
                f"双向合计 {format_bytes(instance.get('traffic_used_bytes', 0))} / "
                f"{format_bytes(instance.get('traffic_limit_bytes', 0))}，处置：{action}",
            )
    if previous_snapshot.get("initialized") and rule_enabled(config, "instance_missing"):
        previous_nodes = previous_snapshot.get("nodes", {})
        for instance_key in previous_snapshot.get("instances", {}):
            if instance_key in current_instances:
                continue
            node, name = instance_key.split("/", 1)
            if previous_nodes.get(node) != "online" or node_statuses.get(node) != "online":
                continue
            key = f"instance_missing:{instance_key}"
            anomalies[key] = _anomaly(
                key, "instance_missing", name, node, f"实例 {name} 从宿主机消失",
                f"宿主机 {node} 在线，但本轮巡检未返回该实例",
            )
    snapshot = {
        "initialized": True,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nodes": node_statuses,
        "instances": current_instances,
    }
    return anomalies, snapshot


def telegram_text(event):
    prefix = "[严重]" if event["severity"] == "critical" else "[警告]"
    if event["kind"] == "recovery":
        prefix = "[恢复]"
    lines = [
        f"{prefix} Incus Control",
        event["title"],
        event["message"],
    ]
    if event.get("node"):
        lines.append(f"宿主机: {event['node']}")
    lines.append(f"时间: {event['time']}")
    return "\n".join(lines)


def redact_telegram_token(value, token):
    return str(value).replace(str(token), "***")


def send_telegram_message(config, text):
    telegram = config["telegram"]
    if not telegram.get("bot_token") or not telegram.get("chat_id"):
        raise ValueError("Telegram Bot Token 或 Chat ID 尚未配置")
    body = json.dumps({
        "chat_id": telegram["chat_id"],
        "text": text,
        "disable_web_page_preview": True,
    }).encode()
    request = Request(
        f"https://api.telegram.org/bot{telegram['bot_token']}/sendMessage",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            result = json.loads(response.read())
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("description", str(exc))
        except Exception:
            detail = str(exc)
        detail = redact_telegram_token(detail, telegram["bot_token"])
        raise RuntimeError(f"Telegram API 错误: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        detail = redact_telegram_token(exc, telegram["bot_token"])
        raise RuntimeError(f"无法连接 Telegram API: {detail}") from exc
    if not result.get("ok"):
        raise RuntimeError(f"Telegram 发送失败: {result.get('description', '未知错误')}")
    return True


def _update_notification_delivery(event_id, status, error=""):
    with NOTIFICATION_LOCK:
        data = _read_private_json(NOTIFICATIONS_FILE, default_notification_data())
        for event in data.get("events", []):
            if event.get("id") == event_id:
                event["telegram_status"] = status
                event["telegram_error"] = str(error)[:300]
                break
        data["telegram_last_error"] = str(error)[:300] if status == "failed" else ""
        _write_private_json(NOTIFICATIONS_FILE, data)


def _persist_anomalies(config, anomalies, snapshot, scan_error=""):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    outgoing = []
    with NOTIFICATION_LOCK:
        data = _read_private_json(NOTIFICATIONS_FILE, default_notification_data())
        previous_active = data.get("active", {})
        active = {}
        events = data.get("events", [])
        for key, anomaly in anomalies.items():
            if key in previous_active:
                current = {**previous_active[key], **anomaly, "last_seen": now}
            else:
                current = {**anomaly, "first_seen": now, "last_seen": now}
                event = {
                    **anomaly,
                    "id": secrets.token_urlsafe(12),
                    "kind": "alert",
                    "time": now,
                    "read": False,
                    "telegram_status": "not_sent",
                    "telegram_error": "",
                }
                events.insert(0, event)
                outgoing.append(event)
            active[key] = current
        for key, previous in previous_active.items():
            if key in anomalies:
                continue
            event = {
                **previous,
                "id": secrets.token_urlsafe(12),
                "kind": "recovery",
                "title": f"已恢复：{previous['title']}",
                "message": "本轮巡检已不再检测到该异常。",
                "time": now,
                "read": False,
                "telegram_status": "not_sent",
                "telegram_error": "",
            }
            events.insert(0, event)
            outgoing.append(event)
        data.update({
            "version": 1,
            "active": active,
            "events": events[:MAX_NOTIFICATION_EVENTS],
            "snapshot": snapshot,
            "last_check": now,
            "last_error": str(scan_error)[:500],
        })
        _write_private_json(NOTIFICATIONS_FILE, data)
    telegram = config["telegram"]
    if telegram.get("enabled"):
        for event in outgoing:
            mode = config["rules"].get(event["type"], "off")
            if mode != "panel_telegram" or (event["kind"] == "recovery" and not telegram.get("send_recovery")):
                continue
            try:
                send_telegram_message(config, telegram_text(event))
                _update_notification_delivery(event["id"], "sent")
            except Exception as exc:
                error = redact_telegram_token(exc, telegram.get("bot_token", ""))
                _update_notification_delivery(event["id"], "failed", error)
    return notification_payload()


def run_monitor_scan(force=False, traffic_only=False):
    global LAST_RECONCILE_AT
    with MONITOR_SCAN_LOCK:
        config = read_notification_config()
        data = read_notification_data()
        try:
            nodes, instances = overview()
            update_traffic_usage(instances)
            now_monotonic = time.monotonic()
            if force or now_monotonic - LAST_RECONCILE_AT >= RECONCILE_INTERVAL_SECONDS:
                try:
                    reconcile_state(nodes, instances, repair=False)
                    LAST_RECONCILE_AT = now_monotonic
                except Exception as reconcile_error:
                    print(f"状态一致性核对失败: {reconcile_error}", flush=True)
            if traffic_only or (not config["enabled"] and not force):
                return notification_payload()
            anomalies, snapshot = detect_anomalies(nodes, instances, config, data.get("snapshot"))
            return _persist_anomalies(config, anomalies, snapshot)
        except Exception as exc:
            if traffic_only or (not config["enabled"] and not force):
                raise
            anomalies = {
                key: dict(value) for key, value in data.get("active", {}).items()
                if value.get("type") != "monitor_failure"
            }
            if rule_enabled(config, "monitor_failure"):
                key = "monitor_failure:controller"
                anomalies[key] = _anomaly(
                    key, "monitor_failure", "控制端", "", "控制端巡检任务失败", str(exc)
                )
            return _persist_anomalies(
                config, anomalies, data.get("snapshot", default_notification_data()["snapshot"]), exc
            )


def test_telegram_notification():
    config = read_notification_config()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    send_telegram_message(config, f"[测试] Incus Control\nTelegram 异常通知连接正常。\n时间: {now}")
    return True


def monitor_loop():
    next_notification = 0.0
    while True:
        try:
            config = read_notification_config()
            now = time.monotonic()
            notification_due = config["enabled"] and now >= next_notification
            run_monitor_scan(traffic_only=not notification_due)
            if notification_due:
                next_notification = now + config["interval_seconds"]
            wait_seconds = min(60, max(1, next_notification - now)) if config["enabled"] else 60
        except Exception as exc:
            print(f"异常巡检失败: {exc}", flush=True)
            wait_seconds = 60
        woke = MONITOR_WAKE_EVENT.wait(wait_seconds)
        MONITOR_WAKE_EVENT.clear()
        if woke:
            next_notification = 0.0


def overview_for_session(session):
    nodes, instances = overview()
    account = {"username": session["username"], "role": session["role"]}
    if session["role"] == "admin":
        return {
            "account": account,
            "nodes": nodes,
            "instances": instances,
            "public_images": public_image_catalog(),
            "operations": recent_operations(),
            "users": list_user_accounts(),
            "notifications": notification_payload(),
            "tasks": list_tasks(session),
            "reconcile": read_reconcile_status(),
            "backups": public_backups(),
            "domains": read_domain_routes(),
        }
    record = get_user_account(session["username"]) or {}
    active = {
        key: expires_at for key, expires_at in assignment_map(record).items()
        if assignment_is_active(expires_at)
    }
    visible_instances = [
        {
            **instance,
            "authorization_expires_at": active[f"{instance['node']}/{instance['name']}"],
        }
        for instance in instances
        if f"{instance['node']}/{instance['name']}" in active
    ]
    visible_nodes = {
        instance["node"] for instance in visible_instances
    }
    minimal_nodes = [
        {"name": node["name"], "address": node["address"], "status": node["status"]}
        for node in nodes if node["name"] in visible_nodes
    ]
    return {
        "account": account,
        "nodes": minimal_nodes,
        "instances": visible_instances,
        "public_images": [],
        "operations": [],
        "users": [],
        "notifications": {},
        "tasks": list_tasks(session),
        "reconcile": {},
        "backups": {"backups": [], "policies": {}},
        "domains": {"routes": [], "apply": {}},
    }


def occupied_host_ports(instances):
    occupied = set()
    for item in instances:
        config = item.get("config") or item.get("expanded_config") or item
        ssh_port = str(config.get("user.incus-cn-panel.ssh-port", item.get("ssh_port", "")))
        if ssh_port.isdigit():
            occupied.add(int(ssh_port))
        start = str(config.get("user.incus-cn-panel.port-start", item.get("port_start", "")))
        end = str(config.get("user.incus-cn-panel.port-end", item.get("port_end", "")))
        if start.isdigit() and end.isdigit() and HOST_PORT_MIN <= int(start) <= int(end) <= HOST_PORT_MAX:
            occupied.update(range(int(start), int(end) + 1))
        devices = item.get("expanded_devices") or item.get("devices") or {}
        for device in devices.values():
            if not isinstance(device, dict) or device.get("type") != "proxy":
                continue
            match = re.search(r"^(?:tcp|udp):[^:]+:(\d+)(?:-(\d+))?$", str(device.get("listen", "")))
            if not match:
                continue
            first = int(match.group(1))
            last = int(match.group(2) or first)
            if HOST_PORT_MIN <= first <= last <= HOST_PORT_MAX and last - first <= MAX_PORTS_PER_INSTANCE:
                occupied.update(range(first, last + 1))
    return occupied


def port_is_used(node, port):
    raw_instances = json.loads(run_incus("list", f"{node}:", "--format=json", timeout=20))
    return int(port) in occupied_host_ports(raw_instances)


def validate_port_range(start, end):
    if start == "" and end == "":
        return None
    if not str(start).isdigit() or not str(end).isdigit():
        raise ValueError("业务端口段必须同时填写起始和结束端口")
    start = int(start)
    end = int(end)
    if not HOST_PORT_MIN <= start <= end <= HOST_PORT_MAX:
        raise ValueError(f"业务端口必须在 {HOST_PORT_MIN} 到 {HOST_PORT_MAX} 之间")
    if end - start + 1 > MAX_PORTS_PER_INSTANCE:
        raise ValueError(f"单台实例最多分配 {MAX_PORTS_PER_INSTANCE} 个业务端口")
    return start, end


def available_port_blocks(instances, pool_start, pool_end, ports_per_instance):
    if not HOST_PORT_MIN <= pool_start <= pool_end <= HOST_PORT_MAX:
        raise ValueError(f"端口池必须在 {HOST_PORT_MIN} 到 {HOST_PORT_MAX} 之间")
    if not 1 <= ports_per_instance <= MAX_PORTS_PER_INSTANCE:
        raise ValueError(f"每台业务端口数必须在 1 到 {MAX_PORTS_PER_INSTANCE} 之间")
    occupied = occupied_host_ports(instances)
    blocks = []
    candidate = pool_start
    while candidate + ports_per_instance - 1 <= pool_end:
        block_end = candidate + ports_per_instance - 1
        conflict = next((port for port in range(candidate, block_end + 1) if port in occupied), None)
        if conflict is None:
            blocks.append((candidate, block_end))
            candidate = block_end + 1
        else:
            candidate = conflict + 1
    return blocks


def allocate_ssh_port(node, reserved=None):
    raw_instances = json.loads(run_incus("list", f"{node}:", "--format=json", timeout=20))
    used = occupied_host_ports(raw_instances)
    used.update(reserved or ())
    for port in range(SSH_PORT_MIN, SSH_PORT_MAX + 1):
        if port not in used:
            return str(port)
    raise ValueError("该宿主机没有可分配的 SSH 端口")


def generate_ssh_password(length=18):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def provision_ssh(ref, password):
    script = r'''
set -eu
if command -v apk >/dev/null 2>&1; then
    apk add --no-cache openssh
    ssh-keygen -A
    service_name=sshd
elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y openssh-server
    mkdir -p /run/sshd
    ssh-keygen -A
    service_name=ssh
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y openssh-server
    ssh-keygen -A
    service_name=sshd
elif command -v yum >/dev/null 2>&1; then
    yum install -y openssh-server
    ssh-keygen -A
    service_name=sshd
else
    echo "当前镜像不支持自动安装 OpenSSH" >&2
    exit 1
fi
set_option() {
    key=$1
    value=$2
    if grep -Eq "^[#[:space:]]*${key}[[:space:]]+" /etc/ssh/sshd_config; then
        sed -i -E "s|^[#[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" /etc/ssh/sshd_config
    else
        printf '%s %s\n' "$key" "$value" >> /etc/ssh/sshd_config
    fi
}
set_option PermitRootLogin yes
set_option PasswordAuthentication yes
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-incus-cn-panel.conf <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
EOF
fi
printf 'root:%s\n' "$PANEL_SSH_PASSWORD" | chpasswd
/usr/sbin/sshd -t
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable "$service_name"
    systemctl restart "$service_name"
    systemctl is-active --quiet "$service_name"
elif command -v rc-update >/dev/null 2>&1; then
    rc-update add "$service_name" default
    rc-service "$service_name" restart
elif command -v service >/dev/null 2>&1; then
    service "$service_name" restart
else
    /usr/sbin/sshd
fi
'''.strip()
    run_incus(
        "exec", ref, "--env", f"PANEL_SSH_PASSWORD={password}",
        "--", "sh", "-c", script, timeout=600,
    )


def node_host(node):
    remote = registered_remotes().get(node) or {}
    address = (remote.get("Addrs") or [""])[0]
    return urlparse(address).hostname or ""


def configure_instance_access(node, name):
    node = require_node(node)
    if not NAME_RE.fullmatch(name):
        raise ValueError("实例名称无效")
    with INSTANCE_MUTATION_LOCK:
        try:
            return instance_credentials(node, name)
        except ValueError:
            pass
        instance = json.loads(
            run_incus("query", f"{node}:/1.0/instances/{name}?recursion=1", timeout=20)
        )
        config = instance.get("config") or {}
        devices = instance.get("expanded_devices") or instance.get("devices") or {}
        ssh_port = str(config.get("user.incus-cn-panel.ssh-port", ""))
        added_port = False
        added_proxy = False
        started = False
        if not ssh_port:
            ssh_port = allocate_ssh_port(node)
            run_incus("config", "set", f"{node}:{name}", "user.incus-cn-panel.ssh-port", ssh_port)
            added_port = True
        try:
            if "ssh" not in devices:
                run_incus(
                    "config", "device", "add", f"{node}:{name}", "ssh", "proxy",
                    f"listen=tcp:0.0.0.0:{ssh_port}", "connect=tcp:127.0.0.1:22",
                )
                added_proxy = True
            if instance.get("status") != "Running":
                run_incus("start", f"{node}:{name}", timeout=180)
                started = True
            password = generate_ssh_password()
            provision_ssh(f"{node}:{name}", password)
            access = {
                "host": node_host(node),
                "host_port": int(ssh_port),
                "guest_port": 22,
                "username": "root",
                "password": password,
            }
            port_start = str(config.get("user.incus-cn-panel.port-start", ""))
            port_end = str(config.get("user.incus-cn-panel.port-end", ""))
            if port_start.isdigit() and port_end.isdigit():
                access.update({
                    "port_start": int(port_start),
                    "port_end": int(port_end),
                    "port_count": int(port_end) - int(port_start) + 1,
                })
            save_instance_credentials(node, name, access)
            return access
        except Exception:
            if started:
                try:
                    run_incus("stop", f"{node}:{name}", "--force", timeout=180)
                except Exception:
                    pass
            if added_proxy:
                try:
                    run_incus("config", "device", "remove", f"{node}:{name}", "ssh")
                except Exception:
                    pass
            if added_port:
                try:
                    run_incus("config", "unset", f"{node}:{name}", "user.incus-cn-panel.ssh-port")
                except Exception:
                    pass
            raise


def create_instance(data, validate_capacity=False):
    node = require_node(str(data.get("node", "")))
    name = str(data.get("name", ""))
    kind = str(data.get("type", ""))
    image = str(data.get("image", ""))
    cpu = str(data.get("cpu", ""))
    cpu_allowance = str(data.get("cpu_allowance", "100"))
    memory = str(data.get("memory", ""))
    disk = str(data.get("disk", ""))
    ingress = str(data.get("ingress", "")).strip()
    egress = str(data.get("egress", "")).strip()
    read_iops = str(data.get("read_iops", "0"))
    write_iops = str(data.get("write_iops", "0"))
    ssh_port = str(data.get("ssh_port", "")).strip()
    port_start = str(data.get("port_start", "")).strip()
    port_end = str(data.get("port_end", "")).strip()
    traffic_limit, traffic_action = validate_traffic_quota(
        data.get("traffic_limit_bytes", 0), data.get("traffic_action", "stop")
    )
    if not NAME_RE.fullmatch(name):
        raise ValueError("名称只能包含字母、数字和连字符，最长 63 位")
    if kind not in {"container", "virtual-machine"}:
        raise ValueError("实例类型无效")
    if not cpu.isdigit() or not 1 <= int(cpu) <= 128:
        raise ValueError("CPU 核心数无效")
    if kind == "container" and (
        not cpu_allowance.isdigit()
        or not 1 <= int(cpu_allowance) <= int(cpu) * 100
    ):
        raise ValueError(f"LXC CPU 硬上限必须在 1% 到 {int(cpu) * 100}% 之间")
    if not SIZE_RE.fullmatch(memory) or not SIZE_RE.fullmatch(disk):
        raise ValueError("内存或磁盘格式无效")
    resolved_image = resolve_image(node, image, kind)
    validate_minimum_resources(memory, disk, resolved_image["profile"])
    if ingress and not RATE_RE.fullmatch(ingress):
        raise ValueError("入站网络速率格式无效")
    if egress and not RATE_RE.fullmatch(egress):
        raise ValueError("网络速率格式无效")
    if not read_iops.isdigit() or not write_iops.isdigit():
        raise ValueError("IOPS 必须是非负整数")
    if int(read_iops) > 1000000 or int(write_iops) > 1000000:
        raise ValueError("IOPS 上限过大")
    if ssh_port and (not ssh_port.isdigit() or not 1024 <= int(ssh_port) <= 65535):
        raise ValueError("SSH 端口必须在 1024 到 65535 之间")
    port_range = validate_port_range(port_start, port_end)
    swap_bytes = recommended_swap_bytes(memory, disk, kind)

    ref = f"{node}:{name}"
    created = False
    with INSTANCE_MUTATION_LOCK:
        if validate_capacity:
            node_info = live_node_info(node)
            maximum, limits = maximum_instances(node_info, data)
            if maximum < 1:
                raise ValueError(
                    "宿主机安全资源不足：当前配置会超过 CPU、内存或磁盘的"
                    f"安全预算（CPU 还可创建 {limits.get('cpu', 0)} 台）"
                )
        if ssh_port and port_is_used(node, ssh_port):
            raise ValueError("该节点上的 SSH 端口已被其他实例占用")
        reserved_ports = set(range(port_range[0], port_range[1] + 1)) if port_range else set()
        if ssh_port and int(ssh_port) in reserved_ports:
            raise ValueError("SSH 端口不能与本实例业务端口段重叠")
        if port_range:
            raw_instances = json.loads(run_incus("list", f"{node}:", "--format=json", timeout=20))
            occupied = occupied_host_ports(raw_instances)
            conflict = next((port for port in reserved_ports if port in occupied), None)
            if conflict is not None:
                raise ValueError(f"业务端口 {conflict} 已被其他实例占用")
        if not ssh_port:
            ssh_port = allocate_ssh_port(node, reserved_ports)
        ssh_password = generate_ssh_password()
        init_args = ["init", resolved_image["reference"], ref]
        if kind == "virtual-machine":
            init_args.append("--vm")
        init_args.extend(["-c", f"limits.cpu={cpu}"])
        if kind == "container":
            init_args.extend(["-c", f"limits.cpu.allowance={cpu_allowance}ms/100ms"])
            if swap_bytes:
                init_args.extend([
                    "-c", f"limits.memory.swap={format_binary_size(swap_bytes)}",
                ])
        init_args.extend([
            "-c", f"limits.memory={memory}",
            "-c", f"user.incus-cn-panel.image={image}",
        ])
        init_args.extend(["-c", f"user.incus-cn-panel.ssh-port={ssh_port}"])
        if traffic_limit:
            init_args.extend([
                "-c", f"user.incus-cn-panel.traffic-limit-bytes={traffic_limit}",
                "-c", f"user.incus-cn-panel.traffic-action={traffic_action}",
            ])
        if port_range:
            init_args.extend([
                "-c", f"user.incus-cn-panel.port-start={port_range[0]}",
                "-c", f"user.incus-cn-panel.port-end={port_range[1]}",
            ])
        run_incus(*init_args, timeout=600)
        created = True
        try:
            root_limits = [f"size={disk}"]
            if int(read_iops):
                root_limits.append(f"limits.read={read_iops}iops")
            if int(write_iops):
                root_limits.append(f"limits.write={write_iops}iops")
            run_incus("config", "device", "override", ref, "root", *root_limits)
            network_limits = []
            if ingress:
                network_limits.append(f"limits.ingress={ingress}")
            if egress:
                network_limits.append(f"limits.egress={egress}")
            if network_limits:
                run_incus("config", "device", "override", ref, "eth0", *network_limits)
            run_incus(
                "config", "device", "add", ref, "ssh", "proxy",
                f"listen=tcp:0.0.0.0:{ssh_port}", "connect=tcp:127.0.0.1:22",
            )
            if port_range:
                run_incus(
                    "config", "device", "add", ref, "ports", "proxy",
                    f"listen=tcp:0.0.0.0:{port_range[0]}-{port_range[1]}",
                    f"connect=tcp:127.0.0.1:{port_range[0]}-{port_range[1]}",
                )
            run_incus("start", ref, timeout=180)
            provision_ssh(ref, ssh_password)
            access = {
                "host": node_host(node),
                "host_port": int(ssh_port),
                "guest_port": 22,
                "username": "root",
                "password": ssh_password,
            }
            if port_range:
                access.update({
                    "port_start": port_range[0],
                    "port_end": port_range[1],
                    "port_count": port_range[1] - port_range[0] + 1,
                })
            save_instance_credentials(node, name, access)
            if traffic_limit:
                initialize_traffic_usage(
                    node, name, traffic_limit, traffic_action, reset=True
                )
        except Exception:
            if created:
                run_incus("delete", ref, "--force")
            raise
    return node, name, access


def maximum_instances(node_info, data):
    try:
        cpu = int(str(data.get("cpu", "0")) or 0)
    except (TypeError, ValueError):
        cpu = 0
    memory = parse_size_bytes(data.get("memory", ""))
    disk = parse_size_bytes(data.get("disk", ""))
    if cpu < 1 or memory < 1 or disk < 1 or node_info.get("status") != "online":
        return 0, {}
    cpu_total = int(node_info.get("cpu", 0))
    kind = str(data.get("type", "container"))
    if kind == "virtual-machine":
        cpu_per_instance = cpu * 100
    else:
        allowance = str(data.get("cpu_allowance", cpu * 100))
        cpu_per_instance = int(allowance) if allowance.isdigit() else 0
        if cpu_per_instance > cpu * 100:
            cpu_per_instance = 0
    cpu_budget = int(node_info.get("cpu_budget_percent", host_cpu_budget_percent(cpu_total)))
    cpu_committed = int(node_info.get("cpu_committed_percent", 0))
    cpu_available = int(node_info.get(
        "cpu_available_percent", max(0, cpu_budget - cpu_committed)
    ))
    limits = {
        "cpu": cpu_available // cpu_per_instance if cpu_per_instance else 0,
        "memory": int(node_info.get("available_memory", 0)) // memory,
        "disk": int(node_info.get("available_disk", 0)) // disk,
        "ssh_ports": int(node_info.get("available_ssh_ports", 0)),
    }
    try:
        ports_per_instance = int(data.get("port_count", 0) or 0)
    except (TypeError, ValueError):
        ports_per_instance = -1
    if ports_per_instance:
        try:
            pool_start = int(data.get("port_pool_start", 0))
            pool_end = int(data.get("port_pool_end", 0))
            limits["forward_ports"] = len(available_port_blocks(
                node_info.get("instances", []), pool_start, pool_end, ports_per_instance,
            ))
        except (TypeError, ValueError):
            limits["forward_ports"] = 0
    if cpu > cpu_total or cpu_per_instance < 1:
        return 0, limits
    hard_limits = [limits[key] for key in ("cpu", "memory", "disk", "ssh_ports")]
    if "forward_ports" in limits:
        hard_limits.append(limits["forward_ports"])
    return max(0, min(hard_limits)), limits


def live_node_info(node):
    node = require_node(node)
    remote = registered_remotes()[node]
    info = inspect_node(node, remote)
    if info["status"] != "online":
        raise ValueError(f"宿主机当前离线: {info['error']}")
    return info


def create_batch_instances(data, progress=None):
    node = require_node(str(data.get("node", "")))
    prefix = str(data.get("name_prefix", "")).lower()
    try:
        start = int(data.get("start_index", 1))
        count = int(data.get("count", 0))
        padding = int(data.get("padding", 3))
        port_count = int(data.get("port_count", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("批量编号参数无效") from exc
    if not 0 <= start <= 999999 or not 1 <= count <= 10000 or not 1 <= padding <= 6:
        raise ValueError("批量编号或数量无效")
    if not 0 <= port_count <= MAX_PORTS_PER_INSTANCE:
        raise ValueError(f"每台业务端口数必须在 0 到 {MAX_PORTS_PER_INSTANCE} 之间")
    names = [f"{prefix}{str(start + offset).zfill(padding)}" for offset in range(count)]
    if len(set(names)) != len(names) or any(not NAME_RE.fullmatch(name) for name in names):
        raise ValueError("批量实例名称无效，请调整前缀、编号或补零位数")
    batch_data = dict(data)
    traffic_allocation = str(data.get("traffic_allocation", "per_instance"))
    if traffic_allocation not in {"per_instance", "batch_total"}:
        raise ValueError("批量流量分配方式无效")
    if traffic_allocation == "batch_total":
        total_limit, _ = validate_traffic_quota(
            data.get("traffic_total_bytes", 0), data.get("traffic_action", "stop")
        )
        if total_limit:
            per_instance_limit = total_limit // count
            validate_traffic_quota(per_instance_limit, data.get("traffic_action", "stop"))
            batch_data["traffic_limit_bytes"] = str(per_instance_limit)
        else:
            batch_data["traffic_limit_bytes"] = "0"
    batch_data["ssh_port"] = ""
    batch_data["name"] = names[0]
    with INSTANCE_MUTATION_LOCK:
        node_info = live_node_info(node)
        port_blocks = []
        if port_count:
            try:
                pool_start = int(data.get("port_pool_start", 0))
                pool_end = int(data.get("port_pool_end", 0))
            except (TypeError, ValueError) as exc:
                raise ValueError("批量业务端口池无效") from exc
            port_blocks = available_port_blocks(
                node_info.get("instances", []), pool_start, pool_end, port_count,
            )
        maximum, limits = maximum_instances(node_info, batch_data)
        if count > maximum:
            raise ValueError(
                f"当前配置最多还能创建 {maximum} 台（内存 {limits.get('memory', 0)}、"
                f"磁盘 {limits.get('disk', 0)}、SSH {limits.get('ssh_ports', 0)}、"
                f"CPU {limits.get('cpu', 0)}、业务端口 "
                f"{limits.get('forward_ports', '未限制')}；宿主机 CPU 已预留 15%）"
            )
        existing = {item["name"] for item in node_info.get("instances", [])}
        duplicate = next((name for name in names if name in existing), "")
        if duplicate:
            raise ValueError(f"实例名称已存在: {duplicate}")
        created = []
        try:
            for index, name in enumerate(names):
                if progress:
                    progress(index, count, name)
                item_data = dict(batch_data)
                item_data["name"] = name
                if port_count:
                    item_data["port_start"], item_data["port_end"] = port_blocks[index]
                _, _, access = create_instance(item_data)
                created.append({"name": name, "access": access})
                if progress:
                    progress(index + 1, count, name)
        except Exception:
            for item in reversed(created):
                try:
                    run_incus("delete", f"{node}:{item['name']}", "--force", timeout=180)
                    delete_credentials(node, item["name"])
                    remove_traffic_usage(node, item["name"])
                except Exception:
                    pass
            raise
    return node, created


def validate_instance_identity(node, name):
    node = require_node(str(node))
    name = str(name)
    if not NAME_RE.fullmatch(name):
        raise ValueError("实例名称无效")
    return node, name, f"{node}:{name}"


def list_instance_snapshots(node, name):
    node, name, ref = validate_instance_identity(node, name)
    raw = json.loads(run_incus("snapshot", "list", ref, "--format=json", timeout=30))
    snapshots = []
    for item in raw if isinstance(raw, list) else []:
        snapshot_name = str(item.get("name", "")).split("/")[-1]
        if not SNAPSHOT_RE.fullmatch(snapshot_name):
            continue
        snapshots.append({
            "name": snapshot_name,
            "created_at": str(item.get("created_at") or item.get("created") or ""),
            "expires_at": str(item.get("expires_at") or ""),
            "stateful": bool(item.get("stateful", False)),
        })
    return sorted(snapshots, key=lambda item: item["created_at"], reverse=True)


def create_snapshot(node, name, snapshot_name):
    node, name, ref = validate_instance_identity(node, name)
    snapshot_name = str(snapshot_name).strip()
    if not SNAPSHOT_RE.fullmatch(snapshot_name):
        raise ValueError("快照名称只能包含字母、数字、点、下划线和连字符")
    run_incus("snapshot", "create", ref, snapshot_name, timeout=600)
    return list_instance_snapshots(node, name)


def restore_snapshot(node, name, snapshot_name):
    node, name, ref = validate_instance_identity(node, name)
    if not SNAPSHOT_RE.fullmatch(str(snapshot_name)):
        raise ValueError("快照名称无效")
    instance = json.loads(run_incus("query", f"{node}:/1.0/instances/{name}?recursion=1", timeout=30))
    was_running = instance.get("status") == "Running"
    if was_running:
        run_incus("stop", ref, "--force", timeout=300)
    try:
        run_incus("snapshot", "restore", ref, str(snapshot_name), timeout=900)
    except Exception:
        if was_running:
            try:
                run_incus("start", ref, timeout=300)
            except Exception:
                pass
        raise
    if was_running:
        run_incus("start", ref, timeout=300)


def delete_snapshot(node, name, snapshot_name):
    node, name, ref = validate_instance_identity(node, name)
    if not SNAPSHOT_RE.fullmatch(str(snapshot_name)):
        raise ValueError("快照名称无效")
    run_incus("snapshot", "delete", ref, str(snapshot_name), timeout=300)


def default_backups_data():
    return {"version": 1, "backups": [], "policies": {}}


def read_backups_data():
    with BACKUP_LOCK:
        data = _read_private_json(BACKUPS_FILE, default_backups_data())
    if not isinstance(data.get("backups"), list):
        data["backups"] = []
    if not isinstance(data.get("policies"), dict):
        data["policies"] = {}
    return data


def _write_backups_data(data):
    data["version"] = 1
    _write_private_json(BACKUPS_FILE, data)


def public_backups():
    data = read_backups_data()
    backups = []
    for item in data["backups"]:
        filename = os.path.join(BACKUP_DIR, f"{item.get('id', '')}.tar.gz")
        if os.path.isfile(filename):
            backups.append({**item, "size": os.path.getsize(filename)})
    backups.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return {"backups": backups, "policies": data["policies"]}


def create_instance_backup(node, name, reason="manual"):
    node, name, ref = validate_instance_identity(node, name)
    backup_id = secrets.token_hex(8)
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    filename = os.path.join(BACKUP_DIR, f"{backup_id}.tar.gz")
    try:
        run_incus("export", ref, filename, timeout=3600)
        os.chmod(filename, 0o600)
        record = {
            "id": backup_id, "node": node, "name": name, "reason": str(reason),
            "created_at": utc_now(), "size": os.path.getsize(filename),
        }
        with BACKUP_LOCK:
            data = _read_private_json(BACKUPS_FILE, default_backups_data())
            data.setdefault("backups", []).append(record)
            _write_backups_data(data)
        enforce_backup_retention(node, name)
        return record
    except Exception:
        try:
            os.unlink(filename)
        except FileNotFoundError:
            pass
        raise


def restore_instance_backup(backup_id):
    if not BACKUP_ID_RE.fullmatch(str(backup_id)):
        raise ValueError("备份编号无效")
    data = read_backups_data()
    backup = next((item for item in data["backups"] if item.get("id") == backup_id), None)
    if not backup:
        raise ValueError("备份不存在")
    node = require_node(str(backup.get("node", "")))
    filename = os.path.join(BACKUP_DIR, f"{backup_id}.tar.gz")
    if not os.path.isfile(filename):
        raise ValueError("备份文件已经丢失")
    raw = json.loads(run_incus("list", f"{node}:", "--format=json", timeout=30))
    if any(item.get("name") == backup.get("name") for item in raw):
        raise ValueError("同名实例仍然存在，请先删除或迁移后再恢复")
    run_incus("import", filename, f"{node}:", timeout=3600)
    return node, str(backup.get("name", ""))


def delete_instance_backup(backup_id):
    if not BACKUP_ID_RE.fullmatch(str(backup_id)):
        raise ValueError("备份编号无效")
    with BACKUP_LOCK:
        data = _read_private_json(BACKUPS_FILE, default_backups_data())
        before = len(data.setdefault("backups", []))
        data["backups"] = [item for item in data["backups"] if item.get("id") != backup_id]
        if len(data["backups"]) == before:
            raise ValueError("备份不存在")
        _write_backups_data(data)
    try:
        os.unlink(os.path.join(BACKUP_DIR, f"{backup_id}.tar.gz"))
    except FileNotFoundError:
        pass


def update_backup_policy(node, name, schedule, retention):
    node, name, _ = validate_instance_identity(node, name)
    schedule = str(schedule)
    if schedule not in {"off", "daily", "weekly"}:
        raise ValueError("备份周期无效")
    try:
        retention = int(retention)
    except (TypeError, ValueError) as exc:
        raise ValueError("备份保留数量无效") from exc
    if not 1 <= retention <= 30:
        raise ValueError("备份保留数量必须在 1 到 30 之间")
    key = f"{node}/{name}"
    with BACKUP_LOCK:
        data = _read_private_json(BACKUPS_FILE, default_backups_data())
        policies = data.setdefault("policies", {})
        if schedule == "off":
            policies.pop(key, None)
        else:
            policies[key] = {
                "node": node, "name": name, "schedule": schedule,
                "retention": retention, "updated_at": utc_now(),
                "last_backup_at": policies.get(key, {}).get("last_backup_at", ""),
            }
        _write_backups_data(data)
    BACKUP_WAKE_EVENT.set()
    return public_backups()["policies"].get(key, {})


def enforce_backup_retention(node, name):
    key = f"{node}/{name}"
    remove_ids = set()
    with BACKUP_LOCK:
        data = _read_private_json(BACKUPS_FILE, default_backups_data())
        policy = data.get("policies", {}).get(key)
        if not policy:
            return
        retention = int(policy.get("retention", 5) or 5)
        matching = sorted(
            [item for item in data.setdefault("backups", []) if item.get("node") == node and item.get("name") == name],
            key=lambda item: item.get("created_at", ""), reverse=True,
        )
        remove_ids = {item["id"] for item in matching[retention:]}
        if remove_ids:
            data["backups"] = [item for item in data["backups"] if item.get("id") not in remove_ids]
            _write_backups_data(data)
    for backup_id in remove_ids:
        try:
            os.unlink(os.path.join(BACKUP_DIR, f"{backup_id}.tar.gz"))
        except FileNotFoundError:
            pass


def backup_scheduler_loop():
    while True:
        try:
            data = read_backups_data()
            now = datetime.now(timezone.utc)
            for key, policy in data["policies"].items():
                try:
                    last_text = str(policy.get("last_backup_at", ""))
                    last = datetime.fromisoformat(last_text.replace("Z", "+00:00")) if last_text else None
                    interval = timedelta(days=1 if policy.get("schedule") == "daily" else 7)
                    if last and now - last < interval:
                        continue
                    task = enqueue_task(
                        "backup_create", f"定时备份 {policy['name']}",
                        node=policy["node"], target=policy["name"],
                        payload={"node": policy["node"], "name": policy["name"], "reason": policy["schedule"]},
                        owner="admin",
                    )
                    if task.get("status") in {"queued", "running"}:
                        with BACKUP_LOCK:
                            current = _read_private_json(BACKUPS_FILE, default_backups_data())
                            if key in current.setdefault("policies", {}):
                                current["policies"][key]["last_backup_at"] = utc_now()
                                _write_backups_data(current)
                except Exception as exc:
                    print(f"自动备份 {key} 启动失败: {exc}", flush=True)
        except Exception as exc:
            print(f"备份调度失败: {exc}", flush=True)
        BACKUP_WAKE_EVENT.wait(300)
        BACKUP_WAKE_EVENT.clear()


def move_instance_metadata(source, target, name):
    try:
        access = instance_credentials(source, name)
    except ValueError:
        access = None
    delete_credentials(source, name)
    if access:
        access["host"] = node_host(target)
        save_instance_credentials(target, name, access)
    with TRAFFIC_LOCK:
        data = _read_private_json(TRAFFIC_FILE, default_traffic_data())
        records = data.setdefault("instances", {})
        old_key, new_key = f"{source}/{name}", f"{target}/{name}"
        if old_key in records:
            records[new_key] = records.pop(old_key)
            _write_traffic_data(data)
    with USERS_LOCK:
        users = _read_users_unlocked()
        changed = False
        for record in users.values():
            assignments = assignment_map(record)
            if old_key in assignments:
                assignments[new_key] = assignments.pop(old_key)
                record["assignments"] = assignments
                changed = True
        if changed:
            _write_users_unlocked(users)


def migrate_instance(source, target, name):
    source, name, source_ref = validate_instance_identity(source, name)
    target = require_node(str(target))
    if source == target:
        raise ValueError("目标宿主机不能与当前宿主机相同")
    instance = json.loads(run_incus("query", f"{source}:/1.0/instances/{name}?recursion=1", timeout=30))
    parsed = parse_instances(source, [instance])[0]
    target_info = live_node_info(target)
    allowance_text = str(instance.get("config", {}).get("limits.cpu.allowance", ""))
    hard_allowance = re.fullmatch(r"(\d+)ms/(\d+)ms", allowance_text)
    soft_allowance = re.fullmatch(r"(\d+)%", allowance_text)
    if hard_allowance and int(hard_allowance.group(2)):
        cpu_allowance = max(1, int(hard_allowance.group(1)) * 100 // int(hard_allowance.group(2)))
    elif soft_allowance:
        cpu_allowance = max(1, int(soft_allowance.group(1)))
    else:
        cpu_allowance = int(parsed["cpu"]) * 100
    config = {
        "type": parsed["type"], "cpu": parsed["cpu"],
        "cpu_allowance": str(cpu_allowance),
        "memory": parsed["memory"], "disk": parsed["disk"], "port_count": "0",
    }
    if maximum_instances(target_info, config)[0] < 1:
        raise ValueError("目标宿主机的 CPU、内存或磁盘安全预算不足")
    source_ports = occupied_host_ports([instance])
    target_ports = occupied_host_ports(target_info.get("instances", []))
    conflict = next((port for port in source_ports if port in target_ports), None)
    if conflict is not None:
        raise ValueError(f"目标宿主机端口 {conflict} 已被占用")
    was_running = instance.get("status") == "Running"
    if was_running:
        run_incus("stop", source_ref, "--force", timeout=300)
    try:
        run_incus("move", source_ref, f"{target}:{name}", timeout=3600)
    except Exception:
        if was_running:
            try:
                run_incus("start", source_ref, timeout=180)
            except Exception:
                pass
        raise
    move_instance_metadata(source, target, name)
    if was_running:
        run_incus("start", f"{target}:{name}", timeout=300)
    return target, name


def rebuild_instance(node, name, image):
    node, name, ref = validate_instance_identity(node, name)
    instance = json.loads(run_incus("query", f"{node}:/1.0/instances/{name}?recursion=1", timeout=30))
    kind = "virtual-machine" if instance.get("type") == "virtual-machine" else "container"
    resolved = resolve_image(node, str(image), kind)
    run_incus("rebuild", resolved["reference"], ref, "--force", timeout=1800)
    run_incus("config", "set", ref, "user.incus-cn-panel.image", str(image))
    delete_credentials(node, name)
    return configure_instance_access(node, name)


def run_instance_console(node, name, command):
    node, name, ref = validate_instance_identity(node, name)
    command = str(command).strip()
    if not command or len(command) > 1000 or "\x00" in command:
        raise ValueError("命令长度必须在 1 到 1000 个字符之间")
    output = run_incus("exec", ref, "--", "sh", "-lc", command, timeout=30)
    return output[-20000:]


def list_instance_port_rules(node, name):
    node, name, _ = validate_instance_identity(node, name)
    instance = json.loads(run_incus("query", f"{node}:/1.0/instances/{name}?recursion=1", timeout=30))
    devices = instance.get("expanded_devices") or instance.get("devices") or {}
    rules = []
    for device_name, device in devices.items():
        if not str(device_name).startswith("panel-port-") or device.get("type") != "proxy":
            continue
        listen = re.search(r"^(tcp|udp):[^:]+:(\d+)$", str(device.get("listen", "")))
        connect = re.search(r"^(tcp|udp):[^:]+:(\d+)$", str(device.get("connect", "")))
        if listen and connect:
            rules.append({
                "id": str(device_name), "protocol": listen.group(1),
                "host_port": int(listen.group(2)), "guest_port": int(connect.group(2)),
            })
    return sorted(rules, key=lambda item: (item["protocol"], item["host_port"]))


def add_instance_port_rule(node, name, protocol, host_port, guest_port):
    node, name, ref = validate_instance_identity(node, name)
    protocol = str(protocol).lower()
    if protocol not in {"tcp", "udp"}:
        raise ValueError("端口协议只能是 TCP 或 UDP")
    try:
        host_port, guest_port = int(host_port), int(guest_port)
    except (TypeError, ValueError) as exc:
        raise ValueError("端口必须是整数") from exc
    if not 1024 <= host_port <= 65535 or not 1 <= guest_port <= 65535:
        raise ValueError("宿主机端口需在 1024-65535，实例端口需在 1-65535")
    if port_is_used(node, host_port):
        raise ValueError("宿主机端口已被其他实例占用")
    rule_id = f"panel-port-{secrets.token_hex(4)}"
    run_incus(
        "config", "device", "add", ref, rule_id, "proxy",
        f"listen={protocol}:0.0.0.0:{host_port}",
        f"connect={protocol}:127.0.0.1:{guest_port}",
    )
    return list_instance_port_rules(node, name)


def delete_instance_port_rule(node, name, rule_id):
    node, name, ref = validate_instance_identity(node, name)
    if not re.fullmatch(r"panel-port-[a-f0-9]{8}", str(rule_id)):
        raise ValueError("端口规则编号无效")
    run_incus("config", "device", "remove", ref, str(rule_id))
    return list_instance_port_rules(node, name)


def default_domain_routes():
    return {"version": 1, "routes": [], "apply": {"status": "idle", "message": ""}}


def read_domain_routes():
    with DOMAIN_LOCK:
        data = _read_private_json(DOMAINS_FILE, default_domain_routes())
    if not isinstance(data.get("routes"), list):
        data["routes"] = []
    return data


def write_caddy_routes(data):
    lines = ["# Generated by Incus Control. Do not edit manually.", ""]
    for route in sorted(data.get("routes", []), key=lambda item: item["domain"]):
        lines.extend([
            route["domain"] + " {",
            f"    reverse_proxy {route['target_host']}:{route['host_port']}",
            "}", "",
        ])
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    temporary = f"{CADDY_ROUTES_FILE}.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    os.replace(temporary, CADDY_ROUTES_FILE)
    apply_status = {"status": "generated", "message": f"配置已生成：{CADDY_ROUTES_FILE}"}
    caddy = shutil.which("caddy")
    if not data.get("routes"):
        subprocess.run(["systemctl", "stop", "incus-cn-panel-proxy.service"], capture_output=True)
        return {"status": "idle", "message": "当前没有域名路由"}
    if not caddy:
        return {"status": "pending", "message": "未安装 Caddy，配置已保存但尚未生效"}
    existing = subprocess.run(["systemctl", "is-active", "caddy.service"], capture_output=True, text=True)
    if existing.returncode == 0:
        return {"status": "pending", "message": "检测到系统已有 Caddy；请在现有 Caddyfile 中 import 生成的配置"}
    validation = subprocess.run(
        [caddy, "validate", "--config", CADDY_ROUTES_FILE], capture_output=True, text=True, timeout=20,
    )
    if validation.returncode != 0:
        return {"status": "failed", "message": (validation.stderr or validation.stdout)[-500:]}
    start = subprocess.run(
        ["systemctl", "enable", "--now", "incus-cn-panel-proxy.service"],
        capture_output=True, text=True, timeout=30,
    )
    if start.returncode != 0:
        return {"status": "pending", "message": (start.stderr or start.stdout or "Caddy 启动失败")[-500:]}
    restart = subprocess.run(
        ["systemctl", "restart", "incus-cn-panel-proxy.service"],
        capture_output=True, text=True, timeout=30,
    )
    if restart.returncode == 0 and shutil.which("ufw"):
        status = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
        if "Status: active" in status.stdout:
            subprocess.run(["ufw", "allow", "80/tcp"], capture_output=True, timeout=20)
            subprocess.run(["ufw", "allow", "443/tcp"], capture_output=True, timeout=20)
    return {"status": "active" if restart.returncode == 0 else "pending", "message": "HTTPS 反向代理已生效" if restart.returncode == 0 else (restart.stderr or restart.stdout)[-500:]}


def save_domain_route(domain, node, name, host_port):
    domain = str(domain).strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("域名格式无效，请填写完整域名")
    node, name, _ = validate_instance_identity(node, name)
    try:
        host_port = int(host_port)
    except (TypeError, ValueError) as exc:
        raise ValueError("反代端口无效") from exc
    instance = json.loads(run_incus("query", f"{node}:/1.0/instances/{name}?recursion=1", timeout=30))
    owned_ports = occupied_host_ports([instance])
    if host_port not in owned_ports:
        raise ValueError("该端口尚未分配给此实例，请先创建 TCP 端口转发")
    with DOMAIN_LOCK:
        data = _read_private_json(DOMAINS_FILE, default_domain_routes())
        routes = data.setdefault("routes", [])
        if any(item.get("domain") == domain for item in routes):
            raise ValueError("该域名已经存在")
        route = {
            "id": secrets.token_hex(8), "domain": domain, "node": node, "name": name,
            "host_port": host_port, "target_host": node_host(node), "created_at": utc_now(),
        }
        routes.append(route)
        data["apply"] = write_caddy_routes(data)
        _write_private_json(DOMAINS_FILE, data)
    return route, data["apply"]


def delete_domain_route(route_id):
    if not BACKUP_ID_RE.fullmatch(str(route_id)):
        raise ValueError("域名路由编号无效")
    with DOMAIN_LOCK:
        data = _read_private_json(DOMAINS_FILE, default_domain_routes())
        before = len(data.setdefault("routes", []))
        data["routes"] = [item for item in data["routes"] if item.get("id") != route_id]
        if len(data["routes"]) == before:
            raise ValueError("域名路由不存在")
        data["apply"] = write_caddy_routes(data)
        _write_private_json(DOMAINS_FILE, data)
    return data


def task_create_instance(context, payload):
    name = str(payload.get("name", ""))
    context.update(5, "检查配置", "正在复核宿主机容量、名称和端口")
    context.update(18, "创建实例", "正在下载镜像并创建 Incus 实例")
    node, name, _access = create_instance(payload, validate_capacity=True)
    context.update(92, "验证 SSH", "实例已启动，正在确认连接信息", check_cancelled=False)
    return {
        "message": f"实例 {name} 已创建并完成 SSH 配置",
        "node": node, "name": name,
    }


def task_create_batch(context, payload):
    try:
        total = int(payload.get("count", 0))
    except (TypeError, ValueError):
        total = 0
    context.update(3, "批量预检", "正在锁定名称、资源和端口计划")

    def progress(done, count, name):
        value = 8 + int(done / max(1, count) * 86)
        context.update(value, f"创建 {done}/{count}", f"正在处理实例 {name}")

    node, created = create_batch_instances(payload, progress=progress)
    return {
        "message": f"已成功创建 {len(created)} 台实例",
        "node": node, "count": len(created),
        "instances": [item["name"] for item in created],
    }


def task_node_preflight(context, payload):
    node = str(payload.get("node", ""))
    context.update(10, "连接宿主机", "正在读取 Incus API 和硬件资源")
    report = node_preflight(node)
    context.update(90, "生成体检报告", report["summary"])
    return {
        "message": f"{node} 体检完成：{report['summary']}",
        "node": node, "preflight": report,
    }


def task_reconcile(context, payload):
    repair = bool(payload.get("repair", False))
    context.update(10, "读取实际状态", "正在读取全部宿主机与实例")
    nodes, instances = overview()
    context.update(65, "比对控制端数据", "正在核对凭据、流量和用户授权")
    report = reconcile_state(nodes, instances, repair=repair)
    context.update(95, "保存核对报告", report["summary"])
    return {
        "message": report["summary"], "reconcile": report,
        "repaired_count": report["repaired_count"],
    }


def task_instance_action(context, payload):
    node, name, ref = validate_instance_identity(payload.get("node"), payload.get("name"))
    action = str(payload.get("action", ""))
    if action not in {"start", "stop", "restart"}:
        raise ValueError("不支持的实例操作")
    context.update(15, "检查实例状态", f"正在准备{action}实例 {name}")
    if action in {"start", "restart"}:
        instance = json.loads(run_incus("query", f"{node}:/1.0/instances/{name}?recursion=1", timeout=20))
        traffic = traffic_quota_status(node, name, instance.get("config") or {})
        if traffic["exceeded"] and traffic["action"] == "stop":
            raise ValueError("该实例本月流量已超过配额，请调整配额或重置用量后再启动")
    args = [action, ref]
    if action in {"stop", "restart"}:
        args.append("--force")
    context.update(45, "执行生命周期操作", f"Incus 正在{action}实例")
    run_incus(*args, timeout=300)
    return {"message": f"实例 {name} 操作完成", "node": node, "name": name, "action": action}


def _remove_domain_routes_for_instance(node, name):
    with DOMAIN_LOCK:
        data = _read_private_json(DOMAINS_FILE, default_domain_routes())
        before = len(data.setdefault("routes", []))
        data["routes"] = [
            item for item in data["routes"]
            if item.get("node") != node or item.get("name") != name
        ]
        if len(data["routes"]) != before:
            data["apply"] = write_caddy_routes(data)
            _write_private_json(DOMAINS_FILE, data)


def task_instance_delete(context, payload):
    node, name, ref = validate_instance_identity(payload.get("node"), payload.get("name"))
    context.update(10, "确认实例", "正在确认实例仍然存在")
    context.update(35, "永久删除", "正在删除实例及其快照")
    run_incus("delete", ref, "--force", timeout=600)
    delete_credentials(node, name)
    remove_instance_assignments(node, name)
    remove_traffic_usage(node, name)
    _remove_domain_routes_for_instance(node, name)
    return {"message": f"实例 {name} 已永久删除", "node": node, "name": name}


def task_snapshot_create(context, payload):
    context.update(15, "创建快照", "正在冻结实例文件系统并保存快照")
    snapshots = create_snapshot(payload.get("node"), payload.get("name"), payload.get("snapshot"))
    return {"message": "快照创建完成", "snapshots": snapshots}


def task_snapshot_restore(context, payload):
    context.update(10, "准备回滚", "正在确认快照和实例状态")
    context.update(35, "恢复快照", "正在将实例磁盘回滚到快照")
    restore_snapshot(payload.get("node"), payload.get("name"), payload.get("snapshot"))
    return {"message": f"已恢复快照 {payload.get('snapshot', '')}"}


def task_snapshot_delete(context, payload):
    context.update(20, "删除快照", "正在释放快照占用空间")
    delete_snapshot(payload.get("node"), payload.get("name"), payload.get("snapshot"))
    return {"message": f"快照 {payload.get('snapshot', '')} 已删除"}


def task_backup_create(context, payload):
    context.update(10, "准备导出", "正在检查控制端备份空间")
    record = create_instance_backup(
        payload.get("node"), payload.get("name"), payload.get("reason", "manual")
    )
    context.update(92, "登记备份", "备份文件已写入控制端")
    return {"message": f"实例 {record['name']} 备份完成", "backup": record}


def task_backup_restore(context, payload):
    context.update(10, "验证备份", "正在检查备份文件和同名实例")
    node, name = restore_instance_backup(str(payload.get("backup_id", "")))
    context.update(88, "恢复连接", "正在重新生成实例 SSH 凭据")
    delete_credentials(node, name)
    access = configure_instance_access(node, name)
    return {"message": f"实例 {name} 已从备份恢复", "node": node, "name": name, "host_port": access["host_port"]}


def task_backup_delete(context, payload):
    context.update(20, "删除备份", "正在删除控制端备份文件")
    delete_instance_backup(str(payload.get("backup_id", "")))
    return {"message": "备份文件已删除"}


def task_instance_migrate(context, payload):
    context.update(8, "迁移预检", "正在检查目标资源和端口冲突")
    target, name = migrate_instance(
        payload.get("node"), payload.get("target_node"), payload.get("name")
    )
    context.update(92, "启动目标实例", "迁移完成，正在确认目标宿主机状态")
    return {"message": f"实例 {name} 已迁移到 {target}", "node": target, "name": name}


def task_instance_rebuild(context, payload):
    context.update(10, "重装预检", "正在解析目标系统镜像")
    access = rebuild_instance(
        payload.get("node"), payload.get("name"), payload.get("image")
    )
    return {"message": f"实例 {payload.get('name', '')} 已重装并重置 SSH 密码", "host_port": access["host_port"]}


TASK_RUNNERS.update({
    "instance_create": task_create_instance,
    "instance_batch_create": task_create_batch,
    "node_preflight": task_node_preflight,
    "state_reconcile": task_reconcile,
    "instance_action": task_instance_action,
    "instance_delete": task_instance_delete,
    "snapshot_create": task_snapshot_create,
    "snapshot_restore": task_snapshot_restore,
    "snapshot_delete": task_snapshot_delete,
    "backup_create": task_backup_create,
    "backup_restore": task_backup_restore,
    "backup_delete": task_backup_delete,
    "instance_migrate": task_instance_migrate,
    "instance_rebuild": task_instance_rebuild,
})




with open(os.path.join(ASSET_DIR, "index.html"), encoding="utf-8") as html_file:
    HTML = html_file.read()


class PanelServer(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = f"IncusCNPanel/{APP_VERSION}"

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self):
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def send_asset(self, filename, content_type):
        try:
            with open(os.path.join(ASSET_DIR, filename), "rb") as asset_file:
                body = asset_file.read()
        except FileNotFoundError:
            self.send_json(404, {"error": "资源不存在"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > MAX_JSON_BODY_BYTES:
            raise ValueError("请求内容长度无效")
        return json.loads(self.rfile.read(length))

    def read_image_upload(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("镜像文件长度无效") from exc
        if length < 1:
            raise ValueError("请选择镜像文件")
        if length > MAX_IMAGE_UPLOAD_BYTES:
            raise ValueError(f"镜像文件不能超过 {format_bytes(MAX_IMAGE_UPLOAD_BYTES)}")
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        free = shutil.disk_usage(DATA_DIR).free
        if free < length + 256 * 1024**2:
            raise ValueError("控制端临时磁盘空间不足")
        descriptor, filename = tempfile.mkstemp(prefix="image-", suffix=".tar", dir=DATA_DIR)
        os.fchmod(descriptor, 0o600)
        remaining = length
        try:
            with os.fdopen(descriptor, "wb") as handle:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("镜像文件上传不完整")
                    handle.write(chunk)
                    remaining -= len(chunk)
            return filename
        except Exception:
            try:
                os.unlink(filename)
            except FileNotFoundError:
                pass
            raise

    def session(self):
        clean_sessions()
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = jar.get("incus_cn_session")
        if not morsel:
            return None, None
        token = morsel.value
        data = SESSIONS.get(token)
        if data:
            if data.get("role") == "user":
                account = get_user_account(data.get("username", ""))
                if not account or not account.get("enabled", True):
                    SESSIONS.pop(token, None)
                    return None, None
            data["expires"] = time.time() + SESSION_TTL
        return token, data

    def require_auth(self, csrf=False):
        token, session = self.session()
        if not session:
            self.send_json(401, {"error": "请先登录"})
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            self.send_json(403, {"error": "安全令牌无效，请刷新页面重试"})
            return None
        return token, session

    def require_admin(self, csrf=False):
        auth = self.require_auth(csrf=csrf)
        if not auth:
            return None
        if auth[1].get("role") != "admin":
            self.send_json(403, {"error": "需要管理员权限"})
            return None
        return auth

    def require_instance_access(self, session, node, name):
        if not session_can_access_instance(session, node, name):
            self.send_json(403, {"error": "该实例未授权或授权已经到期"})
            return False
        return True

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        if path == "/":
            self.send_html()
            return
        if path == "/assets/lucide.min.js":
            self.send_asset("lucide.min.js", "text/javascript; charset=utf-8")
            return
        if path == "/assets/login-datacenter.webp":
            self.send_asset("login-datacenter.webp", "image/webp")
            return
        if path == "/api/session":
            auth = self.require_auth()
            if not auth:
                return
            session = auth[1]
            self.send_json(200, {
                "ok": True,
                "csrf": session["csrf"],
                "account": {
                    "username": session["username"],
                    "role": session["role"],
                },
                "panel_version": APP_VERSION,
            })
            return
        if path == "/api/overview":
            auth = self.require_auth()
            if not auth:
                return
            try:
                payload = overview_for_session(auth[1])
                payload["csrf"] = auth[1]["csrf"]
                payload["panel_version"] = APP_VERSION
                payload["panel_update"] = read_update_status()
                self.send_json(200, payload)
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
            return
        if path == "/api/users":
            auth = self.require_admin()
            if not auth:
                return
            self.send_json(200, {"users": list_user_accounts()})
            return
        if path == "/api/nodes/live":
            auth = self.require_admin()
            if not auth:
                return
            try:
                self.send_json(200, node_live_payload())
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
            return
        if path == "/api/tasks":
            auth = self.require_auth()
            if not auth:
                return
            self.send_json(200, {"tasks": list_tasks(auth[1])})
            return
        if path == "/api/system/reconcile":
            auth = self.require_admin()
            if not auth:
                return
            self.send_json(200, {"reconcile": read_reconcile_status()})
            return
        preflight_match = re.fullmatch(r"/api/nodes/([^/]+)/preflight", path)
        if preflight_match:
            auth = self.require_admin()
            if not auth:
                return
            try:
                node = require_node(preflight_match.group(1))
                report = read_node_health(node)
                if not report:
                    self.send_json(404, {"error": "该宿主机尚未执行接入体检"})
                else:
                    self.send_json(200, {"preflight": report})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        manage_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/manage", path)
        if manage_match:
            auth = self.require_auth()
            if not auth:
                return
            node, name = manage_match.groups()
            if not NAME_RE.fullmatch(node) or not NAME_RE.fullmatch(name):
                self.send_json(400, {"error": "实例名称无效"})
                return
            if not self.require_instance_access(auth[1], node, name):
                return
            try:
                payload = {
                    "node": node, "name": name,
                    "snapshots": list_instance_snapshots(node, name),
                    "port_rules": [], "backups": [], "policy": {}, "nodes": [],
                }
                if auth[1].get("role") == "admin":
                    backup_data = public_backups()
                    key = f"{node}/{name}"
                    payload.update({
                        "port_rules": list_instance_port_rules(node, name),
                        "backups": [item for item in backup_data["backups"] if item.get("node") == node and item.get("name") == name],
                        "policy": backup_data["policies"].get(key, {}),
                        "nodes": [item for item in registered_remotes() if item != node],
                    })
                self.send_json(200, payload)
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/backups":
            auth = self.require_admin()
            if not auth:
                return
            self.send_json(200, public_backups())
            return
        if path == "/api/domains":
            auth = self.require_admin()
            if not auth:
                return
            self.send_json(200, read_domain_routes())
            return
        if path == "/api/notifications":
            auth = self.require_admin()
            if not auth:
                return
            self.send_json(200, {"notifications": notification_payload()})
            return
        if path == "/api/system/version":
            auth = self.require_admin()
            if not auth:
                return
            try:
                refresh = parse_qs(parsed_url.query).get("refresh") == ["1"]
                self.send_json(200, panel_version_payload(refresh=refresh))
            except Exception as exc:
                self.send_json(502, {"error": str(exc)})
            return
        images_match = re.fullmatch(r"/api/nodes/([^/]+)/images", path)
        if images_match:
            auth = self.require_admin()
            if not auth:
                return
            try:
                node = require_node(images_match.group(1))
                self.send_json(200, {
                    "node": node,
                    "images": list_node_images(node),
                    "public_images": public_image_catalog(),
                })
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        access_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/access", path)
        if access_match:
            auth = self.require_auth()
            if not auth:
                return
            try:
                requested_node = access_match.group(1)
                name = access_match.group(2)
                if not NAME_RE.fullmatch(requested_node) or not NAME_RE.fullmatch(name):
                    raise ValueError("实例名称无效")
                if not self.require_instance_access(auth[1], requested_node, name):
                    return
                node = require_node(requested_node)
                self.send_json(200, {"access": instance_credentials(node, name)})
            except Exception as exc:
                self.send_json(404, {"error": str(exc)})
            return
        self.send_json(404, {"error": "页面不存在"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/login":
            ip = self.client_address[0]
            attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(ip, []) if stamp > time.time() - 300]
            LOGIN_ATTEMPTS[ip] = attempts
            if len(attempts) >= 8:
                self.send_json(429, {"error": "登录失败次数过多，请稍后再试"})
                return
            try:
                data = self.read_json()
            except Exception:
                self.send_json(400, {"error": "请求格式无效"})
                return
            account = authenticate_account(data.get("username", ""), data.get("password", ""))
            if not account:
                attempts.append(time.time())
                self.send_json(401, {"error": "用户名或密码错误"})
                return
            LOGIN_ATTEMPTS.pop(ip, None)
            token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_urlsafe(24)
            SESSIONS[token] = {
                **account,
                "csrf": csrf_token,
                "expires": time.time() + SESSION_TTL,
            }
            cookie = f"incus_cn_session={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}"
            self.send_json(200, {
                "ok": True,
                "csrf": csrf_token,
                "account": account,
                "panel_version": APP_VERSION,
            }, {"Set-Cookie": cookie})
            return

        auth = self.require_auth(csrf=True)
        if not auth:
            return
        if path == "/api/logout":
            SESSIONS.pop(auth[0], None)
            self.send_json(200, {"ok": True}, {"Set-Cookie": "incus_cn_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"})
            return
        if path == "/api/account/password":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                data = self.read_json()
                new_password = str(data.get("new_password", ""))
                if not hmac.compare_digest(
                    new_password, str(data.get("confirm_password", ""))
                ):
                    raise ValueError("两次输入的新密码不一致")
                change_admin_password(data.get("current_password", ""), new_password)
                record_operation("admin_password_change", PANEL_USER, message="管理员密码已修改")
                self.send_json(200, {
                    "ok": True,
                    "message": "密码修改成功，请使用新密码重新登录",
                }, {
                    "Set-Cookie": "incus_cn_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
                })
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
            return
        if path == "/api/system/update":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                latest_version = fetch_latest_version()
                update = start_panel_update(latest_version)
                record_operation(
                    "panel_update", latest_version,
                    message=f"从 {APP_VERSION} 更新到 {latest_version}",
                )
                self.send_json(202, {
                    "ok": True,
                    "message": "升级任务已启动，完成后面板会自动重启",
                    "update": update,
                })
            except ValueError as exc:
                self.send_json(409, {"error": str(exc)})
            except Exception as exc:
                record_operation("panel_update", APP_VERSION, status="failed", message=str(exc))
                self.send_json(500, {"error": str(exc)})
            return
        if path == "/api/scheduler/plan":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                data = self.read_json()
                node_info = live_node_info(str(data.get("node", "")))
                plan = scheduler_plan(
                    node_info, data.get("count", 1), str(data.get("type", "container")),
                    str(data.get("image", "")), str(data.get("strategy", "balanced")),
                )
                self.send_json(200, {"plan": plan})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/system/reconcile":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                data = self.read_json()
                repair = bool(data.get("repair", False))
                task = enqueue_task(
                    "state_reconcile", "修复状态一致性" if repair else "核对状态一致性",
                    target="控制端状态", payload={"repair": repair},
                    owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        preflight_match = re.fullmatch(r"/api/nodes/([^/]+)/preflight", path)
        if preflight_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                node = require_node(preflight_match.group(1))
                task = enqueue_task(
                    "node_preflight", f"体检宿主机 {node}", node=node, target=node,
                    payload={"node": node}, owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        task_match = re.fullmatch(r"/api/tasks/([a-f0-9]{16})/(retry|cancel)", path)
        if task_match:
            task = get_task(task_match.group(1), private=True)
            if not task:
                self.send_json(404, {"error": "任务不存在"})
                return
            if auth[1].get("role") != "admin" and task.get("owner") != auth[1].get("username"):
                self.send_json(403, {"error": "无权操作该任务"})
                return
            try:
                if task_match.group(2) == "retry":
                    updated = retry_task(task["id"], auth[1]["username"])
                else:
                    updated = cancel_task(task["id"])
                self.send_json(202, {"ok": True, "task": updated})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        snapshot_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/snapshots", path)
        if snapshot_match:
            node, name = snapshot_match.groups()
            if not self.require_instance_access(auth[1], node, name):
                return
            try:
                data = self.read_json()
                action = str(data.get("action", "create"))
                task_type = {
                    "create": "snapshot_create", "restore": "snapshot_restore",
                    "delete": "snapshot_delete",
                }.get(action)
                if not task_type:
                    raise ValueError("快照操作无效")
                snapshot = str(data.get("snapshot", ""))
                task = enqueue_task(
                    task_type, f"{action} 快照 {snapshot}", node=node,
                    target=f"{name}/{snapshot}",
                    payload={"node": node, "name": name, "snapshot": snapshot},
                    owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        console_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/console", path)
        if console_match:
            node, name = console_match.groups()
            if not self.require_instance_access(auth[1], node, name):
                return
            try:
                output = run_instance_console(node, name, self.read_json().get("command", ""))
                record_operation("instance_console", name, node, message=f"由 {auth[1]['username']} 执行命令")
                self.send_json(200, {"ok": True, "output": output})
            except subprocess.TimeoutExpired:
                self.send_json(504, {"error": "命令执行超过 30 秒，已停止等待"})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        policy_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/backup-policy", path)
        if policy_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                data = self.read_json()
                policy = update_backup_policy(
                    policy_match.group(1), policy_match.group(2),
                    data.get("schedule", "off"), data.get("retention", 5),
                )
                self.send_json(200, {"ok": True, "policy": policy})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        backup_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/backup", path)
        if backup_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                node, name = backup_match.groups()
                validate_instance_identity(node, name)
                task = enqueue_task(
                    "backup_create", f"备份实例 {name}", node=node, target=name,
                    payload={"node": node, "name": name, "reason": "manual"},
                    owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        backup_action_match = re.fullmatch(r"/api/backups/([a-f0-9]{16})/(restore|delete)", path)
        if backup_action_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                backup_id, action = backup_action_match.groups()
                backup = next((item for item in public_backups()["backups"] if item["id"] == backup_id), None)
                if not backup:
                    raise ValueError("备份不存在")
                task = enqueue_task(
                    f"backup_{action}", f"{action} 备份 {backup['name']}",
                    node=backup["node"], target=backup["name"],
                    payload={"backup_id": backup_id}, owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        migrate_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/migrate", path)
        if migrate_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                node, name = migrate_match.groups()
                target = str(self.read_json().get("target_node", ""))
                require_node(target)
                task = enqueue_task(
                    "instance_migrate", f"迁移实例 {name}", node=node, target=name,
                    payload={"node": node, "name": name, "target_node": target},
                    owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        rebuild_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/rebuild", path)
        if rebuild_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                node, name = rebuild_match.groups()
                image = str(self.read_json().get("image", ""))
                task = enqueue_task(
                    "instance_rebuild", f"重装实例 {name}", node=node, target=name,
                    payload={"node": node, "name": name, "image": image},
                    owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        port_rule_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/port-rules", path)
        if port_rule_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                node, name = port_rule_match.groups()
                data = self.read_json()
                action = str(data.get("action", "add"))
                if action == "add":
                    rules = add_instance_port_rule(
                        node, name, data.get("protocol", "tcp"),
                        data.get("host_port"), data.get("guest_port"),
                    )
                elif action == "delete":
                    rules = delete_instance_port_rule(node, name, data.get("rule_id", ""))
                else:
                    raise ValueError("端口规则操作无效")
                self.send_json(200, {"ok": True, "port_rules": rules})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/domains":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                data = self.read_json()
                route, apply = save_domain_route(
                    data.get("domain", ""), data.get("node", ""),
                    data.get("name", ""), data.get("host_port"),
                )
                self.send_json(201, {"ok": True, "route": route, "apply": apply})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        domain_delete_match = re.fullmatch(r"/api/domains/([a-f0-9]{16})/delete", path)
        if domain_delete_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                data = delete_domain_route(domain_delete_match.group(1))
                self.send_json(200, {"ok": True, "domains": data})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/notifications/config":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                config = update_notification_config(self.read_json())
                record_operation("notification_config", "异常通知", message="更新巡检与 Telegram 配置")
                self.send_json(200, {"ok": True, "config": config})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/notifications/scan":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                notifications = run_monitor_scan(force=True)
                self.send_json(200, {"ok": True, "notifications": notifications})
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
            return
        if path == "/api/notifications/read":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                notifications = mark_notifications_read()
                self.send_json(200, {"ok": True, "notifications": notifications})
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
            return
        if path == "/api/notifications/telegram/test":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                test_telegram_notification()
                self.send_json(200, {"ok": True})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/users":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            try:
                data = self.read_json()
                user = create_user_account(data.get("username", ""), str(data.get("password", "")))
                record_operation("user_create", user["username"], message="创建普通账户")
                self.send_json(201, {"ok": True, "user": user})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        user_match = re.fullmatch(r"/api/users/([a-zA-Z0-9][a-zA-Z0-9_.-]{2,31})", path)
        if user_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            username = user_match.group(1).lower()
            try:
                data = self.read_json()
                enabled = data.get("enabled") if "enabled" in data else None
                assignments = data.get("assignments") if "assignments" in data else None
                password = str(data.get("password", ""))
                user = update_user_account(username, enabled, password, assignments)
                active_count = sum(item["active"] for item in user["assignments"])
                record_operation("user_update", username, message=f"有效授权 {active_count} 台实例")
                self.send_json(200, {"ok": True, "user": user})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/nodes":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            name = ""
            try:
                data = self.read_json()
                name = str(data.get("name", "")).lower()
                address = normalize_address(str(data.get("address", "")))
                token = str(data.get("token", "")).strip()
                if not NAME_RE.fullmatch(name) or name == "local":
                    raise ValueError("节点名称只能包含字母、数字和连字符")
                if not 20 <= len(token) <= 12000:
                    raise ValueError("Trust Token 无效")
                add_remote(name, address, token)
                record_operation("node_add", name, name, message=address)
                self.send_json(201, {"ok": True})
            except NodeConnectionError as exc:
                record_operation(
                    "node_add", name or "未知节点", name, "failed",
                    f"{exc.stage}: {exc.summary}; {exc.detail}"[:1000],
                )
                self.send_json(exc.status, exc.payload())
            except Exception as exc:
                record_operation("node_add", name or "未知节点", name, "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            return
        copy_match = re.fullmatch(r"/api/nodes/([^/]+)/images/copy", path)
        if copy_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            node = copy_match.group(1)
            image_id = ""
            try:
                data = self.read_json()
                image_id = str(data.get("image", ""))
                alias = str(data.get("alias", "")).strip()
                images = copy_public_image(node, image_id, alias)
                record_operation("image_copy", image_id, node, message=alias)
                self.send_json(201, {"ok": True, "images": images})
            except subprocess.TimeoutExpired:
                record_operation("image_copy", image_id or "未知镜像", node, "failed", "下载超时")
                self.send_json(504, {"error": "镜像下载超时"})
            except Exception as exc:
                record_operation("image_copy", image_id or "未知镜像", node, "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            return
        upload_match = re.fullmatch(r"/api/nodes/([^/]+)/images/upload", path)
        if upload_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            node = upload_match.group(1)
            alias = self.headers.get("X-Image-Alias", "").strip()
            filename = ""
            try:
                filename = self.read_image_upload()
                images = import_local_image(node, filename, alias)
                record_operation("image_upload", alias or "本地镜像", node)
                self.send_json(201, {"ok": True, "images": images})
            except subprocess.TimeoutExpired:
                record_operation("image_upload", alias or "本地镜像", node, "failed", "导入超时")
                self.send_json(504, {"error": "镜像导入超时"})
            except Exception as exc:
                record_operation("image_upload", alias or "本地镜像", node, "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            finally:
                if filename:
                    try:
                        os.unlink(filename)
                    except FileNotFoundError:
                        pass
            return
        if path == "/api/instances":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            node = ""
            name = ""
            try:
                data = self.read_json()
                node = str(data.get("node", ""))
                name = str(data.get("name", ""))
                require_node(node)
                if not NAME_RE.fullmatch(name):
                    raise ValueError("实例名称格式无效")
                task = enqueue_task(
                    "instance_create", f"创建实例 {name}", node=node, target=name,
                    payload=data, owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/instances/batch":
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "需要管理员权限"})
                return
            node = ""
            prefix = ""
            try:
                data = self.read_json()
                node = str(data.get("node", ""))
                prefix = str(data.get("name_prefix", ""))
                require_node(node)
                if not prefix:
                    raise ValueError("请填写批量名称前缀")
                task = enqueue_task(
                    "instance_batch_create", f"批量创建 {data.get('count', 0)} 台实例",
                    node=node, target=prefix, payload=data, owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return

        access_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/access", path)
        if access_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "只有管理员可以配置实例 SSH"})
                return
            node = access_match.group(1)
            name = access_match.group(2)
            try:
                access = configure_instance_access(node, name)
                record_operation("instance_access", name, node)
                self.send_json(200, {"ok": True, "access": access})
            except Exception as exc:
                record_operation("instance_access", name, node, "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            return

        traffic_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/traffic", path)
        if traffic_match:
            if auth[1].get("role") != "admin":
                self.send_json(403, {"error": "只有管理员可以调整实例流量配额"})
                return
            node = traffic_match.group(1)
            name = traffic_match.group(2)
            try:
                data = self.read_json()
                traffic = update_instance_traffic_quota(
                    node, name, data.get("traffic_limit_bytes", 0),
                    data.get("traffic_action", "stop"), data.get("reset_usage", False),
                )
                record_operation(
                    "instance_traffic_update", name, node,
                    message=(
                        f"月配额 {format_bytes(traffic['limit_bytes'])}"
                        if traffic["limit_bytes"] else "取消月流量限制"
                    ),
                )
                self.send_json(200, {"ok": True, "traffic": traffic})
            except Exception as exc:
                record_operation("instance_traffic_update", name, node, "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            return

        match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/action", path)
        if match:
            try:
                requested_node = match.group(1)
                name = match.group(2)
                if not NAME_RE.fullmatch(requested_node) or not NAME_RE.fullmatch(name):
                    raise ValueError("实例名称无效")
                if not self.require_instance_access(auth[1], requested_node, name):
                    return
                node = require_node(requested_node)
                action = str(self.read_json().get("action", ""))
                if action not in {"start", "stop", "restart"}:
                    raise ValueError("不支持的操作")
                task = enqueue_task(
                    "instance_action", f"{action} 实例 {name}", node=node, target=name,
                    payload={"node": node, "name": name, "action": action},
                    owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        self.send_json(404, {"error": "接口不存在"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        auth = self.require_admin(csrf=True)
        if not auth:
            return
        user_match = re.fullmatch(r"/api/users/([a-zA-Z0-9][a-zA-Z0-9_.-]{2,31})", path)
        if user_match:
            username = user_match.group(1).lower()
            try:
                delete_user_account(username)
                record_operation("user_delete", username, message="删除普通账户")
                self.send_json(200, {"ok": True})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        image_match = re.fullmatch(r"/api/nodes/([^/]+)/images/([a-fA-F0-9]{12,64})", path)
        if image_match:
            node = image_match.group(1)
            fingerprint = image_match.group(2)
            try:
                delete_local_image(node, fingerprint)
                record_operation("image_delete", fingerprint[:12], node)
                self.send_json(200, {"ok": True})
            except Exception as exc:
                record_operation("image_delete", fingerprint[:12], node, "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            return
        node_match = re.fullmatch(r"/api/nodes/([^/]+)", path)
        if node_match:
            try:
                node = require_node(node_match.group(1))
                with REMOTE_CONFIG_LOCK:
                    run_incus("remote", "remove", node, timeout=20)
                delete_credentials(node)
                remove_instance_assignments(node)
                remove_traffic_usage(node)
                record_operation("node_remove", node, node)
                self.send_json(200, {"ok": True})
            except Exception as exc:
                record_operation("node_remove", node_match.group(1), node_match.group(1), "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            return
        instance_match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)", path)
        if instance_match:
            try:
                node = require_node(instance_match.group(1))
                name = instance_match.group(2)
                if not NAME_RE.fullmatch(name):
                    raise ValueError("实例名称无效")
                task = enqueue_task(
                    "instance_delete", f"删除实例 {name}", node=node, target=name,
                    payload={"node": node, "name": name}, owner=auth[1]["username"],
                )
                self.send_json(202, {"ok": True, "task": task})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        self.send_json(404, {"error": "接口不存在"})


def main():
    if not PASSWORD_SALT or not PASSWORD_HASH:
        raise SystemExit("缺少面板密码配置")
    recover_interrupted_tasks()
    server = PanelServer((HOST, PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    server.socket = context.wrap_socket(
        server.socket,
        server_side=True,
        do_handshake_on_connect=False,
    )
    threading.Thread(target=monitor_loop, name="notification-monitor", daemon=True).start()
    threading.Thread(target=backup_scheduler_loop, name="backup-scheduler", daemon=True).start()
    print(f"Incus 中文集群面板正在监听 https://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
