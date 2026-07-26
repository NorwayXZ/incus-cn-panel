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
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


HOST = os.environ.get("PANEL_HOST", "127.0.0.1")
PORT = int(os.environ.get("PANEL_PORT", "8443"))
PANEL_USER = os.environ.get("PANEL_USER", "admin")
PASSWORD_SALT = os.environ.get("PANEL_PASSWORD_SALT", "")
PASSWORD_HASH = os.environ.get("PANEL_PASSWORD_HASH", "")
PASSWORD_ITERATIONS = int(os.environ.get("PANEL_PASSWORD_ITERATIONS", "0"))
TLS_CERT = os.environ.get("TLS_CERT", "/etc/incus-cn-panel/panel.crt")
TLS_KEY = os.environ.get("TLS_KEY", "/etc/incus-cn-panel/panel.key")
DATA_DIR = os.environ.get("PANEL_DATA_DIR", "/var/lib/incus-cn-panel")
OPERATIONS_FILE = os.path.join(DATA_DIR, "operations.jsonl")
CREDENTIALS_FILE = os.path.join(DATA_DIR, "credentials.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SESSIONS = {}
LOGIN_ATTEMPTS = {}
REMOTE_CONFIG_LOCK = threading.Lock()
INSTANCE_MUTATION_LOCK = threading.RLock()
OPERATION_LOCK = threading.Lock()
CREDENTIALS_LOCK = threading.Lock()
USERS_LOCK = threading.Lock()
SESSION_TTL = 12 * 60 * 60
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,31}$")
SIZE_RE = re.compile(r"^[1-9][0-9]*(MiB|GiB)$")
SIZE_VALUE_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([KMGTPE]?i?B)$", re.IGNORECASE)
RATE_RE = re.compile(r"^[1-9][0-9]*(kbit|Mbit|Gbit)$")
IMAGE_ALIAS_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$")
FINGERPRINT_RE = re.compile(r"^[a-fA-F0-9]{12,64}$")
SSH_PORT_MIN = 22000
SSH_PORT_MAX = 59999
HOST_PORT_MIN = 1024
HOST_PORT_MAX = 65535
MAX_PORTS_PER_INSTANCE = 1000
USER_PASSWORD_ITERATIONS = 260000
MAX_USER_ASSIGNMENTS = 500
MAX_JSON_BODY_BYTES = 128 * 1024
MAX_IMAGE_UPLOAD_BYTES = int(os.environ.get("MAX_IMAGE_UPLOAD_BYTES", str(8 * 1024**3)))
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


def run_incus(*args, timeout=120):
    result = subprocess.run(
        ["/usr/bin/incus", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "LC_ALL": "C.UTF-8"},
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


def add_remote(name, address, token):
    with REMOTE_CONFIG_LOCK:
        if name in registered_remotes():
            raise ValueError("节点名称已经存在")
        run_incus("remote", "add", name, token, timeout=90)
        try:
            run_incus("remote", "set-url", name, address, timeout=20)
            run_incus("query", f"{name}:/1.0", timeout=20)
        except Exception:
            run_incus("remote", "remove", name, timeout=20)
            raise


def format_bytes(value):
    value = int(value or 0)
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


def allocation_summary(instances, memory_total=0):
    cpu = 0
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
        ipv4 = ""
        for interface in (state.get("network") or {}).values():
            for address in interface.get("addresses", []):
                if address.get("family") == "inet" and address.get("scope") == "global":
                    ipv4 = address.get("address", "")
                    break
            if ipv4:
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
            "disk": root_device.get("size", "不限"),
            "image": config.get("user.incus-cn-panel.image", "未知镜像"),
            "ssh_port": config.get("user.incus-cn-panel.ssh-port", ""),
            "port_start": config.get("user.incus-cn-panel.port-start", ""),
            "port_end": config.get("user.incus-cn-panel.port-end", ""),
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
        allocations = allocation_summary(instances, int(memory.get("total", 0)))
        occupied_ports = occupied_host_ports(instances)
        memory_reserved = max(int(memory.get("used", 0)), allocations["memory"])
        disk_reserved = max(disk_used, allocations["disk"])
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
            "cpu": int((resources.get("cpu") or {}).get("total", 0)),
            "memory": int(memory.get("total", 0)),
            "memory_used": int(memory.get("used", 0)),
            "disk": disk_total,
            "disk_used": disk_used,
            "allocated_cpu": allocations["cpu"],
            "allocated_memory": allocations["memory"],
            "allocated_disk": allocations["disk"],
            "available_cpu": int((resources.get("cpu") or {}).get("total", 0)),
            "available_memory": max(0, int(memory.get("total", 0)) - memory_reserved),
            "available_disk": max(0, disk_total - disk_reserved),
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
            "disk": 0,
            "disk_used": 0,
            "allocated_cpu": 0,
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
            "error": str(exc),
        }


def overview():
    remotes = registered_remotes()
    if not remotes:
        return [], []
    with ThreadPoolExecutor(max_workers=min(8, len(remotes))) as executor:
        nodes = list(executor.map(lambda item: inspect_node(*item), remotes.items()))
    nodes.sort(key=lambda item: item["name"])
    instances = [instance for node in nodes for instance in node.pop("instances")]
    return nodes, instances


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
printf 'root:%s\n' "$PANEL_SSH_PASSWORD" | chpasswd
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "$service_name"
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


def create_instance(data):
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
    if not NAME_RE.fullmatch(name):
        raise ValueError("名称只能包含字母、数字和连字符，最长 63 位")
    if kind not in {"container", "virtual-machine"}:
        raise ValueError("实例类型无效")
    if not cpu.isdigit() or not 1 <= int(cpu) <= 128:
        raise ValueError("CPU 核心数无效")
    if not cpu_allowance.isdigit() or not 1 <= int(cpu_allowance) <= 100:
        raise ValueError("CPU 配额无效")
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

    ref = f"{node}:{name}"
    created = False
    with INSTANCE_MUTATION_LOCK:
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
        init_args.extend([
            "-c", f"limits.cpu={cpu}",
            "-c", f"limits.cpu.allowance={cpu_allowance}%",
            "-c", f"limits.memory={memory}",
            "-c", f"user.incus-cn-panel.image={image}",
        ])
        init_args.extend(["-c", f"user.incus-cn-panel.ssh-port={ssh_port}"])
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
        except Exception:
            if created:
                run_incus("delete", ref, "--force")
            raise
    return node, name, access


def maximum_instances(node_info, data):
    cpu = int(str(data.get("cpu", "0")) or 0)
    memory = parse_size_bytes(data.get("memory", ""))
    disk = parse_size_bytes(data.get("disk", ""))
    if cpu < 1 or memory < 1 or disk < 1 or node_info.get("status") != "online":
        return 0, {}
    cpu_total = int(node_info.get("cpu", node_info.get("available_cpu", 0)))
    limits = {
        "cpu": "共享" if cpu <= cpu_total else 0,
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
    if cpu > cpu_total:
        return 0, limits
    hard_limits = [limits[key] for key in ("memory", "disk", "ssh_ports")]
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


def create_batch_instances(data):
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
                f"业务端口 {limits.get('forward_ports', '未限制')}；CPU 共享调度）"
            )
        existing = {item["name"] for item in node_info.get("instances", [])}
        duplicate = next((name for name in names if name in existing), "")
        if duplicate:
            raise ValueError(f"实例名称已存在: {duplicate}")
        created = []
        try:
            for index, name in enumerate(names):
                item_data = dict(batch_data)
                item_data["name"] = name
                if port_count:
                    item_data["port_start"], item_data["port_end"] = port_blocks[index]
                _, _, access = create_instance(item_data)
                created.append({"name": name, "access": access})
        except Exception:
            for item in reversed(created):
                try:
                    run_incus("delete", f"{node}:{item['name']}", "--force", timeout=180)
                    delete_credentials(node, item["name"])
                except Exception:
                    pass
            raise
    return node, created




with open(os.path.join(ASSET_DIR, "index.html"), encoding="utf-8") as html_file:
    HTML = html_file.read()


class PanelServer(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "IncusCNPanel/0.8"

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
        path = urlparse(self.path).path
        if path == "/":
            self.send_html()
            return
        if path == "/assets/lucide.min.js":
            self.send_asset("lucide.min.js", "text/javascript; charset=utf-8")
            return
        if path == "/api/overview":
            auth = self.require_auth()
            if not auth:
                return
            try:
                payload = overview_for_session(auth[1])
                payload["csrf"] = auth[1]["csrf"]
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
            self.send_json(200, {"ok": True, "csrf": csrf_token, "account": account}, {"Set-Cookie": cookie})
            return

        auth = self.require_auth(csrf=True)
        if not auth:
            return
        if path == "/api/logout":
            SESSIONS.pop(auth[0], None)
            self.send_json(200, {"ok": True}, {"Set-Cookie": "incus_cn_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"})
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
            except subprocess.TimeoutExpired:
                record_operation("node_add", name or "未知节点", name, "failed", "连接超时")
                self.send_json(504, {"error": "连接节点超时，请检查地址和防火墙"})
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
                node, name, access = create_instance(data)
                record_operation("instance_create", name, node)
                self.send_json(201, {"ok": True, "access": access})
            except subprocess.TimeoutExpired:
                record_operation("instance_create", name or "未知实例", node, "failed", "创建超时")
                self.send_json(504, {"error": "镜像下载或实例创建超时"})
            except Exception as exc:
                record_operation("instance_create", name or "未知实例", node, "failed", str(exc))
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
                node, created = create_batch_instances(data)
                record_operation(
                    "instance_batch_create", prefix or "批量实例", node,
                    message=f"成功创建 {len(created)} 台实例",
                )
                self.send_json(201, {"ok": True, "count": len(created), "instances": created})
            except subprocess.TimeoutExpired:
                record_operation(
                    "instance_batch_create", prefix or "批量实例", node,
                    "failed", "批量创建超时",
                )
                self.send_json(504, {"error": "批量创建超时，已尝试清理本批实例"})
            except Exception as exc:
                record_operation(
                    "instance_batch_create", prefix or "批量实例", node,
                    "failed", str(exc),
                )
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

        match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/action", path)
        if match:
            node = ""
            name = ""
            action = "action"
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
                args = [action, f"{node}:{name}"]
                if action in {"stop", "restart"}:
                    args.append("--force")
                run_incus(*args, timeout=180)
                record_operation(f"instance_{action}", name, node)
                self.send_json(200, {"ok": True})
            except Exception as exc:
                record_operation(
                    f"instance_{action}", name or "未知实例", node,
                    "failed", str(exc),
                )
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
                run_incus("delete", f"{node}:{name}", "--force", timeout=180)
                delete_credentials(node, name)
                remove_instance_assignments(node, name)
                record_operation("instance_delete", name, node)
                self.send_json(200, {"ok": True})
            except Exception as exc:
                record_operation("instance_delete", instance_match.group(2), instance_match.group(1), "failed", str(exc))
                self.send_json(400, {"error": str(exc)})
            return
        self.send_json(404, {"error": "接口不存在"})


def main():
    if not PASSWORD_SALT or not PASSWORD_HASH:
        raise SystemExit("缺少面板密码配置")
    server = PanelServer((HOST, PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    server.socket = context.wrap_socket(
        server.socket,
        server_side=True,
        do_handshake_on_connect=False,
    )
    print(f"Incus 中文集群面板正在监听 https://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
