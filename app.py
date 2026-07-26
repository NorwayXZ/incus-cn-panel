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
ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SESSIONS = {}
LOGIN_ATTEMPTS = {}
REMOTE_CONFIG_LOCK = threading.Lock()
INSTANCE_MUTATION_LOCK = threading.RLock()
OPERATION_LOCK = threading.Lock()
CREDENTIALS_LOCK = threading.Lock()
SESSION_TTL = 12 * 60 * 60
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")
SIZE_RE = re.compile(r"^[1-9][0-9]*(MiB|GiB)$")
SIZE_VALUE_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([KMGTPE]?i?B)$", re.IGNORECASE)
RATE_RE = re.compile(r"^[1-9][0-9]*(kbit|Mbit|Gbit)$")
IMAGE_ALIAS_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$")
FINGERPRINT_RE = re.compile(r"^[a-fA-F0-9]{12,64}$")
SSH_PORT_MIN = 22000
SSH_PORT_MAX = 59999
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
    return {
        "cpu": cpu,
        "memory": memory,
        "disk": disk,
        "unlimited_instances": unlimited,
        "ssh_ports": ssh_ports,
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
            "available_ssh_ports": max(0, SSH_PORT_MAX - SSH_PORT_MIN + 1 - allocations["ssh_ports"]),
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


def port_is_used(node, port):
    raw_instances = json.loads(run_incus("list", f"{node}:", "--format=json", timeout=20))
    expected = str(port)
    return any(
        (item.get("config") or {}).get("user.incus-cn-panel.ssh-port") == expected
        for item in raw_instances
    )


def allocate_ssh_port(node):
    raw_instances = json.loads(run_incus("list", f"{node}:", "--format=json", timeout=20))
    used = {
        int(value)
        for item in raw_instances
        if (value := (item.get("config") or {}).get("user.incus-cn-panel.ssh-port", "")).isdigit()
    }
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

    ref = f"{node}:{name}"
    created = False
    with INSTANCE_MUTATION_LOCK:
        if ssh_port and port_is_used(node, ssh_port):
            raise ValueError("该节点上的 SSH 端口已被其他实例占用")
        if not ssh_port:
            ssh_port = allocate_ssh_port(node)
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
            run_incus("start", ref, timeout=180)
            provision_ssh(ref, ssh_password)
            access = {
                "host": node_host(node),
                "host_port": int(ssh_port),
                "guest_port": 22,
                "username": "root",
                "password": ssh_password,
            }
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
    if cpu > cpu_total:
        return 0, limits
    return max(0, min(limits[key] for key in ("memory", "disk", "ssh_ports"))), limits


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
    except (TypeError, ValueError) as exc:
        raise ValueError("批量编号参数无效") from exc
    if not 0 <= start <= 999999 or not 1 <= count <= 10000 or not 1 <= padding <= 6:
        raise ValueError("批量编号或数量无效")
    names = [f"{prefix}{str(start + offset).zfill(padding)}" for offset in range(count)]
    if len(set(names)) != len(names) or any(not NAME_RE.fullmatch(name) for name in names):
        raise ValueError("批量实例名称无效，请调整前缀、编号或补零位数")
    batch_data = dict(data)
    batch_data["ssh_port"] = ""
    batch_data["name"] = names[0]
    with INSTANCE_MUTATION_LOCK:
        node_info = live_node_info(node)
        maximum, limits = maximum_instances(node_info, batch_data)
        if count > maximum:
            raise ValueError(
                f"当前配置最多还能创建 {maximum} 台（内存 {limits.get('memory', 0)}、"
                f"磁盘 {limits.get('disk', 0)}、端口 {limits.get('ssh_ports', 0)}；CPU 共享调度）"
            )
        existing = {item["name"] for item in node_info.get("instances", [])}
        duplicate = next((name for name in names if name in existing), "")
        if duplicate:
            raise ValueError(f"实例名称已存在: {duplicate}")
        created = []
        try:
            for name in names:
                item_data = dict(batch_data)
                item_data["name"] = name
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


class Handler(BaseHTTPRequestHandler):
    server_version = "IncusCNPanel/0.6"

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
        if length < 1 or length > 16384:
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
                nodes, instances = overview()
                self.send_json(200, {
                    "nodes": nodes,
                    "instances": instances,
                    "public_images": public_image_catalog(),
                    "operations": recent_operations(),
                    "csrf": auth[1]["csrf"],
                })
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
            return
        images_match = re.fullmatch(r"/api/nodes/([^/]+)/images", path)
        if images_match:
            auth = self.require_auth()
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
                node = require_node(access_match.group(1))
                name = access_match.group(2)
                if not NAME_RE.fullmatch(name):
                    raise ValueError("实例名称无效")
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
            if not hmac.compare_digest(str(data.get("username", "")), PANEL_USER) or not password_matches(str(data.get("password", ""))):
                attempts.append(time.time())
                self.send_json(401, {"error": "用户名或密码错误"})
                return
            LOGIN_ATTEMPTS.pop(ip, None)
            token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_urlsafe(24)
            SESSIONS[token] = {"csrf": csrf_token, "expires": time.time() + SESSION_TTL}
            cookie = f"incus_cn_session={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}"
            self.send_json(200, {"ok": True, "csrf": csrf_token}, {"Set-Cookie": cookie})
            return

        auth = self.require_auth(csrf=True)
        if not auth:
            return
        if path == "/api/logout":
            SESSIONS.pop(auth[0], None)
            self.send_json(200, {"ok": True}, {"Set-Cookie": "incus_cn_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"})
            return
        if path == "/api/nodes":
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
                node = require_node(match.group(1))
                name = match.group(2)
                if not NAME_RE.fullmatch(name):
                    raise ValueError("实例名称无效")
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
        auth = self.require_auth(csrf=True)
        if not auth:
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
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Incus 中文集群面板正在监听 https://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
