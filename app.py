#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import subprocess
import time
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
SESSIONS = {}
LOGIN_ATTEMPTS = {}
SESSION_TTL = 12 * 60 * 60
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")
SIZE_RE = re.compile(r"^[1-9][0-9]*(MiB|GiB)$")


def run_incus(*args, timeout=120):
    command = ["/usr/bin/incus", *args]
    result = subprocess.run(
        command,
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


HTML = r'''<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Incus 中文管理面板</title>
  <style>
    :root { --ink:#182026; --muted:#647078; --line:#d9dee2; --bg:#f5f7f8; --paper:#fff; --green:#0b7a53; --green2:#075e41; --red:#b42318; --amber:#a15c00; --nav:#17252d; }
    * { box-sizing:border-box; }
    body { margin:0; font:14px/1.5 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif; color:var(--ink); background:var(--bg); }
    button,input,select { font:inherit; }
    button { cursor:pointer; }
    .hidden { display:none!important; }
    .login { min-height:100vh; display:grid; place-items:center; padding:24px; background:#edf2f0; }
    .login-box { width:min(390px,100%); background:var(--paper); border:1px solid var(--line); border-top:4px solid var(--green); border-radius:6px; padding:30px; box-shadow:0 16px 45px rgba(23,37,45,.11); }
    .brand { display:flex; align-items:center; gap:11px; font-size:18px; font-weight:700; }
    .mark { width:30px; height:30px; display:grid; place-items:center; color:#fff; background:var(--green); border-radius:5px; font-weight:800; }
    .login h1 { margin:28px 0 4px; font-size:22px; }
    .login p { margin:0 0 22px; color:var(--muted); }
    label { display:block; margin:14px 0 6px; font-weight:600; }
    input,select { width:100%; min-height:40px; padding:8px 10px; color:var(--ink); background:#fff; border:1px solid #b8c1c7; border-radius:4px; outline:none; }
    input:focus,select:focus { border-color:var(--green); box-shadow:0 0 0 2px rgba(11,122,83,.13); }
    .btn { min-height:38px; padding:7px 13px; border:1px solid #aeb8be; border-radius:4px; color:var(--ink); background:#fff; font-weight:600; }
    .btn:hover { background:#f1f4f5; }
    .btn.primary { color:#fff; border-color:var(--green); background:var(--green); }
    .btn.primary:hover { background:var(--green2); }
    .btn.danger { color:var(--red); border-color:#e4b5af; }
    .btn.small { min-height:30px; padding:4px 9px; font-size:13px; }
    .login .btn { width:100%; margin-top:22px; }
    .error { color:var(--red); margin-top:12px; min-height:21px; }
    header { height:58px; display:flex; align-items:center; justify-content:space-between; padding:0 24px; color:#fff; background:var(--nav); }
    header .mark { background:#10a56f; }
    header .btn { color:#fff; border-color:#53636b; background:transparent; }
    main { width:min(1180px,100%); margin:0 auto; padding:24px; }
    .toolbar { display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:20px; }
    .toolbar h1 { margin:0; font-size:22px; }
    .actions { display:flex; gap:8px; }
    .stats { display:grid; grid-template-columns:repeat(4,1fr); border:1px solid var(--line); border-radius:6px; background:var(--paper); margin-bottom:20px; overflow:hidden; }
    .stat { min-height:90px; padding:16px 18px; border-right:1px solid var(--line); }
    .stat:last-child { border-right:0; }
    .stat span { display:block; color:var(--muted); }
    .stat strong { display:block; margin-top:5px; font-size:22px; }
    .panel { border:1px solid var(--line); border-radius:6px; background:var(--paper); overflow:hidden; }
    .panel-head { display:flex; justify-content:space-between; align-items:center; min-height:54px; padding:10px 16px; border-bottom:1px solid var(--line); }
    .panel-head h2 { margin:0; font-size:16px; }
    table { width:100%; border-collapse:collapse; }
    th,td { padding:12px 14px; text-align:left; border-bottom:1px solid #e6e9eb; vertical-align:middle; }
    th { color:#526069; background:#f8f9fa; font-size:12px; font-weight:700; }
    tr:last-child td { border-bottom:0; }
    .status { display:inline-flex; align-items:center; gap:6px; font-weight:600; }
    .dot { width:8px; height:8px; border-radius:50%; background:#8b969d; }
    .running .dot { background:#0e9f6e; }
    .stopped .dot { background:#8b969d; }
    .row-actions { display:flex; flex-wrap:wrap; gap:6px; }
    .empty { padding:46px 20px; text-align:center; color:var(--muted); }
    .toast { position:fixed; right:20px; bottom:20px; z-index:10; max-width:min(440px,calc(100vw - 40px)); padding:12px 16px; color:#fff; background:#26343c; border-radius:5px; box-shadow:0 8px 24px rgba(0,0,0,.18); }
    dialog { width:min(520px,calc(100% - 32px)); padding:0; border:0; border-radius:6px; box-shadow:0 24px 70px rgba(0,0,0,.25); }
    dialog::backdrop { background:rgba(17,27,32,.52); }
    .modal-head,.modal-foot { display:flex; align-items:center; justify-content:space-between; gap:10px; padding:14px 18px; border-bottom:1px solid var(--line); }
    .modal-head h2 { margin:0; font-size:17px; }
    .modal-body { padding:4px 18px 20px; }
    .modal-foot { justify-content:flex-end; border:0; border-top:1px solid var(--line); }
    .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:0 14px; }
    .close { width:34px; height:34px; padding:0; border:0; background:transparent; font-size:22px; }
    .muted { color:var(--muted); }
    @media (max-width:760px) {
      header { padding:0 14px; }
      main { padding:16px 12px; }
      .toolbar { align-items:flex-start; }
      .stats { grid-template-columns:1fr 1fr; }
      .stat:nth-child(2) { border-right:0; }
      .stat:nth-child(-n+2) { border-bottom:1px solid var(--line); }
      .table-wrap { overflow:auto; }
      table { min-width:760px; }
    }
    @media (max-width:480px) { .grid2 { grid-template-columns:1fr; } .toolbar { display:block; } .actions { margin-top:12px; } }
  </style>
</head>
<body>
  <section id="login" class="login">
    <form id="loginForm" class="login-box">
      <div class="brand"><span class="mark">I</span><span>Incus 中文管理面板</span></div>
      <h1>管理员登录</h1>
      <p>登录后管理本机上的容器与虚拟机。</p>
      <label for="username">用户名</label><input id="username" autocomplete="username" required>
      <label for="password">密码</label><input id="password" type="password" autocomplete="current-password" required>
      <button class="btn primary" type="submit">登录</button>
      <div id="loginError" class="error"></div>
    </form>
  </section>

  <section id="app" class="hidden">
    <header><div class="brand"><span class="mark">I</span><span>Incus 中文管理面板</span></div><button id="logout" class="btn small">退出</button></header>
    <main>
      <div class="toolbar"><h1>实例管理</h1><div class="actions"><button id="refresh" class="btn">刷新</button><button id="openCreate" class="btn primary">创建实例</button></div></div>
      <section class="stats">
        <div class="stat"><span>实例总数</span><strong id="total">-</strong></div>
        <div class="stat"><span>正在运行</span><strong id="running">-</strong></div>
        <div class="stat"><span>宿主机内存</span><strong id="memory">-</strong></div>
        <div class="stat"><span>根分区可用</span><strong id="disk">-</strong></div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>容器与虚拟机</h2><span id="updated" class="muted"></span></div>
        <div class="table-wrap"><table><thead><tr><th>名称</th><th>类型</th><th>状态</th><th>IPv4</th><th>CPU</th><th>内存</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table><div id="empty" class="empty hidden">当前还没有实例。</div></div>
      </section>
    </main>
  </section>

  <dialog id="createDialog">
    <form id="createForm">
      <div class="modal-head"><h2>创建实例</h2><button type="button" class="close" id="closeCreate" aria-label="关闭">&times;</button></div>
      <div class="modal-body">
        <label for="name">名称</label><input id="name" pattern="[A-Za-z0-9][A-Za-z0-9-]{0,62}" placeholder="例如 web-01" required>
        <div class="grid2">
          <div><label for="type">类型</label><select id="type"><option value="container">系统容器</option><option value="virtual-machine">虚拟机</option></select></div>
          <div><label for="image">系统镜像</label><select id="image"><option value="images:ubuntu/24.04">Ubuntu 24.04</option><option value="images:debian/12">Debian 12</option><option value="images:alpine/edge">Alpine Edge</option></select></div>
          <div><label for="cpu">CPU 核心</label><input id="cpu" type="number" min="1" max="128" value="1" required></div>
          <div><label for="ram">内存</label><input id="ram" value="512MiB" pattern="[1-9][0-9]*(MiB|GiB)" required></div>
        </div>
        <label for="storage">磁盘上限</label><input id="storage" value="2GiB" pattern="[1-9][0-9]*(MiB|GiB)" required>
        <div id="createError" class="error"></div>
      </div>
      <div class="modal-foot"><button type="button" class="btn" id="cancelCreate">取消</button><button type="submit" class="btn primary" id="createSubmit">创建并启动</button></div>
    </form>
  </dialog>
  <div id="toast" class="toast hidden"></div>
  <script>
    let csrf = '';
    const $ = (id) => document.getElementById(id);
    const apiBase = location.pathname === '/' ? '' : location.pathname.replace(/\/$/, '');
    async function api(path, options={}) {
      options.headers = {'Content-Type':'application/json', ...(options.headers||{})};
      if (csrf) options.headers['X-CSRF-Token'] = csrf;
      const response = await fetch(apiBase + path, options);
      const data = await response.json().catch(()=>({error:'服务器返回了无效响应'}));
      if (response.status === 401) showLogin();
      if (!response.ok) throw new Error(data.error || '请求失败');
      return data;
    }
    function showLogin() { $('app').classList.add('hidden'); $('login').classList.remove('hidden'); }
    function showApp() { $('login').classList.add('hidden'); $('app').classList.remove('hidden'); }
    function toast(message) { $('toast').textContent=message; $('toast').classList.remove('hidden'); setTimeout(()=>$('toast').classList.add('hidden'),3500); }
    function esc(value) { return String(value??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
    async function load() {
      try {
        const data=await api('/api/instances'); csrf=data.csrf; showApp();
        $('total').textContent=data.instances.length;
        $('running').textContent=data.instances.filter(x=>x.status==='Running').length;
        $('memory').textContent=data.host.memory;
        $('disk').textContent=data.host.disk;
        $('updated').textContent='更新于 '+new Date().toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});
        $('empty').classList.toggle('hidden',data.instances.length!==0);
        $('rows').innerHTML=data.instances.map(x=>`<tr><td><strong>${esc(x.name)}</strong></td><td>${x.type==='virtual-machine'?'虚拟机':'系统容器'}</td><td><span class="status ${x.status.toLowerCase()}"><span class="dot"></span>${x.status==='Running'?'运行中':x.status==='Stopped'?'已停止':esc(x.status)}</span></td><td>${esc(x.ipv4||'-')}</td><td>${esc(x.cpu||'-')}</td><td>${esc(x.memory||'-')}</td><td><div class="row-actions">${x.status==='Running'?`<button class="btn small" onclick="act('${esc(x.name)}','stop')">停止</button><button class="btn small" onclick="act('${esc(x.name)}','restart')">重启</button>`:`<button class="btn small" onclick="act('${esc(x.name)}','start')">启动</button>`}<button class="btn small danger" onclick="removeInstance('${esc(x.name)}')">删除</button></div></td></tr>`).join('');
      } catch(e) { if (!$('app').classList.contains('hidden')) toast(e.message); }
    }
    async function act(name, action) {
      try { await api(`/api/instances/${encodeURIComponent(name)}/action`,{method:'POST',body:JSON.stringify({action})}); toast('操作已完成'); await load(); } catch(e) { toast(e.message); }
    }
    async function removeInstance(name) {
      if (!confirm(`确定永久删除实例“${name}”及其数据吗？`)) return;
      try { await api(`/api/instances/${encodeURIComponent(name)}`,{method:'DELETE'}); toast('实例已删除'); await load(); } catch(e) { toast(e.message); }
    }
    $('loginForm').addEventListener('submit',async e=>{ e.preventDefault(); $('loginError').textContent=''; try { const d=await api('/api/login',{method:'POST',body:JSON.stringify({username:$('username').value,password:$('password').value})}); csrf=d.csrf; showApp(); await load(); } catch(err) { $('loginError').textContent=err.message; } });
    $('logout').onclick=async()=>{ try{await api('/api/logout',{method:'POST',body:'{}'});}finally{csrf='';showLogin();} };
    $('refresh').onclick=load;
    $('openCreate').onclick=()=>{$('createError').textContent='';$('createDialog').showModal();};
    $('closeCreate').onclick=$('cancelCreate').onclick=()=>$('createDialog').close();
    $('createForm').addEventListener('submit',async e=>{ e.preventDefault(); const button=$('createSubmit'); button.disabled=true; button.textContent='正在创建...'; $('createError').textContent=''; try { await api('/api/instances',{method:'POST',body:JSON.stringify({name:$('name').value,type:$('type').value,image:$('image').value,cpu:$('cpu').value,memory:$('ram').value,disk:$('storage').value})}); $('createDialog').close(); $('createForm').reset(); toast('实例创建成功'); await load(); } catch(err) { $('createError').textContent=err.message; } finally { button.disabled=false; button.textContent='创建并启动'; } });
    load();
  </script>
</body>
</html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "IncusCNPanel/0.1"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'")
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
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 16384:
            raise ValueError("请求内容长度无效")
        return json.loads(self.rfile.read(length))

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
        if path == "/api/instances":
            auth = self.require_auth()
            if not auth:
                return
            try:
                raw = json.loads(run_incus("list", "--format=json"))
                instances = []
                for item in raw:
                    state = item.get("state") or {}
                    addresses = state.get("network") or {}
                    ipv4 = ""
                    for interface in addresses.values():
                        for address in interface.get("addresses", []):
                            if address.get("family") == "inet" and address.get("scope") == "global":
                                ipv4 = address.get("address", "")
                                break
                        if ipv4:
                            break
                    config = item.get("expanded_config") or item.get("config") or {}
                    instances.append({
                        "name": item.get("name"),
                        "type": item.get("type"),
                        "status": item.get("status"),
                        "ipv4": ipv4,
                        "cpu": config.get("limits.cpu", "不限"),
                        "memory": config.get("limits.memory", "不限"),
                    })
                memory_total = 0
                with open("/proc/meminfo", encoding="ascii") as meminfo:
                    for line in meminfo:
                        if line.startswith("MemTotal:"):
                            memory_total = int(line.split()[1])
                            break
                disk = os.statvfs("/")
                free_gib = disk.f_bavail * disk.f_frsize / 1024**3
                self.send_json(200, {
                    "instances": instances,
                    "host": {"memory": f"{memory_total / 1024**2:.1f} GiB", "disk": f"{free_gib:.1f} GiB"},
                    "csrf": auth[1]["csrf"],
                })
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
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
        if path == "/api/instances":
            try:
                data = self.read_json()
                name = str(data.get("name", ""))
                kind = str(data.get("type", ""))
                image = str(data.get("image", ""))
                cpu = str(data.get("cpu", ""))
                memory = str(data.get("memory", ""))
                disk = str(data.get("disk", ""))
                if not NAME_RE.fullmatch(name):
                    raise ValueError("名称只能包含字母、数字和连字符，最长 63 位")
                if kind not in {"container", "virtual-machine"}:
                    raise ValueError("实例类型无效")
                if image not in {"images:ubuntu/24.04", "images:debian/12", "images:alpine/edge"}:
                    raise ValueError("系统镜像无效")
                if not cpu.isdigit() or not 1 <= int(cpu) <= 128:
                    raise ValueError("CPU 核心数无效")
                if not SIZE_RE.fullmatch(memory) or not SIZE_RE.fullmatch(disk):
                    raise ValueError("内存或磁盘格式无效")
                init_args = ["init", image, name]
                if kind == "virtual-machine":
                    init_args.append("--vm")
                init_args.extend(["-c", f"limits.cpu={cpu}", "-c", f"limits.memory={memory}"])
                run_incus(*init_args, timeout=600)
                try:
                    run_incus("config", "device", "override", name, "root", f"size={disk}")
                    run_incus("start", name, timeout=180)
                except Exception:
                    run_incus("delete", name, "--force")
                    raise
                self.send_json(201, {"ok": True})
            except subprocess.TimeoutExpired:
                self.send_json(504, {"error": "镜像下载或实例创建超时"})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return

        match = re.fullmatch(r"/api/instances/([^/]+)/action", path)
        if match:
            name = match.group(1)
            if not NAME_RE.fullmatch(name):
                self.send_json(400, {"error": "实例名称无效"})
                return
            try:
                action = str(self.read_json().get("action", ""))
                if action not in {"start", "stop", "restart"}:
                    raise ValueError("不支持的操作")
                args = [action, name]
                if action in {"stop", "restart"}:
                    args.append("--force")
                run_incus(*args, timeout=180)
                self.send_json(200, {"ok": True})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        self.send_json(404, {"error": "接口不存在"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        auth = self.require_auth(csrf=True)
        if not auth:
            return
        match = re.fullmatch(r"/api/instances/([^/]+)", path)
        if not match or not NAME_RE.fullmatch(match.group(1)):
            self.send_json(404, {"error": "实例不存在"})
            return
        try:
            run_incus("delete", match.group(1), "--force", timeout=180)
            self.send_json(200, {"ok": True})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})


def main():
    if not PASSWORD_SALT or not PASSWORD_HASH:
        raise SystemExit("缺少面板密码配置")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Incus 中文管理面板正在监听 https://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
