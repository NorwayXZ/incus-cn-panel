#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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
REMOTE_CONFIG_LOCK = threading.Lock()
SESSION_TTL = 12 * 60 * 60
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")
SIZE_RE = re.compile(r"^[1-9][0-9]*(MiB|GiB)$")
ALLOWED_IMAGES = {
    "images:ubuntu/24.04",
    "images:debian/12",
    "images:alpine/edge",
}


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
        instances.append({
            "node": node,
            "name": item.get("name", ""),
            "type": item.get("type", "container"),
            "status": item.get("status", "Unknown"),
            "ipv4": ipv4,
            "cpu": config.get("limits.cpu", "不限"),
            "memory": config.get("limits.memory", "不限"),
        })
    return instances


def inspect_node(name, remote):
    address = (remote.get("Addrs") or [""])[0]
    try:
        resources = json.loads(run_incus("query", f"{name}:/1.0/resources", timeout=15))
        raw_instances = json.loads(run_incus("list", f"{name}:", "--format=json", timeout=20))
        instances = parse_instances(name, raw_instances)
        return {
            "name": name,
            "address": address,
            "status": "online",
            "cpu": int((resources.get("cpu") or {}).get("total", 0)),
            "memory": int((resources.get("memory") or {}).get("total", 0)),
            "instance_count": len(instances),
            "instances": instances,
            "error": "",
        }
    except Exception as exc:
        return {
            "name": name,
            "address": address,
            "status": "offline",
            "cpu": 0,
            "memory": 0,
            "instance_count": 0,
            "instances": [],
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


HTML = r'''<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Incus 中文集群面板</title>
  <style>
    :root { --ink:#182026; --muted:#647078; --line:#d9dee2; --bg:#f5f7f8; --paper:#fff; --green:#0b7a53; --green2:#075e41; --red:#b42318; --nav:#17252d; }
    * { box-sizing:border-box; }
    body { margin:0; font:14px/1.5 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif; color:var(--ink); background:var(--bg); }
    button,input,select,textarea { font:inherit; }
    button { cursor:pointer; }
    .hidden { display:none!important; }
    .login { min-height:100vh; display:grid; place-items:center; padding:24px; background:#edf2f0; }
    .login-box { width:min(390px,100%); background:var(--paper); border:1px solid var(--line); border-top:4px solid var(--green); border-radius:6px; padding:30px; box-shadow:0 16px 45px rgba(23,37,45,.11); }
    .brand { display:flex; align-items:center; gap:11px; font-size:18px; font-weight:700; }
    .mark { width:30px; height:30px; display:grid; place-items:center; color:#fff; background:var(--green); border-radius:5px; font-weight:800; }
    .login h1 { margin:28px 0 4px; font-size:22px; }
    .login p { margin:0 0 22px; color:var(--muted); }
    label { display:block; margin:14px 0 6px; font-weight:600; }
    input,select,textarea { width:100%; min-height:40px; padding:8px 10px; color:var(--ink); background:#fff; border:1px solid #b8c1c7; border-radius:4px; outline:none; }
    textarea { min-height:92px; resize:vertical; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; }
    input:focus,select:focus,textarea:focus { border-color:var(--green); box-shadow:0 0 0 2px rgba(11,122,83,.13); }
    .btn { min-height:38px; padding:7px 13px; border:1px solid #aeb8be; border-radius:4px; color:var(--ink); background:#fff; font-weight:600; }
    .btn:hover { background:#f1f4f5; }
    .btn.primary { color:#fff; border-color:var(--green); background:var(--green); }
    .btn.primary:hover { background:var(--green2); }
    .btn.danger { color:var(--red); border-color:#e4b5af; }
    .btn.small { min-height:30px; padding:4px 9px; font-size:13px; }
    .btn:disabled { cursor:not-allowed; opacity:.55; }
    .login .btn { width:100%; margin-top:22px; }
    .error { color:var(--red); margin-top:12px; min-height:21px; white-space:pre-wrap; }
    header { height:58px; display:flex; align-items:center; justify-content:space-between; padding:0 24px; color:#fff; background:var(--nav); }
    header .mark { background:#10a56f; }
    header .btn { color:#fff; border-color:#53636b; background:transparent; }
    main { width:min(1240px,100%); margin:0 auto; padding:24px; }
    .toolbar { display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:20px; }
    .toolbar h1 { margin:0; font-size:22px; }
    .actions { display:flex; flex-wrap:wrap; gap:8px; }
    .stats { display:grid; grid-template-columns:repeat(4,1fr); border:1px solid var(--line); border-radius:6px; background:var(--paper); margin-bottom:20px; overflow:hidden; }
    .stat { min-height:90px; padding:16px 18px; border-right:1px solid var(--line); }
    .stat:last-child { border-right:0; }
    .stat span { display:block; color:var(--muted); }
    .stat strong { display:block; margin-top:5px; font-size:22px; }
    .panel { border:1px solid var(--line); border-radius:6px; background:var(--paper); overflow:hidden; margin-bottom:20px; }
    .panel-head { display:flex; justify-content:space-between; align-items:center; min-height:54px; padding:10px 16px; border-bottom:1px solid var(--line); }
    .panel-head h2 { margin:0; font-size:16px; }
    table { width:100%; border-collapse:collapse; }
    th,td { padding:12px 14px; text-align:left; border-bottom:1px solid #e6e9eb; vertical-align:middle; }
    th { color:#526069; background:#f8f9fa; font-size:12px; font-weight:700; }
    tr:last-child td { border-bottom:0; }
    .status { display:inline-flex; align-items:center; gap:6px; font-weight:600; }
    .dot { width:8px; height:8px; border-radius:50%; background:#8b969d; }
    .online .dot,.running .dot { background:#0e9f6e; }
    .offline .dot,.stopped .dot { background:#8b969d; }
    .row-actions { display:flex; flex-wrap:wrap; gap:6px; }
    .empty { padding:38px 20px; text-align:center; color:var(--muted); }
    .toast { position:fixed; right:20px; bottom:20px; z-index:10; max-width:min(440px,calc(100vw - 40px)); padding:12px 16px; color:#fff; background:#26343c; border-radius:5px; box-shadow:0 8px 24px rgba(0,0,0,.18); }
    dialog { width:min(540px,calc(100% - 32px)); padding:0; border:0; border-radius:6px; box-shadow:0 24px 70px rgba(0,0,0,.25); }
    dialog::backdrop { background:rgba(17,27,32,.52); }
    .modal-head,.modal-foot { display:flex; align-items:center; justify-content:space-between; gap:10px; padding:14px 18px; border-bottom:1px solid var(--line); }
    .modal-head h2 { margin:0; font-size:17px; }
    .modal-body { padding:4px 18px 20px; }
    .modal-foot { justify-content:flex-end; border:0; border-top:1px solid var(--line); }
    .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:0 14px; }
    .close { width:34px; height:34px; padding:0; border:0; background:transparent; font-size:22px; }
    .muted { color:var(--muted); }
    .mono { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; }
    @media (max-width:760px) {
      header { padding:0 14px; }
      main { padding:16px 12px; }
      .toolbar { align-items:flex-start; }
      .stats { grid-template-columns:1fr 1fr; }
      .stat:nth-child(2) { border-right:0; }
      .stat:nth-child(-n+2) { border-bottom:1px solid var(--line); }
      .table-wrap { overflow:auto; }
      table { min-width:880px; }
    }
    @media (max-width:480px) { .grid2 { grid-template-columns:1fr; } .toolbar { display:block; } .actions { margin-top:12px; } }
  </style>
</head>
<body>
  <section id="login" class="login">
    <form id="loginForm" class="login-box">
      <div class="brand"><span class="mark">I</span><span>Incus 中文集群面板</span></div>
      <h1>管理员登录</h1>
      <p>集中管理远程计算节点上的容器与虚拟机。</p>
      <label for="username">用户名</label><input id="username" autocomplete="username" required>
      <label for="password">密码</label><input id="password" type="password" autocomplete="current-password" required>
      <button class="btn primary" type="submit">登录</button>
      <div id="loginError" class="error"></div>
    </form>
  </section>

  <section id="app" class="hidden">
    <header><div class="brand"><span class="mark">I</span><span>Incus 中文集群面板</span></div><button id="logout" class="btn small">退出</button></header>
    <main>
      <div class="toolbar"><h1>集群管理</h1><div class="actions"><button id="refresh" class="btn">刷新</button><button id="openNode" class="btn">添加节点</button><button id="openCreate" class="btn primary">创建实例</button></div></div>
      <section class="stats">
        <div class="stat"><span>计算节点</span><strong id="nodeTotal">-</strong></div>
        <div class="stat"><span>在线节点</span><strong id="nodeOnline">-</strong></div>
        <div class="stat"><span>实例总数</span><strong id="total">-</strong></div>
        <div class="stat"><span>正在运行</span><strong id="running">-</strong></div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>计算节点</h2><span id="updated" class="muted"></span></div>
        <div class="table-wrap"><table><thead><tr><th>节点</th><th>管理地址</th><th>状态</th><th>CPU</th><th>内存</th><th>实例</th><th>操作</th></tr></thead><tbody id="nodeRows"></tbody></table><div id="nodeEmpty" class="empty hidden">尚未接入计算节点。</div></div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>容器与虚拟机</h2></div>
        <div class="table-wrap"><table><thead><tr><th>节点</th><th>名称</th><th>类型</th><th>状态</th><th>IPv4</th><th>CPU</th><th>内存</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table><div id="empty" class="empty hidden">当前还没有实例。</div></div>
      </section>
    </main>
  </section>

  <dialog id="nodeDialog">
    <form id="nodeForm">
      <div class="modal-head"><h2>添加计算节点</h2><button type="button" class="close" id="closeNode" aria-label="关闭">&times;</button></div>
      <div class="modal-body">
        <label for="nodeName">节点名称</label><input id="nodeName" pattern="[A-Za-z0-9][A-Za-z0-9-]{0,62}" placeholder="例如 node-hk-01" required>
        <label for="nodeAddress">管理地址</label><input id="nodeAddress" placeholder="例如 203.0.113.10:8443" required>
        <label for="nodeToken">一次性 Trust Token</label><textarea id="nodeToken" spellcheck="false" required></textarea>
        <div id="nodeError" class="error"></div>
      </div>
      <div class="modal-foot"><button type="button" class="btn" id="cancelNode">取消</button><button type="submit" class="btn primary" id="nodeSubmit">验证并接入</button></div>
    </form>
  </dialog>

  <dialog id="createDialog">
    <form id="createForm">
      <div class="modal-head"><h2>创建实例</h2><button type="button" class="close" id="closeCreate" aria-label="关闭">&times;</button></div>
      <div class="modal-body">
        <label for="targetNode">计算节点</label><select id="targetNode" required></select>
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
    let currentNodes = [];
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
    function formatBytes(value) { return value>=1073741824?(value/1073741824).toFixed(1)+' GiB':Math.round(value/1048576)+' MiB'; }
    async function load() {
      try {
        const data=await api('/api/overview'); csrf=data.csrf; showApp(); currentNodes=data.nodes;
        $('nodeTotal').textContent=data.nodes.length;
        $('nodeOnline').textContent=data.nodes.filter(x=>x.status==='online').length;
        $('total').textContent=data.instances.length;
        $('running').textContent=data.instances.filter(x=>x.status==='Running').length;
        $('updated').textContent='更新于 '+new Date().toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});
        $('nodeEmpty').classList.toggle('hidden',data.nodes.length!==0);
        $('empty').classList.toggle('hidden',data.instances.length!==0);
        $('nodeRows').innerHTML=data.nodes.map(x=>`<tr><td><strong>${esc(x.name)}</strong></td><td class="mono">${esc(x.address)}</td><td><span class="status ${x.status}"><span class="dot"></span>${x.status==='online'?'在线':'离线'}</span></td><td>${x.status==='online'?esc(x.cpu):'-'}</td><td>${x.status==='online'?formatBytes(x.memory):'-'}</td><td>${esc(x.instance_count)}</td><td><button class="btn small danger" onclick="removeNode('${esc(x.name)}')">移除</button></td></tr>`).join('');
        $('rows').innerHTML=data.instances.map(x=>`<tr><td>${esc(x.node)}</td><td><strong>${esc(x.name)}</strong></td><td>${x.type==='virtual-machine'?'虚拟机':'系统容器'}</td><td><span class="status ${x.status.toLowerCase()}"><span class="dot"></span>${x.status==='Running'?'运行中':x.status==='Stopped'?'已停止':esc(x.status)}</span></td><td>${esc(x.ipv4||'-')}</td><td>${esc(x.cpu||'-')}</td><td>${esc(x.memory||'-')}</td><td><div class="row-actions">${x.status==='Running'?`<button class="btn small" onclick="act('${esc(x.node)}','${esc(x.name)}','stop')">停止</button><button class="btn small" onclick="act('${esc(x.node)}','${esc(x.name)}','restart')">重启</button>`:`<button class="btn small" onclick="act('${esc(x.node)}','${esc(x.name)}','start')">启动</button>`}<button class="btn small danger" onclick="removeInstance('${esc(x.node)}','${esc(x.name)}')">删除</button></div></td></tr>`).join('');
        const online=data.nodes.filter(x=>x.status==='online');
        $('targetNode').innerHTML=online.map(x=>`<option value="${esc(x.name)}">${esc(x.name)}</option>`).join('');
        $('openCreate').disabled=online.length===0;
      } catch(e) { if (!$('app').classList.contains('hidden')) toast(e.message); }
    }
    async function act(node,name,action) {
      try { await api(`/api/nodes/${encodeURIComponent(node)}/instances/${encodeURIComponent(name)}/action`,{method:'POST',body:JSON.stringify({action})}); toast('操作已完成'); await load(); } catch(e) { toast(e.message); }
    }
    async function removeInstance(node,name) {
      if (!confirm(`确定永久删除 ${node} 上的实例“${name}”及其数据吗？`)) return;
      try { await api(`/api/nodes/${encodeURIComponent(node)}/instances/${encodeURIComponent(name)}`,{method:'DELETE'}); toast('实例已删除'); await load(); } catch(e) { toast(e.message); }
    }
    async function removeNode(node) {
      if (!confirm(`确定从面板移除节点“${node}”吗？节点上的实例不会被删除。`)) return;
      try { await api(`/api/nodes/${encodeURIComponent(node)}`,{method:'DELETE'}); toast('节点已从面板移除'); await load(); } catch(e) { toast(e.message); }
    }
    $('loginForm').addEventListener('submit',async e=>{ e.preventDefault(); $('loginError').textContent=''; try { const d=await api('/api/login',{method:'POST',body:JSON.stringify({username:$('username').value,password:$('password').value})}); csrf=d.csrf; showApp(); await load(); } catch(err) { $('loginError').textContent=err.message; } });
    $('logout').onclick=async()=>{ try{await api('/api/logout',{method:'POST',body:'{}'});}finally{csrf='';showLogin();} };
    $('refresh').onclick=load;
    $('openNode').onclick=()=>{$('nodeError').textContent='';$('nodeDialog').showModal();};
    $('closeNode').onclick=$('cancelNode').onclick=()=>$('nodeDialog').close();
    $('nodeForm').addEventListener('submit',async e=>{ e.preventDefault(); const button=$('nodeSubmit'); button.disabled=true; button.textContent='正在验证...'; $('nodeError').textContent=''; try { await api('/api/nodes',{method:'POST',body:JSON.stringify({name:$('nodeName').value,address:$('nodeAddress').value,token:$('nodeToken').value})}); $('nodeDialog').close(); $('nodeForm').reset(); toast('计算节点接入成功'); await load(); } catch(err) { $('nodeError').textContent=err.message; } finally { button.disabled=false; button.textContent='验证并接入'; } });
    $('openCreate').onclick=()=>{$('createError').textContent='';$('createDialog').showModal();};
    $('closeCreate').onclick=$('cancelCreate').onclick=()=>$('createDialog').close();
    $('createForm').addEventListener('submit',async e=>{ e.preventDefault(); const button=$('createSubmit'); button.disabled=true; button.textContent='正在创建...'; $('createError').textContent=''; try { await api('/api/instances',{method:'POST',body:JSON.stringify({node:$('targetNode').value,name:$('name').value,type:$('type').value,image:$('image').value,cpu:$('cpu').value,memory:$('ram').value,disk:$('storage').value})}); $('createDialog').close(); $('createForm').reset(); toast('实例创建成功'); await load(); } catch(err) { $('createError').textContent=err.message; } finally { button.disabled=false; button.textContent='创建并启动'; } });
    load();
  </script>
</body>
</html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "IncusCNPanel/0.2"

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
        if path == "/api/overview":
            auth = self.require_auth()
            if not auth:
                return
            try:
                nodes, instances = overview()
                self.send_json(200, {"nodes": nodes, "instances": instances, "csrf": auth[1]["csrf"]})
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
        if path == "/api/nodes":
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
                self.send_json(201, {"ok": True})
            except subprocess.TimeoutExpired:
                self.send_json(504, {"error": "连接节点超时，请检查地址和防火墙"})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/instances":
            try:
                data = self.read_json()
                node = require_node(str(data.get("node", "")))
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
                if image not in ALLOWED_IMAGES:
                    raise ValueError("系统镜像无效")
                if not cpu.isdigit() or not 1 <= int(cpu) <= 128:
                    raise ValueError("CPU 核心数无效")
                if not SIZE_RE.fullmatch(memory) or not SIZE_RE.fullmatch(disk):
                    raise ValueError("内存或磁盘格式无效")
                ref = f"{node}:{name}"
                init_args = ["init", image, ref]
                if kind == "virtual-machine":
                    init_args.append("--vm")
                init_args.extend(["-c", f"limits.cpu={cpu}", "-c", f"limits.memory={memory}"])
                run_incus(*init_args, timeout=600)
                try:
                    run_incus("config", "device", "override", ref, "root", f"size={disk}")
                    run_incus("start", ref, timeout=180)
                except Exception:
                    run_incus("delete", ref, "--force")
                    raise
                self.send_json(201, {"ok": True})
            except subprocess.TimeoutExpired:
                self.send_json(504, {"error": "镜像下载或实例创建超时"})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return

        match = re.fullmatch(r"/api/nodes/([^/]+)/instances/([^/]+)/action", path)
        if match:
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
        node_match = re.fullmatch(r"/api/nodes/([^/]+)", path)
        if node_match:
            try:
                node = require_node(node_match.group(1))
                with REMOTE_CONFIG_LOCK:
                    run_incus("remote", "remove", node, timeout=20)
                self.send_json(200, {"ok": True})
            except Exception as exc:
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
                self.send_json(200, {"ok": True})
            except Exception as exc:
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
