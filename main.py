"""
File Manager Pro — Auth Server
Python 3.11+ | FastAPI | SQLite | JWT
"""

import hashlib, hmac, os, secrets, sqlite3, time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# ── 配置 ────────────────────────────────────────────────────────────────────
SECRET_KEY   = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "admin123")   # 首次部署务必修改
DB_PATH      = os.environ.get("DB_PATH", "users.db")
TOKEN_EXPIRE = int(os.environ.get("TOKEN_EXPIRE_DAYS", "30")) * 86400

# ── 数据库 ───────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            pw_hash     TEXT    NOT NULL,
            email       TEXT    DEFAULT '',
            role        TEXT    DEFAULT 'user',
            banned      INTEGER DEFAULT 0,
            created_at  INTEGER NOT NULL,
            last_login  INTEGER,
            login_count INTEGER DEFAULT 0,
            last_ip     TEXT    DEFAULT '',
            device_info TEXT    DEFAULT '{}'
        );
        -- migrate: add column if upgrading from old schema
        SELECT 1;
        CREATE TABLE IF NOT EXISTS login_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            ip         TEXT,
            success    INTEGER,
            ts         INTEGER NOT NULL
        );
    """)
    # Migration: add device_info column if it doesn't exist yet
    try:
        db.execute("ALTER TABLE users ADD COLUMN device_info TEXT DEFAULT '{}'")
        db.commit()
    except Exception:
        pass  # Column already exists
    db.commit(); db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="File Manager Auth", lifespan=lifespan)

# ── 工具函数 ─────────────────────────────────────────────────────────────────
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def make_token(username: str, role: str) -> str:
    payload = {
        "sub":  username,
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + TOKEN_EXPIRE,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token 已过期")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Token 无效")

security = HTTPBearer(auto_error=False)

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not creds:
        raise HTTPException(401, "未提供认证")
    return verify_token(creds.credentials)

def require_admin(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not creds:
        raise HTTPException(401, "未提供认证")
    payload = verify_token(creds.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(403, "需要管理员权限")
    return payload

def get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "")

def log_login(db, username: str, ip: str, success: bool):
    db.execute("INSERT INTO login_logs (username,ip,success,ts) VALUES (?,?,?,?)",
               (username, ip, int(success), int(time.time())))
    db.commit()

def fmt_time(ts: Optional[int]) -> str:
    if not ts: return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# ── Pydantic 模型 ─────────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    username: str
    password: str
    device:   dict = {}

class RegisterReq(BaseModel):
    username: str
    password: str
    email:    str = ""
    device:   dict = {}

class AdminLoginReq(BaseModel):
    password: str

class UpdateUserReq(BaseModel):
    email:  Optional[str]  = None
    role:   Optional[str]  = None
    banned: Optional[bool] = None

class ChangePasswordReq(BaseModel):
    old_password: str
    new_password: str

# ── 认证接口 ─────────────────────────────────────────────────────────────────
@app.post("/auth/register")
async def register(req: RegisterReq, request: Request):
    if len(req.username) < 2:
        raise HTTPException(400, "用户名至少2个字符")
    if len(req.password) < 4:
        raise HTTPException(400, "密码至少4个字符")
    db = get_db()
    try:
        import json as _json
        db.execute(
            "INSERT INTO users (username,pw_hash,email,created_at,device_info) VALUES (?,?,?,?,?)",
            (req.username.strip(), hash_pw(req.password), req.email, int(time.time()), _json.dumps(req.device, ensure_ascii=False))
        )
        db.commit()
        token = make_token(req.username, "user")
        return {"token": token, "username": req.username, "role": "user"}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "用户名已存在")
    finally:
        db.close()

@app.post("/auth/login")
async def login(req: LoginReq, request: Request):
    ip = get_ip(request)
    db = get_db()
    try:
        row = db.execute("SELECT * FROM users WHERE username=?", (req.username.strip(),)).fetchone()
        if not row or row["pw_hash"] != hash_pw(req.password):
            log_login(db, req.username, ip, False)
            raise HTTPException(401, "账户名或密码错误")
        if row["banned"]:
            log_login(db, req.username, ip, False)
            raise HTTPException(403, "账户已被封禁")
        # 更新登录信息
        import json as _json2
        db.execute(
            "UPDATE users SET last_login=?, login_count=login_count+1, last_ip=?, device_info=? WHERE username=?",
            (int(time.time()), ip, _json2.dumps(req.device, ensure_ascii=False), req.username)
        )
        log_login(db, req.username, ip, True)
        db.commit()
        token = make_token(req.username, row["role"])
        return {"token": token, "username": req.username, "role": row["role"]}
    finally:
        db.close()

@app.post("/auth/change-password")
async def change_password(req: ChangePasswordReq, user=Depends(get_current_user)):
    db = get_db()
    try:
        row = db.execute("SELECT pw_hash FROM users WHERE username=?", (user["sub"],)).fetchone()
        if not row or row["pw_hash"] != hash_pw(req.old_password):
            raise HTTPException(400, "当前密码错误")
        if len(req.new_password) < 4:
            raise HTTPException(400, "新密码至少4个字符")
        db.execute("UPDATE users SET pw_hash=? WHERE username=?",
                   (hash_pw(req.new_password), user["sub"]))
        db.commit()
        return {"message": "密码已更新"}
    finally:
        db.close()

@app.get("/auth/me")
async def me(user=Depends(get_current_user)):
    db = get_db()
    try:
        row = db.execute("SELECT username,email,role,created_at,last_login,login_count FROM users WHERE username=?",
                         (user["sub"],)).fetchone()
        if not row: raise HTTPException(404, "用户不存在")
        return dict(row)
    finally:
        db.close()

# ── 管理员接口 ────────────────────────────────────────────────────────────────
@app.post("/admin/login")
async def admin_login(req: AdminLoginReq):
    if not hmac.compare_digest(req.password, ADMIN_PASS):
        raise HTTPException(401, "管理员密码错误")
    token = make_token("__admin__", "admin")
    return {"token": token}

@app.get("/admin/users")
async def list_users(page: int = 1, q: str = "", _=Depends(require_admin)):
    db = get_db()
    try:
        per = 20
        like = f"%{q}%"
        total = db.execute("SELECT COUNT(*) FROM users WHERE username LIKE ? OR email LIKE ?", (like,like)).fetchone()[0]
        rows  = db.execute(
            "SELECT id,username,email,role,banned,created_at,last_login,login_count,last_ip,device_info "
            "FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (like, like, per, (page-1)*per)
        ).fetchall()
        return {"total": total, "page": page, "per": per,
                "users": [dict(r) for r in rows]}
    finally:
        db.close()

@app.patch("/admin/users/{username}")
async def update_user(username: str, req: UpdateUserReq, _=Depends(require_admin)):
    db = get_db()
    try:
        fields, vals = [], []
        if req.email  is not None: fields.append("email=?");  vals.append(req.email)
        if req.role   is not None: fields.append("role=?");   vals.append(req.role)
        if req.banned is not None: fields.append("banned=?"); vals.append(int(req.banned))
        if not fields: raise HTTPException(400, "无更新内容")
        vals.append(username)
        db.execute(f"UPDATE users SET {','.join(fields)} WHERE username=?", vals)
        db.commit()
        return {"message": "已更新"}
    finally:
        db.close()

@app.delete("/admin/users/{username}")
async def delete_user(username: str, _=Depends(require_admin)):
    db = get_db()
    try:
        db.execute("DELETE FROM users WHERE username=?", (username,))
        db.commit()
        return {"message": "已删除"}
    finally:
        db.close()

@app.get("/admin/logs")
async def get_logs(page: int = 1, username: str = "", _=Depends(require_admin)):
    db = get_db()
    try:
        per  = 50
        like = f"%{username}%"
        total = db.execute("SELECT COUNT(*) FROM login_logs WHERE username LIKE ?", (like,)).fetchone()[0]
        rows  = db.execute(
            "SELECT * FROM login_logs WHERE username LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (like, per, (page-1)*per)
        ).fetchall()
        return {"total": total, "logs": [dict(r) for r in rows]}
    finally:
        db.close()

@app.get("/admin/stats")
async def stats(_=Depends(require_admin)):
    db = get_db()
    try:
        total   = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        banned  = db.execute("SELECT COUNT(*) FROM users WHERE banned=1").fetchone()[0]
        admins  = db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        day_ago = int(time.time()) - 86400
        active  = db.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (day_ago,)).fetchone()[0]
        logins_today = db.execute("SELECT COUNT(*) FROM login_logs WHERE ts>? AND success=1", (day_ago,)).fetchone()[0]
        fails_today  = db.execute("SELECT COUNT(*) FROM login_logs WHERE ts>? AND success=0", (day_ago,)).fetchone()[0]
        return {"total": total, "banned": banned, "admins": admins,
                "active_24h": active, "logins_today": logins_today, "fails_today": fails_today}
    finally:
        db.close()

# ── 管理后台网页 ──────────────────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    return HTMLResponse(ADMIN_HTML)

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>File Manager Pro — 管理后台</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1e2130;border:1px solid #2d3148;border-radius:16px;padding:32px;width:360px}
h1{font-size:22px;margin-bottom:4px;color:#fff}
.sub{color:#64748b;font-size:13px;margin-bottom:24px}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:4px;margin-top:14px}
input{width:100%;padding:10px 14px;background:#0f1117;border:1px solid #2d3148;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none}
input:focus{border-color:#6366f1}
.btn{display:block;width:100%;padding:11px;background:#6366f1;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;margin-top:20px;font-weight:600}
.btn:hover{background:#4f46e5}
.err{color:#f87171;font-size:12px;margin-top:8px;min-height:16px}
/* dashboard */
#app{display:none;min-height:100vh}
.topbar{background:#1e2130;border-bottom:1px solid #2d3148;padding:0 24px;height:56px;display:flex;align-items:center;gap:16px}
.topbar h2{font-size:16px;color:#fff;flex:1}
.topbar .logout{font-size:12px;color:#94a3b8;cursor:pointer;padding:6px 12px;border:1px solid #2d3148;border-radius:6px}
.topbar .logout:hover{color:#f87171;border-color:#f87171}
.layout{display:flex;min-height:calc(100vh - 56px)}
.sidebar{width:200px;background:#1e2130;border-right:1px solid #2d3148;padding:16px 0}
.nav-item{padding:10px 20px;font-size:13px;cursor:pointer;color:#94a3b8;display:flex;align-items:center;gap:8px}
.nav-item:hover,.nav-item.active{background:#2d3148;color:#fff}
.content{flex:1;padding:24px;overflow:auto}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.stat{background:#1e2130;border:1px solid #2d3148;border-radius:12px;padding:18px}
.stat .num{font-size:28px;font-weight:700;color:#6366f1}
.stat .lbl{font-size:12px;color:#64748b;margin-top:4px}
.toolbar{display:flex;gap:10px;margin-bottom:16px;align-items:center;flex-wrap:wrap}
.search{flex:1;min-width:180px;padding:8px 12px;background:#0f1117;border:1px solid #2d3148;border-radius:8px;color:#e2e8f0;font-size:13px;outline:none}
.search:focus{border-color:#6366f1}
.sm-btn{padding:7px 14px;background:#2d3148;border:none;border-radius:7px;color:#e2e8f0;font-size:12px;cursor:pointer}
.sm-btn:hover{background:#3d4160}
.sm-btn.danger{background:#7f1d1d;color:#fca5a5}
.sm-btn.danger:hover{background:#991b1b}
.sm-btn.primary{background:#6366f1;color:#fff}
.sm-btn.primary:hover{background:#4f46e5}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;border-bottom:1px solid #2d3148;color:#64748b;font-weight:500}
td{padding:9px 12px;border-bottom:1px solid #1a1f2e;vertical-align:middle}
tr:hover td{background:#1a1f2e}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600}
.badge.admin{background:#312e81;color:#a5b4fc}
.badge.user{background:#1e3a5f;color:#93c5fd}
.badge.banned{background:#7f1d1d;color:#fca5a5}
.page-row{display:flex;gap:8px;align-items:center;margin-top:16px;justify-content:flex-end}
.page-btn{padding:5px 12px;background:#2d3148;border:none;border-radius:6px;color:#e2e8f0;cursor:pointer;font-size:12px}
.page-btn:disabled{opacity:0.4;cursor:default}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:999}
.modal{background:#1e2130;border:1px solid #2d3148;border-radius:14px;padding:28px;width:340px}
.modal h3{margin-bottom:16px;font-size:16px}
.modal .btn-row{display:flex;gap:8px;margin-top:20px;justify-content:flex-end}
.log-row{font-size:12px;padding:6px 0;border-bottom:1px solid #1a1f2e;display:flex;gap:12px;align-items:center}
.log-row .ok{color:#4ade80}.log-row .fail{color:#f87171}
.ts{color:#64748b;font-size:11px;min-width:140px}
.ip-tag{background:#1a1f2e;border-radius:4px;padding:1px 6px;font-family:monospace;font-size:11px}
</style>
</head>
<body>

<!-- 登录 -->
<div class="login-wrap" id="loginWrap">
  <div class="card">
    <h1>🔐 管理后台</h1>
    <p class="sub">File Manager Pro</p>
    <label>管理员密码</label>
    <input type="password" id="adminPw" placeholder="输入管理员密码" onkeydown="if(event.key==='Enter')doLogin()">
    <button class="btn" onclick="doLogin()">登 录</button>
    <div class="err" id="loginErr"></div>
  </div>
</div>

<!-- 主界面 -->
<div id="app">
  <div class="topbar">
    <h2>📊 File Manager Pro — 管理后台</h2>
    <span class="logout" onclick="logout()">退出登录</span>
  </div>
  <div class="layout">
    <div class="sidebar">
      <div class="nav-item active" id="nav-overview" onclick="showTab('overview')">📊 概览</div>
      <div class="nav-item" id="nav-users"    onclick="showTab('users')">👥 用户管理</div>
      <div class="nav-item" id="nav-logs"     onclick="showTab('logs')">📋 登录日志</div>
    </div>
    <div class="content">

      <!-- 概览 -->
      <div id="tab-overview">
        <div class="stats-grid" id="statsGrid"></div>
        <div style="color:#64748b;font-size:13px">最近注册用户</div>
        <table style="margin-top:12px"><thead><tr>
          <th>用户名</th><th>邮箱</th><th>角色</th><th>注册时间</th><th>最后登录</th>
        </tr></thead><tbody id="recentUsers"></tbody></table>
      </div>

      <!-- 用户管理 -->
      <div id="tab-users" style="display:none">
        <div class="toolbar">
          <input class="search" placeholder="搜索用户名/邮箱…" id="userSearch" oninput="debounceSearch()">
          <button class="sm-btn primary" onclick="openAddModal()">+ 添加用户</button>
        </div>
        <table><thead><tr>
          <th>ID</th><th>用户名</th><th>邮箱</th><th>角色</th><th>状态</th>
          <th>登录次数</th><th>最后登录</th><th>最后IP</th><th>操作</th>
        </tr></thead><tbody id="usersBody"></tbody></table>
        <div class="page-row">
          <button class="page-btn" id="prevBtn" onclick="changePage(-1)">← 上页</button>
          <span id="pageInfo" style="font-size:12px;color:#64748b"></span>
          <button class="page-btn" id="nextBtn" onclick="changePage(1)">下页 →</button>
        </div>
      </div>

      <!-- 登录日志 -->
      <div id="tab-logs" style="display:none">
        <div class="toolbar">
          <input class="search" placeholder="按用户名筛选…" id="logSearch" oninput="loadLogs()">
        </div>
        <div id="logsBody"></div>
        <div class="page-row">
          <button class="page-btn" id="logPrev" onclick="changeLogPage(-1)">← 上页</button>
          <span id="logPageInfo" style="font-size:12px;color:#64748b"></span>
          <button class="page-btn" id="logNext" onclick="changeLogPage(1)">下页 →</button>
        </div>
      </div>

    </div>
  </div>
</div>

<!-- 编辑用户 modal -->
<div class="modal-bg" id="editModal" style="display:none" onclick="if(event.target===this)this.style.display='none'">
  <div class="modal">
    <h3>编辑用户：<span id="editUsername"></span></h3>
    <label>邮箱</label><input id="editEmail" placeholder="email">
    <label>角色</label>
    <select id="editRole" style="width:100%;padding:9px;background:#0f1117;border:1px solid #2d3148;border-radius:8px;color:#e2e8f0;margin-top:4px">
      <option value="user">user</option><option value="admin">admin</option>
    </select>
    <label style="display:flex;align-items:center;gap:8px;margin-top:14px;cursor:pointer">
      <input type="checkbox" id="editBanned"> 封禁账户
    </label>
    <div class="btn-row">
      <button class="sm-btn" onclick="document.getElementById('editModal').style.display='none'">取消</button>
      <button class="sm-btn primary" onclick="saveEdit()">保存</button>
    </div>
  </div>
</div>

<!-- 添加用户 modal -->
<div class="modal-bg" id="addModal" style="display:none" onclick="if(event.target===this)this.style.display='none'">
  <div class="modal">
    <h3>添加用户</h3>
    <label>用户名</label><input id="addUser" placeholder="至少2个字符">
    <label>密码</label><input id="addPw" type="password" placeholder="至少4个字符">
    <label>邮箱（可选）</label><input id="addEmail" placeholder="email">
    <div class="err" id="addErr"></div>
    <div class="btn-row">
      <button class="sm-btn" onclick="document.getElementById('addModal').style.display='none'">取消</button>
      <button class="sm-btn primary" onclick="doAddUser()">创建</button>
    </div>
  </div>
</div>

<!-- 设备信息 modal -->
<div class="modal-bg" id="deviceModal" style="display:none" onclick="if(event.target===this)this.style.display='none'">
  <div class="modal" style="width:380px">
    <h3>📱 设备信息：<span id="deviceUsername"></span></h3>
    <div id="deviceBody" style="margin-top:12px;font-size:13px;line-height:2"></div>
    <div class="btn-row" style="margin-top:16px">
      <button class="sm-btn" onclick="document.getElementById('deviceModal').style.display='none'">关闭</button>
    </div>
  </div>
</div>

<script>
let TOKEN = '', curPage = 1, logPage = 1, curTab = 'overview', editingUser = '';
let searchTimer = null;

async function api(method, path, body) {
  const r = await fetch(path, {
    method, headers: {'Content-Type':'application/json', 'Authorization': TOKEN ? `Bearer ${TOKEN}` : ''},
    body: body ? JSON.stringify(body) : undefined
  });
  const d = await r.json().catch(()=>({}));
  if (!r.ok) throw new Error(d.detail || d.message || r.status);
  return d;
}

async function doLogin() {
  const pw = document.getElementById('adminPw').value;
  try {
    const d = await api('POST', '/admin/login', {password: pw});
    TOKEN = d.token;
    document.getElementById('loginWrap').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    showTab('overview');
  } catch(e) {
    document.getElementById('loginErr').textContent = e.message;
  }
}

function logout() {
  TOKEN = ''; location.reload();
}

function showTab(tab) {
  curTab = tab;
  ['overview','users','logs'].forEach(t => {
    document.getElementById('tab-'+t).style.display = t===tab ? '' : 'none';
    document.getElementById('nav-'+t).classList.toggle('active', t===tab);
  });
  if (tab==='overview') loadOverview();
  if (tab==='users')    { curPage=1; loadUsers(); }
  if (tab==='logs')     { logPage=1; loadLogs(); }
}

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts*1000).toLocaleString('zh-CN',{hour12:false});
}

function fmtDevice(raw) {
  if (!raw) return '—';
  try {
    const d = JSON.parse(raw);
    if (!d || Object.keys(d).length === 0) return '—';
    return (d.model || d.os || '未知设备').substring(0, 24);
  } catch(e) { return '—'; }
}

function showDevice(u) {
  document.getElementById('deviceUsername').textContent = u.username;
  let html = '';
  try {
    const d = u.device_info ? JSON.parse(u.device_info) : {};
    const fmtBytes = b => b > 0 ? (b >= 1073741824 ? (b/1073741824).toFixed(1)+'GB' : (b/1048576).toFixed(0)+'MB') : '—';
    const rows = [
      ['操作系统',   d.os],
      ['设备型号',   d.model],
      ['CPU',       d.cpu],
      ['CPU核心',   d.cpu_cores ? d.cpu_cores+'核' : null],
      ['CPU架构',   d.cpu_arch],
      ['内存',      fmtBytes(d.ram_total)],
      ['可用存储',  fmtBytes(d.storage_free)],
      ['本地IP',    d.local_ip],
      ['语言区域',  d.locale],
      ['引擎版本',  d.godot_ver ? 'Godot '+d.godot_ver : null],
    ];
    for (const [k, v] of rows) {
      if (v && v !== '—') {
        html += `<div style="display:flex;gap:8px;border-bottom:1px solid #1a1f2e;padding:4px 0">
          <span style="color:#64748b;min-width:80px">${k}</span>
          <span>${v}</span></div>`;
      }
    }
    if (!html) html = '<span style="color:#64748b">暂无设备数据（旧版客户端）</span>';
  } catch(e) {
    html = '<span style="color:#64748b">数据解析失败</span>';
  }
  document.getElementById('deviceBody').innerHTML = html;
  document.getElementById('deviceModal').style.display = 'flex';
}

// ── 概览 ──
async function loadOverview() {
  try {
    const s = await api('GET', '/admin/stats');
    document.getElementById('statsGrid').innerHTML = [
      ['总用户数', s.total, ''],
      ['24h活跃', s.active_24h, ''],
      ['今日登录', s.logins_today, ''],
      ['今日失败', s.fails_today, ''],
      ['管理员', s.admins, ''],
      ['已封禁', s.banned, ''],
    ].map(([l,n])=>`<div class="stat"><div class="num">${n}</div><div class="lbl">${l}</div></div>`).join('');
    const d = await api('GET', '/admin/users?page=1');
    document.getElementById('recentUsers').innerHTML = d.users.map(u=>`
      <tr><td>${u.username}</td><td>${u.email||'—'}</td>
      <td><span class="badge ${u.role}">${u.role}</span></td>
      <td>${fmtTime(u.created_at)}</td><td>${fmtTime(u.last_login)}</td></tr>
    `).join('');
  } catch(e) { console.error(e); }
}

// ── 用户管理 ──
async function loadUsers() {
  const q = document.getElementById('userSearch').value;
  try {
    const d = await api('GET', `/admin/users?page=${curPage}&q=${encodeURIComponent(q)}`);
    const totalPages = Math.ceil(d.total / d.per) || 1;
    document.getElementById('pageInfo').textContent = `第 ${curPage}/${totalPages} 页，共 ${d.total} 用户`;
    document.getElementById('prevBtn').disabled = curPage <= 1;
    document.getElementById('nextBtn').disabled = curPage >= totalPages;
    document.getElementById('usersBody').innerHTML = d.users.map(u => `
      <tr>
        <td style="color:#64748b">${u.id}</td>
        <td><b>${u.username}</b></td>
        <td>${u.email||'—'}</td>
        <td><span class="badge ${u.role}">${u.role}</span></td>
        <td>${u.banned ? '<span class="badge banned">封禁</span>' : '<span style="color:#4ade80">正常</span>'}</td>
        <td>${u.login_count}</td>
        <td>${fmtTime(u.last_login)}</td>
        <td style="font-size:11px;max-width:140px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">
          ${fmtDevice(u.device_info)}
        </td>
        <td><span class="ip-tag">${u.last_ip||'—'}</span></td>
        <td style="white-space:nowrap">
          <button class="sm-btn" onclick="openEdit(${JSON.stringify(u).replace(/"/g,'&quot;')})">编辑</button>
          <button class="sm-btn" onclick="showDevice(${JSON.stringify(u).replace(/"/g,'&quot;')})">📱</button>
          <button class="sm-btn danger" onclick="delUser('${u.username}')">删除</button>
        </td>
      </tr>
    `).join('');
  } catch(e) { console.error(e); }
}

function debounceSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { curPage=1; loadUsers(); }, 300);
}

function changePage(d) { curPage += d; loadUsers(); }

function openEdit(u) {
  editingUser = u.username;
  document.getElementById('editUsername').textContent = u.username;
  document.getElementById('editEmail').value = u.email||'';
  document.getElementById('editRole').value  = u.role;
  document.getElementById('editBanned').checked = !!u.banned;
  document.getElementById('editModal').style.display = 'flex';
}

async function saveEdit() {
  try {
    await api('PATCH', `/admin/users/${editingUser}`, {
      email:  document.getElementById('editEmail').value,
      role:   document.getElementById('editRole').value,
      banned: document.getElementById('editBanned').checked
    });
    document.getElementById('editModal').style.display = 'none';
    loadUsers();
  } catch(e) { alert(e.message); }
}

async function delUser(username) {
  if (!confirm(`确认删除用户 "${username}"？此操作不可撤销`)) return;
  try {
    await api('DELETE', `/admin/users/${username}`);
    loadUsers();
  } catch(e) { alert(e.message); }
}

function openAddModal() {
  ['addUser','addPw','addEmail'].forEach(id => document.getElementById(id).value='');
  document.getElementById('addErr').textContent='';
  document.getElementById('addModal').style.display='flex';
}

async function doAddUser() {
  const u = document.getElementById('addUser').value.trim();
  const p = document.getElementById('addPw').value;
  const e = document.getElementById('addEmail').value.trim();
  try {
    await api('POST', '/auth/register', {username:u, password:p, email:e});
    document.getElementById('addModal').style.display='none';
    loadUsers();
  } catch(err) {
    document.getElementById('addErr').textContent = err.message;
  }
}

// ── 登录日志 ──
async function loadLogs() {
  const q = document.getElementById('logSearch').value;
  try {
    const d = await api('GET', `/admin/logs?page=${logPage}&username=${encodeURIComponent(q)}`);
    const totalPages = Math.ceil(d.total / 50) || 1;
    document.getElementById('logPageInfo').textContent = `第 ${logPage}/${totalPages} 页，共 ${d.total} 条`;
    document.getElementById('logPrev').disabled = logPage <= 1;
    document.getElementById('logNext').disabled = logPage >= totalPages;
    document.getElementById('logsBody').innerHTML = d.logs.map(l => `
      <div class="log-row">
        <span class="ts">${fmtTime(l.ts)}</span>
        <span class="${l.success?'ok':'fail'}">${l.success?'✅ 成功':'❌ 失败'}</span>
        <b>${l.username}</b>
        <span class="ip-tag">${l.ip||'—'}</span>
      </div>
    `).join('') || '<div style="color:#64748b;padding:16px 0">暂无日志</div>';
  } catch(e) { console.error(e); }
}

function changeLogPage(d) { logPage += d; loadLogs(); }
</script>
</body>
</html>
"""
