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
    # Migration: add avatar column
    try:
        db.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''")
        db.commit()
    except Exception:
        pass
    # New tables
    db.executescript("""
        CREATE TABLE IF NOT EXISTS announcements (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            author     TEXT NOT NULL,
            pinned     INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chat_messages (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content  TEXT NOT NULL,
            ts       INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS forum_posts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            author     TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS forum_comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id    INTEGER NOT NULL,
            author     TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cloud_files (
            id         TEXT    PRIMARY KEY,
            owner      TEXT    NOT NULL,
            filename   TEXT    NOT NULL,
            size       INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
    """)
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
    username: Optional[str] = None
    password: str

class UpdateUserReq(BaseModel):
    email:    Optional[str]  = None
    role:     Optional[str]  = None
    banned:   Optional[bool] = None
    password: Optional[str]  = None
    avatar:   Optional[str]  = None   # base64图片或""（清除）

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
    # 方式1：纯密码登录（ADMIN_PASSWORD 环境变量，兼容旧模式）
    if not req.username:
        if not hmac.compare_digest(req.password, ADMIN_PASS):
            raise HTTPException(401, "管理员密码错误")
        token = make_token("__admin__", "admin")
        return {"token": token, "username": "__admin__"}
    # 方式2：用户名+密码登录（数据库中 role=admin 的用户）
    db = get_db()
    try:
        row = db.execute(
            "SELECT username, pw_hash, role, banned FROM users WHERE username=?",
            (req.username,)
        ).fetchone()
        if not row:
            raise HTTPException(401, "用户名或密码错误")
        if row["banned"]:
            raise HTTPException(403, "账号已被封禁")
        if row["role"] != "admin":
            raise HTTPException(403, "该账号没有管理员权限")
        if not hmac.compare_digest(hash_pw(req.password), row["pw_hash"]):
            raise HTTPException(401, "用户名或密码错误")
        token = make_token(row["username"], "admin")
        return {"token": token, "username": row["username"]}
    finally:
        db.close()

@app.get("/admin/users")
async def list_users(page: int = 1, q: str = "", _=Depends(require_admin)):
    db = get_db()
    try:
        per = 20
        like = f"%{q}%"
        total = db.execute("SELECT COUNT(*) FROM users WHERE username LIKE ? OR email LIKE ?", (like,like)).fetchone()[0]
        rows  = db.execute(
            "SELECT id,username,email,role,banned,created_at,last_login,login_count,last_ip,avatar "
            "FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (like, like, per, (page-1)*per)
        ).fetchall()
        pages = max(1, (total + per - 1) // per)
        return {"total": total, "page": page, "per": per, "pages": pages,
                "users": [dict(r) for r in rows]}
    finally:
        db.close()

class CreateUserReq(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: str = "user"

@app.post("/admin/users")
async def create_user_admin(req: CreateUserReq, _=Depends(require_admin)):
    db = get_db()
    try:
        if db.execute("SELECT 1 FROM users WHERE username=?", (req.username,)).fetchone():
            raise HTTPException(400, "用户名已存在")
        if len(req.username) < 2: raise HTTPException(400, "用户名至少2位")
        if len(req.password) < 4: raise HTTPException(400, "密码至少4位")
        db.execute(
            "INSERT INTO users (username,pw_hash,email,role,created_at) VALUES (?,?,?,?,?)",
            (req.username, hash_pw(req.password), req.email or "", req.role, int(time.time()))
        )
        db.commit(); return {"message": "已创建"}
    finally:
        db.close()

@app.patch("/admin/users/{username}")
async def update_user(username: str, req: UpdateUserReq, _=Depends(require_admin)):
    db = get_db()
    try:
        fields, vals = [], []
        if req.email    is not None: fields.append("email=?");    vals.append(req.email)
        if req.role     is not None: fields.append("role=?");     vals.append(req.role)
        if req.banned   is not None: fields.append("banned=?");   vals.append(int(req.banned))
        if req.password is not None and req.password != "":
            if len(req.password) < 4: raise HTTPException(400, "密码至少4位")
            fields.append("pw_hash=?"); vals.append(hash_pw(req.password))
        if req.avatar is not None:
            if len(req.avatar) > 400_000: raise HTTPException(400, "头像数据过大")
            fields.append("avatar=?"); vals.append(req.avatar)
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

# ── Admin: 聊天删除 ───────────────────────────────────────────────────────────
@app.delete("/api/chat/{msg_id}")
async def delete_chat_msg(msg_id: int, user=Depends(get_current_user)):
    if user.get("role") != "admin": raise HTTPException(403, "仅管理员可删除")
    db = get_db()
    try:
        db.execute("DELETE FROM chat_messages WHERE id=?", (msg_id,))
        db.commit(); return {"message": "已删除"}
    finally:
        db.close()

# ── Admin: 论坛帖子删除 ───────────────────────────────────────────────────────
@app.delete("/api/forum/posts/{pid}")
async def delete_forum_post(pid: int, user=Depends(get_current_user)):
    if user.get("role") != "admin": raise HTTPException(403, "仅管理员可删除")
    db = get_db()
    try:
        db.execute("DELETE FROM forum_comments WHERE post_id=?", (pid,))
        db.execute("DELETE FROM forum_posts WHERE id=?", (pid,))
        db.commit(); return {"message": "已删除"}
    finally:
        db.close()

# ── Admin: 云盘文件列表 & 删除 ────────────────────────────────────────────────
@app.get("/admin/cloud/files")
async def admin_list_cloud(username: str = "", page: int = 1, _=Depends(require_admin)):
    db = get_db()
    try:
        per = 30
        like = f"%{username}%"
        total = db.execute("SELECT COUNT(*) FROM cloud_files WHERE owner LIKE ?", (like,)).fetchone()[0]
        rows = db.execute(
            "SELECT id,owner,filename,size,created_at FROM cloud_files WHERE owner LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (like, per, (page-1)*per)).fetchall()
        pages = max(1, (total + per - 1) // per)
        return {"files": [dict(r) for r in rows], "total": total, "page": page, "pages": pages}
    finally:
        db.close()

@app.delete("/admin/cloud/files/{fid}")
async def admin_delete_cloud(fid: str, _=Depends(require_admin)):
    db = get_db()
    try:
        row = db.execute("SELECT id FROM cloud_files WHERE id=?", (fid,)).fetchone()
        if not row: raise HTTPException(404, "文件不存在")
        path = os.path.join(CLOUD_DIR, fid)
        if os.path.exists(path): os.remove(path)
        db.execute("DELETE FROM cloud_files WHERE id=?", (fid,))
        db.commit(); return {"message": "已删除"}
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
        total        = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        banned       = db.execute("SELECT COUNT(*) FROM users WHERE banned=1").fetchone()[0]
        admins       = db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        day_ago      = int(time.time()) - 86400
        active       = db.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (day_ago,)).fetchone()[0]
        logins_today = db.execute("SELECT COUNT(*) FROM login_logs WHERE ts>? AND success=1", (day_ago,)).fetchone()[0]
        fails_today  = db.execute("SELECT COUNT(*) FROM login_logs WHERE ts>? AND success=0", (day_ago,)).fetchone()[0]
        chat_count   = db.execute("SELECT COUNT(*) FROM chat_messages").fetchone()[0]
        forum_posts  = db.execute("SELECT COUNT(*) FROM forum_posts").fetchone()[0]
        forum_cmts   = db.execute("SELECT COUNT(*) FROM forum_comments").fetchone()[0]
        cloud_files  = db.execute("SELECT COUNT(*) FROM cloud_files").fetchone()[0]
        cloud_bytes  = db.execute("SELECT COALESCE(SUM(size),0) FROM cloud_files").fetchone()[0]
        return {"total_users": total, "banned_count": banned, "admins": admins,
                "active_24h": active, "today_logins": logins_today, "today_fails": fails_today,
                "chat_count": chat_count, "forum_posts": forum_posts, "forum_comments": forum_cmts,
                "cloud_files": cloud_files, "cloud_bytes": cloud_bytes}
    finally:
        db.close()

# ── 用户 Profile ─────────────────────────────────────────────────────────────
@app.get("/api/profile")
async def get_profile(user=Depends(get_current_user)):
    db = get_db()
    try:
        row = db.execute(
            "SELECT username,email,role,created_at,last_login,login_count,last_ip,device_info,avatar FROM users WHERE username=?",
            (user["sub"],)).fetchone()
        if not row: raise HTTPException(404, "用户不存在")
        import json as _j
        d = dict(row)
        try: d["device_info"] = _j.loads(d["device_info"] or "{}")
        except: d["device_info"] = {}
        d["avatar"] = d.get("avatar") or ""
        return d
    finally:
        db.close()

@app.post("/api/profile/avatar")
async def set_avatar(req: Request, user=Depends(get_current_user)):
    body = await req.json()
    avatar = str(body.get("avatar", ""))
    MAX_B64 = 400_000  # ~300KB image
    if len(avatar) > MAX_B64:
        raise HTTPException(400, "图片太大，请使用小于 300KB 的图片")
    # accept either base64 image data or short emoji/text
    db = get_db()
    try:
        db.execute("UPDATE users SET avatar=? WHERE username=?", (avatar, user["sub"]))
        db.commit(); return {"message": "已更新"}
    finally:
        db.close()

class UpdateProfileReq(BaseModel):
    email:        Optional[str] = None
    old_password: Optional[str] = None
    new_password: Optional[str] = None

@app.post("/api/profile/update")
async def update_profile(req: UpdateProfileReq, user=Depends(get_current_user)):
    db = get_db()
    try:
        fields, vals = [], []
        if req.email is not None:
            fields.append("email=?"); vals.append(req.email)
        if req.new_password is not None:
            row = db.execute("SELECT pw_hash FROM users WHERE username=?", (user["sub"],)).fetchone()
            if not row: raise HTTPException(404)
            if hash_pw(req.old_password or "") != row["pw_hash"]:
                raise HTTPException(400, "当前密码错误")
            if len(req.new_password) < 4:
                raise HTTPException(400, "新密码至少4个字符")
            fields.append("pw_hash=?"); vals.append(hash_pw(req.new_password))
        if not fields: raise HTTPException(400, "无更新内容")
        vals.append(user["sub"])
        db.execute(f"UPDATE users SET {','.join(fields)} WHERE username=?", vals)
        db.commit(); return {"message": "已更新"}
    finally:
        db.close()

@app.get("/api/users/{username}")
async def get_public_profile(username: str, user=Depends(get_current_user)):
    db = get_db()
    try:
        row = db.execute(
            "SELECT username,role,created_at,login_count,avatar FROM users WHERE username=? AND banned=0",
            (username,)).fetchone()
        if not row: raise HTTPException(404, "用户不存在")
        return dict(row)
    finally:
        db.close()

@app.get("/api/cloud/stats")
async def cloud_stats(user=Depends(get_current_user)):
    db = get_db()
    try:
        row = db.execute(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(size),0) as total FROM cloud_files WHERE owner=?",
            (user["sub"],)).fetchone()
        return {"count": row["cnt"], "total_bytes": row["total"]}
    finally:
        db.close()

# ── 公告 ─────────────────────────────────────────────────────────────────────
class AnnouncementReq(BaseModel):
    title:   str
    content: str
    pinned:  bool = False

@app.get("/api/announcements")
async def list_announcements(user=Depends(get_current_user)):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id,title,content,author,pinned,created_at FROM announcements ORDER BY pinned DESC, id DESC LIMIT 50"
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        db.close()

@app.post("/api/announcements")
async def post_announcement(req: AnnouncementReq, user=Depends(get_current_user)):
    if user.get("role") != "admin": raise HTTPException(403, "仅管理员可发布公告")
    db = get_db()
    try:
        db.execute("INSERT INTO announcements (title,content,author,pinned,created_at) VALUES (?,?,?,?,?)",
                   (req.title, req.content, user["sub"], int(req.pinned), int(time.time())))
        db.commit(); return {"message": "已发布"}
    finally:
        db.close()

@app.delete("/api/announcements/{aid}")
async def del_announcement(aid: int, user=Depends(get_current_user)):
    if user.get("role") != "admin": raise HTTPException(403, "仅管理员可删除")
    db = get_db()
    try:
        db.execute("DELETE FROM announcements WHERE id=?", (aid,))
        db.commit(); return {"message": "已删除"}
    finally:
        db.close()

# ── 聊天 ─────────────────────────────────────────────────────────────────────
class ChatReq(BaseModel):
    content: str

@app.get("/api/chat")
async def get_chat(since: int = 0, user=Depends(get_current_user)):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT c.id,c.username,c.content,c.ts,COALESCE(u.avatar,'') as avatar "
            "FROM chat_messages c LEFT JOIN users u ON c.username=u.username "
            "WHERE c.ts>? ORDER BY c.ts ASC LIMIT 100",
            (since,)).fetchall()
        return {"messages": [dict(r) for r in rows]}
    finally:
        db.close()

@app.post("/api/chat")
async def send_chat(req: ChatReq, user=Depends(get_current_user)):
    content = req.content.strip()[:500]
    if not content: raise HTTPException(400, "内容不能为空")
    db = get_db()
    try:
        ts = int(time.time())
        db.execute("INSERT INTO chat_messages (username,content,ts) VALUES (?,?,?)",
                   (user["sub"], content, ts))
        db.commit()
        return {"id": db.execute("SELECT last_insert_rowid()").fetchone()[0], "ts": ts}
    finally:
        db.close()

# ── 论坛 ─────────────────────────────────────────────────────────────────────
class PostReq(BaseModel):
    title:   str
    content: str

class CommentReq(BaseModel):
    content: str

@app.get("/api/forum/posts")
async def list_posts(page: int = 1, user=Depends(get_current_user)):
    db = get_db()
    try:
        per = 20
        total = db.execute("SELECT COUNT(*) FROM forum_posts").fetchone()[0]
        rows  = db.execute(
            "SELECT p.id,p.title,p.author,p.created_at,"
            "(SELECT COUNT(*) FROM forum_comments WHERE post_id=p.id) AS replies,"
            "COALESCE(u.avatar,'') as avatar "
            "FROM forum_posts p LEFT JOIN users u ON p.author=u.username "
            "ORDER BY p.id DESC LIMIT ? OFFSET ?",
            (per, (page-1)*per)).fetchall()
        return {"total": total, "page": page, "posts": [dict(r) for r in rows]}
    finally:
        db.close()

@app.post("/api/forum/posts")
async def create_post(req: PostReq, user=Depends(get_current_user)):
    title = req.title.strip()[:100]; content = req.content.strip()[:5000]
    if not title or not content: raise HTTPException(400, "标题和内容不能为空")
    db = get_db()
    try:
        db.execute("INSERT INTO forum_posts (title,content,author,created_at) VALUES (?,?,?,?)",
                   (title, content, user["sub"], int(time.time())))
        db.commit(); return {"message": "发布成功"}
    finally:
        db.close()

@app.get("/api/forum/posts/{pid}")
async def get_post(pid: int, user=Depends(get_current_user)):
    db = get_db()
    try:
        post = db.execute(
            "SELECT p.*,COALESCE(u.avatar,'') as avatar FROM forum_posts p "
            "LEFT JOIN users u ON p.author=u.username WHERE p.id=?", (pid,)).fetchone()
        if not post: raise HTTPException(404, "帖子不存在")
        comments = db.execute(
            "SELECT c.id,c.author,c.content,c.created_at,COALESCE(u.avatar,'') as avatar "
            "FROM forum_comments c LEFT JOIN users u ON c.author=u.username "
            "WHERE c.post_id=? ORDER BY c.id ASC",
            (pid,)).fetchall()
        return {"post": dict(post), "comments": [dict(c) for c in comments]}
    finally:
        db.close()

@app.post("/api/forum/posts/{pid}/comments")
async def add_comment(pid: int, req: CommentReq, user=Depends(get_current_user)):
    content = req.content.strip()[:1000]
    if not content: raise HTTPException(400, "内容不能为空")
    db = get_db()
    try:
        post = db.execute("SELECT id FROM forum_posts WHERE id=?", (pid,)).fetchone()
        if not post: raise HTTPException(404, "帖子不存在")
        db.execute("INSERT INTO forum_comments (post_id,author,content,created_at) VALUES (?,?,?,?)",
                   (pid, user["sub"], content, int(time.time())))
        db.commit(); return {"message": "回复成功"}
    finally:
        db.close()

# ── 云盘 ─────────────────────────────────────────────────────────────────────
CLOUD_DIR = os.environ.get("CLOUD_DIR", "cloud_files")
os.makedirs(CLOUD_DIR, exist_ok=True)
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_MB", "50")) * 1024 * 1024

@app.get("/api/cloud/files")
async def list_cloud_files(user=Depends(get_current_user)):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id,filename,size,created_at FROM cloud_files WHERE owner=? ORDER BY id DESC",
            (user["sub"],)).fetchall()
        return {"files": [dict(r) for r in rows]}
    finally:
        db.close()

@app.post("/api/cloud/upload")
async def upload_file(request: Request, user=Depends(get_current_user)):
    import json as _j2
    body = await request.body()
    try:
        data = _j2.loads(body)
        filename = str(data.get("filename","")).strip().replace("/","_").replace("\\","_")
        import base64
        file_bytes = base64.b64decode(data.get("data",""))
    except Exception as e:
        raise HTTPException(400, f"格式错误: {e}")
    if not filename: raise HTTPException(400, "文件名不能为空")
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(413, f"文件过大，最大 {MAX_FILE_SIZE//1048576}MB")
    db = get_db()
    try:
        # check quota: max 100 files per user
        count = db.execute("SELECT COUNT(*) FROM cloud_files WHERE owner=?", (user["sub"],)).fetchone()[0]
        if count >= 100: raise HTTPException(400, "云盘文件数量已达上限(100个)")
        import uuid
        fid      = str(uuid.uuid4())
        user_dir = os.path.join(CLOUD_DIR, user["sub"])
        os.makedirs(user_dir, exist_ok=True)
        path = os.path.join(user_dir, fid)
        with open(path, "wb") as f: f.write(file_bytes)
        db.execute("INSERT INTO cloud_files (id,owner,filename,size,created_at) VALUES (?,?,?,?,?)",
                   (fid, user["sub"], filename, len(file_bytes), int(time.time())))
        db.commit()
        return {"id": fid, "filename": filename, "size": len(file_bytes)}
    finally:
        db.close()

@app.get("/api/cloud/download/{fid}")
async def download_file(fid: str, user=Depends(get_current_user)):
    db = get_db()
    try:
        # 管理员可下载任意文件，普通用户只能下载自己的
        if user.get("role") == "admin":
            row = db.execute("SELECT * FROM cloud_files WHERE id=?", (fid,)).fetchone()
        else:
            row = db.execute("SELECT * FROM cloud_files WHERE id=? AND owner=?", (fid, user["sub"])).fetchone()
        if not row: raise HTTPException(404, "文件不存在")
        # 兼容旧路径（扁平）和新路径（按用户分目录）
        path_flat = os.path.join(CLOUD_DIR, fid)
        path_user = os.path.join(CLOUD_DIR, row["owner"], fid)
        path = path_user if os.path.exists(path_user) else path_flat
        if not os.path.exists(path): raise HTTPException(404, "文件已丢失")
        import base64
        with open(path, "rb") as f: raw = f.read()
        return {"filename": row["filename"], "data": base64.b64encode(raw).decode(), "size": len(raw)}
    finally:
        db.close()

@app.get("/admin/cloud/download/{fid}")
async def admin_download_file(fid: str, _=Depends(require_admin)):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM cloud_files WHERE id=?", (fid,)).fetchone()
        if not row: raise HTTPException(404, "文件不存在")
        path_flat = os.path.join(CLOUD_DIR, fid)
        path_user = os.path.join(CLOUD_DIR, row["owner"], fid)
        path = path_user if os.path.exists(path_user) else path_flat
        if not os.path.exists(path): raise HTTPException(404, "文件已丢失")
        import base64
        with open(path, "rb") as f: raw = f.read()
        return {"filename": row["filename"], "data": base64.b64encode(raw).decode(), "size": len(raw)}
    finally:
        db.close()

@app.delete("/api/cloud/files/{fid}")
async def delete_cloud_file(fid: str, user=Depends(get_current_user)):
    db = get_db()
    try:
        row = db.execute("SELECT id FROM cloud_files WHERE id=? AND owner=?", (fid, user["sub"])).fetchone()
        if not row: raise HTTPException(404, "文件不存在")
        path = os.path.join(CLOUD_DIR, fid)
        if os.path.exists(path): os.remove(path)
        db.execute("DELETE FROM cloud_files WHERE id=?", (fid,))
        db.commit(); return {"message": "已删除"}
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
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;font-size:14px}
a{color:#7c83ff;text-decoration:none}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1e2130;border:1px solid #2d3148;border-radius:16px;padding:32px;width:360px}
h1{font-size:22px;margin-bottom:4px;color:#fff}
h2{font-size:17px;color:#c8ccff;margin-bottom:12px}
h3{font-size:14px;color:#a0aec0;margin-bottom:8px}
input,select,textarea{width:100%;padding:10px 14px;background:#252840;border:1px solid #2d3148;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;transition:.2s}
input:focus,select:focus,textarea:focus{border-color:#7c83ff}
button{cursor:pointer;border:none;border-radius:8px;padding:8px 16px;font-size:13px;font-weight:600;transition:.15s}
.btn-primary{background:#5a60e8;color:#fff}.btn-primary:hover{background:#6e74f0}
.btn-danger{background:#e05252;color:#fff}.btn-danger:hover{background:#f06060}
.btn-secondary{background:#2d3148;color:#c8ccff}.btn-secondary:hover{background:#363c5a}
.btn-sm{padding:4px 10px;font-size:12px;border-radius:6px}
.btn-success{background:#3a7d44;color:#fff}.btn-success:hover{background:#4a9d57}
/* Layout */
#app{display:none;min-height:100vh;flex-direction:column}
.topbar{background:#1e2130;border-bottom:1px solid #2d3148;padding:0 24px;height:56px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100}
.topbar h1{font-size:16px;color:#fff;flex:1}
.topbar .badge{background:#5a60e8;color:#fff;border-radius:20px;padding:2px 10px;font-size:12px}
.layout{display:flex;flex:1}
.sidebar{width:200px;background:#161824;border-right:1px solid #2d3148;padding:12px 0;flex-shrink:0;position:sticky;top:56px;height:calc(100vh - 56px);overflow-y:auto}
.sidebar a{display:flex;align-items:center;gap:10px;padding:10px 20px;color:#a0aec0;font-size:14px;border-radius:0;transition:.15s;text-decoration:none}
.sidebar a:hover{background:#1e2130;color:#e2e8f0}
.sidebar a.active{background:#252840;color:#7c83ff;border-right:3px solid #7c83ff}
.sidebar .section-title{padding:16px 20px 6px;font-size:11px;color:#4a5568;text-transform:uppercase;letter-spacing:.06em}
.main{flex:1;padding:24px;overflow:auto;max-width:1200px}
/* Cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#1e2130;border:1px solid #2d3148;border-radius:12px;padding:20px}
.stat-card .val{font-size:32px;font-weight:700;color:#7c83ff}
.stat-card .lbl{font-size:12px;color:#a0aec0;margin-top:4px}
.panel{background:#1e2130;border:1px solid #2d3148;border-radius:12px;padding:20px;margin-bottom:20px}
/* Table */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{background:#161824;color:#a0aec0;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:10px 12px;text-align:left;white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid #252840;vertical-align:middle;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#252840}
/* Toolbar */
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.toolbar input,.toolbar select{width:auto;flex:1;min-width:140px;max-width:280px}
/* Avatar */
.av{width:32px;height:32px;border-radius:50%;background:#5a60e8;display:inline-flex;align-items:center;justify-content:center;font-size:13px;color:#fff;font-weight:700;flex-shrink:0;overflow:hidden}
.av img{width:100%;height:100%;object-fit:cover;border-radius:50%}
/* Tags */
.tag{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
.tag-admin{background:#3a3a8a;color:#9090ff}
.tag-user{background:#253040;color:#7ab4d8}
.tag-banned{background:#4a2020;color:#f08080}
.tag-pinned{background:#3a4a20;color:#aadd70}
/* Modal */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;align-items:center;justify-content:center}
.modal-bg.open{display:flex}
.modal{background:#1e2130;border:1px solid #2d3148;border-radius:16px;padding:28px;width:min(480px,95vw);max-height:85vh;overflow-y:auto}
.modal h2{margin-bottom:16px}
.modal .row{margin-bottom:12px}
.modal label{display:block;font-size:12px;color:#a0aec0;margin-bottom:4px}
.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}
/* Pagination */
.pagination{display:flex;gap:8px;align-items:center;margin-top:12px;flex-wrap:wrap}
.pagination button{background:#252840;color:#c8ccff;border-radius:6px;padding:5px 12px;font-size:13px;border:1px solid #2d3148;cursor:pointer}
.pagination button.active{background:#5a60e8;color:#fff;border-color:#5a60e8}
.pagination button:disabled{opacity:.4;cursor:default}
/* Forum post detail */
.post-content{background:#161824;border-radius:8px;padding:14px;line-height:1.6;margin:10px 0;white-space:pre-wrap;word-break:break-word}
/* Tabs */
.tabs{display:flex;gap:2px;margin-bottom:20px;background:#161824;border-radius:10px;padding:4px}
.tab-btn{flex:1;padding:8px;background:none;border:none;color:#a0aec0;font-size:13px;border-radius:7px;cursor:pointer;transition:.15s}
.tab-btn.active{background:#252840;color:#c8ccff}
/* Toast */
#toast{position:fixed;bottom:20px;right:20px;background:#2d3148;color:#e2e8f0;padding:10px 18px;border-radius:10px;font-size:13px;z-index:999;display:none}
</style>
</head>
<body>

<!-- LOGIN -->
<div class="login-wrap" id="loginView">
<div class="card">
  <h1>🛡 管理后台</h1>
  <p style="color:#a0aec0;font-size:13px;margin-bottom:20px">File Manager Pro</p>
  <div style="margin-bottom:8px">
    <div class="tabs" style="margin-bottom:12px">
      <button class="tab-btn active" id="loginTab1" onclick="switchLoginTab(1)">账号登录</button>
      <button class="tab-btn" id="loginTab2" onclick="switchLoginTab(2)">主密码登录</button>
    </div>
    <div id="loginPane1">
      <div style="margin-bottom:10px"><input id="adminUsername" placeholder="管理员用户名" onkeydown="if(event.key==='Enter')doLogin()"></div>
      <div><input type="password" id="adminPw" placeholder="密码" onkeydown="if(event.key==='Enter')doLogin()"></div>
    </div>
    <div id="loginPane2" style="display:none">
      <input type="password" id="adminMasterPw" placeholder="环境变量主密码" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
  </div>
  <button class="btn-primary" style="width:100%;padding:12px;margin-top:12px" onclick="doLogin()">登 录</button>
  <div id="loginErr" style="color:#f08080;font-size:13px;margin-top:10px;text-align:center"></div>
</div>
</div>

<!-- APP -->
<div id="app" style="display:none;flex-direction:column">
<div class="topbar">
  <h1>🛡 File Manager Pro 管理后台</h1>
  <span class="badge" id="adminBadge">管理员</span>
  <button class="btn-secondary btn-sm" onclick="doLogout()">退出</button>
</div>
<div class="layout">
  <!-- Sidebar -->
  <div class="sidebar">
    <div class="section-title">概览</div>
    <a href="#" onclick="showTab('overview')" id="nav-overview" class="active">📊 数据概览</a>
    <div class="section-title">用户</div>
    <a href="#" onclick="showTab('users')" id="nav-users">👥 用户管理</a>
    <a href="#" onclick="showTab('logs')" id="nav-logs">📋 登录日志</a>
    <div class="section-title">内容</div>
    <a href="#" onclick="showTab('announce')" id="nav-announce">📢 公告管理</a>
    <a href="#" onclick="showTab('chat')" id="nav-chat">💬 聊天记录</a>
    <a href="#" onclick="showTab('forum')" id="nav-forum">🗣 论坛管理</a>
    <div class="section-title">存储</div>
    <a href="#" onclick="showTab('cloud')" id="nav-cloud">☁️ 云盘管理</a>
  </div>

  <!-- Main content -->
  <div class="main" id="mainContent">
    <!-- OVERVIEW -->
    <div id="tab-overview">
      <div class="stats-grid" id="statsGrid"></div>
      <div class="panel">
        <h2>📈 最近注册用户</h2>
        <div class="tbl-wrap"><table id="recentUsersTable">
          <thead><tr><th>用户名</th><th>邮箱</th><th>注册时间</th><th>登录次数</th><th>角色</th></tr></thead>
          <tbody></tbody>
        </table></div>
      </div>
    </div>

    <!-- USERS -->
    <div id="tab-users" style="display:none">
      <div class="panel">
        <h2>👥 用户管理</h2>
        <div class="toolbar">
          <input id="userSearch" placeholder="搜索用户名..." oninput="loadUsers(1)">
          <button class="btn-primary" onclick="showCreateUser()">＋ 新建用户</button>
        </div>
        <div class="tbl-wrap"><table><thead><tr>
          <th>头像</th><th>用户名</th><th>邮箱</th><th>角色</th><th>登录次数</th><th>最后登录</th><th>最后IP</th><th>状态</th><th>操作</th>
        </tr></thead><tbody id="usersTbody"></tbody></table></div>
        <div class="pagination" id="usersPagination"></div>
      </div>
    </div>

    <!-- LOGS -->
    <div id="tab-logs" style="display:none">
      <div class="panel">
        <h2>📋 登录日志</h2>
        <div class="toolbar">
          <input id="logSearch" placeholder="搜索用户名..." oninput="loadLogs(1)">
        </div>
        <div class="tbl-wrap"><table><thead><tr>
          <th>用户名</th><th>时间</th><th>IP</th><th>设备</th><th>结果</th>
        </tr></thead><tbody id="logsTbody"></tbody></table></div>
        <div class="pagination" id="logsPagination"></div>
      </div>
    </div>

    <!-- ANNOUNCE -->
    <div id="tab-announce" style="display:none">
      <div class="panel">
        <h2>📢 公告管理</h2>
        <button class="btn-primary" style="margin-bottom:14px" onclick="showAnnounceModal()">＋ 发布公告</button>
        <div id="announceList"></div>
      </div>
    </div>

    <!-- CHAT -->
    <div id="tab-chat" style="display:none">
      <div class="panel">
        <h2>💬 聊天记录</h2>
        <div class="toolbar">
          <input id="chatUserSearch" placeholder="筛选用户名..." oninput="loadChat()">
          <button class="btn-secondary btn-sm" onclick="loadChat()">刷新</button>
        </div>
        <div id="chatList" style="display:flex;flex-direction:column;gap:8px"></div>
      </div>
    </div>

    <!-- FORUM -->
    <div id="tab-forum" style="display:none">
      <div id="forumList">
        <div class="panel">
          <h2>🗣 论坛帖子</h2>
          <div class="toolbar">
            <button class="btn-secondary btn-sm" onclick="loadForum(1)">刷新</button>
          </div>
          <div class="tbl-wrap"><table><thead><tr>
            <th>ID</th><th>标题</th><th>作者</th><th>回复</th><th>时间</th><th>操作</th>
          </tr></thead><tbody id="forumTbody"></tbody></table></div>
          <div class="pagination" id="forumPagination"></div>
        </div>
      </div>
      <div id="forumDetail" style="display:none"></div>
    </div>

    <!-- CLOUD -->
    <div id="tab-cloud" style="display:none">
      <div class="panel">
        <h2>☁️ 云盘文件管理</h2>
        <div class="toolbar">
          <input id="cloudUserSearch" placeholder="筛选用户名..." oninput="loadCloud(1)">
          <button class="btn-secondary btn-sm" onclick="loadCloud(1)">刷新</button>
        </div>
        <div class="tbl-wrap"><table><thead><tr>
          <th style="width:32px"></th><th>文件名</th><th>大小</th><th>上传时间</th><th>操作</th>
        </tr></thead><tbody id="cloudTbody"></tbody></table></div>
        <div class="pagination" id="cloudPagination"></div>
        <div id="cloudStats" style="margin-top:12px;color:#a0aec0;font-size:12px"></div>
      </div>
    </div>
  </div>
</div>
</div>

<!-- Modals -->
<div class="modal-bg" id="userModal">
<div class="modal">
  <h2 id="userModalTitle">编辑用户</h2>
  <input type="hidden" id="editUsername">
  <!-- 头像预览 + 上传 -->
  <div class="row" style="display:flex;align-items:center;gap:14px">
    <div id="editAvPreview" style="width:56px;height:56px;border-radius:50%;background:#252840;display:flex;align-items:center;justify-content:center;font-size:22px;overflow:hidden;flex-shrink:0;border:2px solid #2d3148"></div>
    <div style="flex:1;min-width:0">
      <label style="display:block;font-size:12px;color:#a0aec0;margin-bottom:6px">头像（选择图片文件，PNG/JPG ≤300KB）</label>
      <div style="display:flex;gap:6px">
        <input type="file" id="editAvFile" accept="image/png,image/jpeg" style="display:none" onchange="previewAvatar(this)">
        <button class="btn-secondary btn-sm" onclick="document.getElementById('editAvFile').click()">📂 选择图片</button>
        <button class="btn-secondary btn-sm" onclick="clearAvatar()">🗑 清除头像</button>
      </div>
      <div id="editAvStatus" style="font-size:11px;color:#a0aec0;margin-top:4px"></div>
    </div>
  </div>
  <input type="hidden" id="editAvatarData">
  <div class="row"><label>邮箱</label><input id="editEmail" placeholder="邮箱（可选）"></div>
  <div class="row"><label>角色</label><select id="editRole"><option value="user">普通用户</option><option value="admin">管理员</option></select></div>
  <div class="row"><label>新密码（留空不改）</label><input type="password" id="editPassword" placeholder="新密码"></div>
  <div class="row" id="banRow"><label>封禁</label><select id="editBanned"><option value="0">正常</option><option value="1">封禁</option></select></div>
  <div id="userModalErr" style="color:#f08080;font-size:13px;margin-bottom:8px"></div>
  <div class="modal-footer">
    <button class="btn-secondary" onclick="closeModal('userModal')">取消</button>
    <button class="btn-primary" onclick="saveUser()">保存</button>
  </div>
</div>
</div>

<div class="modal-bg" id="createUserModal">
<div class="modal">
  <h2>＋ 新建用户</h2>
  <div class="row"><label>用户名</label><input id="newUsername" placeholder="用户名"></div>
  <div class="row"><label>密码</label><input type="password" id="newPassword" placeholder="密码"></div>
  <div class="row"><label>邮箱（可选）</label><input id="newEmail" placeholder="邮箱"></div>
  <div class="row"><label>角色</label><select id="newRole"><option value="user">普通用户</option><option value="admin">管理员</option></select></div>
  <div id="createUserErr" style="color:#f08080;font-size:13px;margin-bottom:8px"></div>
  <div class="modal-footer">
    <button class="btn-secondary" onclick="closeModal('createUserModal')">取消</button>
    <button class="btn-primary" onclick="doCreateUser()">创建</button>
  </div>
</div>
</div>

<div class="modal-bg" id="announceModal">
<div class="modal">
  <h2>📢 发布公告</h2>
  <div class="row"><label>标题</label><input id="annTitle" placeholder="公告标题"></div>
  <div class="row"><label>内容</label><textarea id="annContent" rows="4" placeholder="公告内容"></textarea></div>
  <div class="row"><label><input type="checkbox" id="annPinned" style="width:auto;margin-right:6px">置顶</label></div>
  <div class="modal-footer">
    <button class="btn-secondary" onclick="closeModal('announceModal')">取消</button>
    <button class="btn-primary" onclick="postAnnounce()">发布</button>
  </div>
</div>
</div>

<div id="toast"></div>

<script>
let token = '';
const BASE = '';

async function api(method, path, body) {
  const opts = { method, headers: {'Content-Type':'application/json'} };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(BASE + path, opts);
  let data; try { data = await r.json(); } catch { data = {}; }
  if (!r.ok) throw new Error(data.detail || r.statusText);
  return data;
}

function toast(msg, err=false) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.style.background = err ? '#6a2020' : '#2d3148';
  t.style.display = 'block'; setTimeout(() => t.style.display='none', 2500);
}

let loginTabMode = 1;
function switchLoginTab(n) {
  loginTabMode = n;
  document.getElementById('loginPane1').style.display = n===1 ? 'block' : 'none';
  document.getElementById('loginPane2').style.display = n===2 ? 'block' : 'none';
  document.getElementById('loginTab1').classList.toggle('active', n===1);
  document.getElementById('loginTab2').classList.toggle('active', n===2);
}

async function doLogin() {
  let body;
  if (loginTabMode === 1) {
    const username = document.getElementById('adminUsername').value.trim();
    const pw = document.getElementById('adminPw').value;
    if (!username) { document.getElementById('loginErr').textContent = '⚠ 请输入用户名'; return; }
    body = {username, password: pw};
  } else {
    body = {password: document.getElementById('adminMasterPw').value};
  }
  try {
    const d = await api('POST', '/admin/login', body);
    token = d.token;
    const badge = document.getElementById('adminBadge');
    badge.textContent = d.username && d.username !== '__admin__' ? d.username : '管理员';
    document.getElementById('loginView').style.display = 'none';
    document.getElementById('app').style.display = 'flex';
    showTab('overview');
  } catch(e) { document.getElementById('loginErr').textContent = '❌ ' + e.message; }
}

function doLogout() { token=''; location.reload(); }

const TABS = ['overview','users','logs','announce','chat','forum','cloud'];
function showTab(name) {
  TABS.forEach(t => {
    document.getElementById('tab-'+t).style.display = t===name ? 'block' : 'none';
    const n = document.getElementById('nav-'+t);
    if (n) n.classList.toggle('active', t===name);
  });
  if (name==='overview') loadOverview();
  else if (name==='users') loadUsers(1);
  else if (name==='logs') loadLogs(1);
  else if (name==='announce') loadAnnounce();
  else if (name==='chat') loadChat();
  else if (name==='forum') loadForum(1);
  else if (name==='cloud') loadCloud(1);
}

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ── OVERVIEW ──────────────────────────────────────────────────────────────────
async function loadOverview() {
  try {
    const d = await api('GET', '/admin/stats');
    const sg = document.getElementById('statsGrid');
    sg.innerHTML = [
      ['👥 总用户', d.total_users],
      ['✅ 今日登录', d.today_logins],
      ['💬 聊天消息', d.chat_count || 0],
      ['🗣 论坛帖子', d.forum_posts || 0],
      ['💬 论坛回复', d.forum_comments || 0],
      ['☁️ 云盘文件', d.cloud_files || 0],
      ['📦 云盘用量', fmtSize(d.cloud_bytes || 0)],
      ['🚫 封禁用户', d.banned_count || 0],
    ].map(([l,v]) => `<div class="stat-card"><div class="val">${v}</div><div class="lbl">${l}</div></div>`).join('');
    const ru = await api('GET', '/admin/users?page=1&q=');
    const tbody = document.querySelector('#recentUsersTable tbody');
    tbody.innerHTML = (ru.users || []).slice(0,8).map(u => `
      <tr>
        <td>${esc(u.username)}</td>
        <td>${esc(u.email||'—')}</td>
        <td>${fmtTs(u.created_at)}</td>
        <td>${u.login_count}</td>
        <td><span class="tag ${u.role==='admin'?'tag-admin':'tag-user'}">${u.role}</span></td>
      </tr>`).join('');
  } catch(e) { toast('加载失败: '+e.message, true); }
}

// ── USERS ─────────────────────────────────────────────────────────────────────
let usersPage = 1;
async function loadUsers(page=1) {
  usersPage = page;
  const q = document.getElementById('userSearch').value;
  try {
    const d = await api('GET', `/admin/users?page=${page}&q=${encodeURIComponent(q)}`);
    const tbody = document.getElementById('usersTbody');
    tbody.innerHTML = (d.users||[]).map(u => {
      const avHtml = u.avatar && u.avatar.length > 50
        ? `<div class="av"><img src="data:image/png;base64,${u.avatar}" onerror="this.parentElement.textContent='${esc(u.username).charAt(0).toUpperCase()}'"></div>`
        : `<div class="av">${esc(u.avatar||u.username.charAt(0).toUpperCase())}</div>`;
      return `<tr>
        <td>${avHtml}</td>
        <td><strong>${esc(u.username)}</strong></td>
        <td>${esc(u.email||'—')}</td>
        <td><span class="tag ${u.role==='admin'?'tag-admin':'tag-user'}">${u.role}</span></td>
        <td>${u.login_count}</td>
        <td>${fmtTs(u.last_login)}</td>
        <td>${esc(u.last_ip||'—')}</td>
        <td>${u.banned?'<span class="tag tag-banned">封禁</span>':'<span style="color:#48bb78;font-size:12px">正常</span>'}</td>
        <td style="white-space:nowrap">
          <button class="btn-secondary btn-sm" onclick="editUser('${esc(u.username)}','${esc(u.email||'')}','${u.role}',${u.banned},'${u.avatar && u.avatar.length > 50 ? '__img__' : esc(u.avatar||'')}','${u.avatar && u.avatar.length > 50 ? u.avatar : ''}')">编辑</button>
          <button class="btn-danger btn-sm" onclick="delUser('${esc(u.username)}')">删除</button>
        </td>
      </tr>`;
    }).join('');
    renderPagination('usersPagination', d.page, d.pages, loadUsers);
  } catch(e) { toast('加载失败: '+e.message, true); }
}

function editUser(uname, email, role, banned, avShort, avB64) {
  document.getElementById('editUsername').value = uname;
  document.getElementById('editEmail').value = email;
  document.getElementById('editRole').value = role;
  document.getElementById('editBanned').value = banned;
  document.getElementById('editPassword').value = '';
  document.getElementById('editAvatarData').value = '';   // no change by default
  document.getElementById('editAvFile').value = '';
  document.getElementById('editAvStatus').textContent = '';
  document.getElementById('userModalTitle').textContent = '编辑用户 — ' + uname;
  document.getElementById('userModalErr').textContent = '';
  // render avatar preview
  const prev = document.getElementById('editAvPreview');
  if (avB64 && avB64.length > 50) {
    prev.innerHTML = `<img src="data:image/png;base64,${avB64}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">`;
  } else {
    prev.textContent = avShort || uname.charAt(0).toUpperCase();
  }
  openModal('userModal');
}

function previewAvatar(input) {
  const file = input.files[0];
  if (!file) return;
  if (file.size > 300_000) {
    document.getElementById('editAvStatus').textContent = '❌ 文件超过 300KB';
    input.value = ''; return;
  }
  const reader = new FileReader();
  reader.onload = e => {
    const b64 = e.target.result.split(',')[1];
    document.getElementById('editAvatarData').value = b64;
    document.getElementById('editAvPreview').innerHTML =
      `<img src="${e.target.result}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">`;
    document.getElementById('editAvStatus').textContent = `✅ 已选择: ${file.name}`;
  };
  reader.readAsDataURL(file);
}

function clearAvatar() {
  document.getElementById('editAvatarData').value = '__clear__';
  document.getElementById('editAvPreview').textContent = '🚫';
  document.getElementById('editAvStatus').textContent = '头像将被清除';
  document.getElementById('editAvFile').value = '';
}

async function saveUser() {
  const uname = document.getElementById('editUsername').value;
  const body = {
    email: document.getElementById('editEmail').value || null,
    role: document.getElementById('editRole').value,
    banned: parseInt(document.getElementById('editBanned').value),
  };
  const pw = document.getElementById('editPassword').value;
  if (pw) body.password = pw;
  const avData = document.getElementById('editAvatarData').value;
  if (avData === '__clear__') body.avatar = '';
  else if (avData) body.avatar = avData;
  try {
    await api('PATCH', `/admin/users/${encodeURIComponent(uname)}`, body);
    toast('✅ 已更新'); closeModal('userModal'); loadUsers(usersPage);
  } catch(e) { document.getElementById('userModalErr').textContent = '❌ '+e.message; }
}

async function delUser(uname) {
  if (!confirm(`确认删除用户 ${uname}？此操作不可逆！`)) return;
  try { await api('DELETE', `/admin/users/${encodeURIComponent(uname)}`); toast('已删除'); loadUsers(usersPage); }
  catch(e) { toast(e.message, true); }
}

function showCreateUser() {
  document.getElementById('newUsername').value='';
  document.getElementById('newPassword').value='';
  document.getElementById('newEmail').value='';
  document.getElementById('newRole').value='user';
  document.getElementById('createUserErr').textContent='';
  openModal('createUserModal');
}

async function doCreateUser() {
  const body = {
    username: document.getElementById('newUsername').value.trim(),
    password: document.getElementById('newPassword').value,
    email: document.getElementById('newEmail').value.trim() || null,
    role: document.getElementById('newRole').value,
  };
  if (!body.username || !body.password) { document.getElementById('createUserErr').textContent='⚠ 用户名和密码必填'; return; }
  try {
    await api('POST', '/admin/users', body);
    toast('✅ 用户已创建'); closeModal('createUserModal'); loadUsers(1);
  } catch(e) { document.getElementById('createUserErr').textContent = '❌ '+e.message; }
}

// ── LOGS ──────────────────────────────────────────────────────────────────────
let logsPage = 1;
async function loadLogs(page=1) {
  logsPage = page;
  const q = document.getElementById('logSearch').value;
  try {
    const d = await api('GET', `/admin/logs?page=${page}&username=${encodeURIComponent(q)}`);
    const tbody = document.getElementById('logsTbody');
    tbody.innerHTML = (d.logs||[]).map(l => `<tr>
      <td>${esc(l.username)}</td>
      <td>${fmtTs(l.ts)}</td>
      <td>${esc(l.ip||'—')}</td>
      <td style="max-width:200px">${esc(l.device||'—')}</td>
      <td>${l.success?'<span style="color:#48bb78">✓ 成功</span>':'<span style="color:#f08080">✗ 失败</span>'}</td>
    </tr>`).join('');
    renderPagination('logsPagination', d.page, d.pages, loadLogs);
  } catch(e) { toast('加载失败: '+e.message, true); }
}

// ── ANNOUNCE ──────────────────────────────────────────────────────────────────
async function loadAnnounce() {
  try {
    const d = await api('GET', '/api/announcements');
    const el = document.getElementById('announceList');
    if (!d.items || d.items.length===0) { el.innerHTML='<p style="color:#a0aec0">暂无公告</p>'; return; }
    el.innerHTML = d.items.map(a => `
      <div style="background:#161824;border-radius:10px;padding:14px;margin-bottom:10px;border-left:3px solid ${a.pinned?'#f6c90e':'#5a60e8'}">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          ${a.pinned?'<span class="tag tag-pinned">📌 置顶</span>':''}
          <strong>${esc(a.title)}</strong>
          <span style="flex:1"></span>
          <span style="color:#a0aec0;font-size:12px">${fmtTs(a.created_at)} · ${esc(a.author)}</span>
          <button class="btn-danger btn-sm" onclick="delAnnounce(${a.id})">删除</button>
        </div>
        <div style="color:#c8ccff;font-size:13px;line-height:1.6;white-space:pre-wrap">${esc(a.content)}</div>
      </div>`).join('');
  } catch(e) { toast('加载失败: '+e.message, true); }
}

function showAnnounceModal() {
  document.getElementById('annTitle').value='';
  document.getElementById('annContent').value='';
  document.getElementById('annPinned').checked=false;
  openModal('announceModal');
}

async function postAnnounce() {
  const title = document.getElementById('annTitle').value.trim();
  const content = document.getElementById('annContent').value.trim();
  if (!title||!content) { toast('标题和内容不能为空', true); return; }
  try {
    await api('POST', '/api/announcements', {title, content, pinned: document.getElementById('annPinned').checked});
    toast('✅ 已发布'); closeModal('announceModal'); loadAnnounce();
  } catch(e) { toast(e.message, true); }
}

async function delAnnounce(id) {
  if (!confirm('确认删除该公告？')) return;
  try { await api('DELETE', `/api/announcements/${id}`); toast('已删除'); loadAnnounce(); }
  catch(e) { toast(e.message, true); }
}

// ── CHAT ──────────────────────────────────────────────────────────────────────
async function loadChat() {
  const q = document.getElementById('chatUserSearch').value.toLowerCase();
  try {
    const d = await api('GET', '/api/chat?since=0');
    const el = document.getElementById('chatList');
    const msgs = (d.messages||[]).filter(m => !q || m.username.toLowerCase().includes(q));
    if (!msgs.length) { el.innerHTML='<p style="color:#a0aec0">暂无消息</p>'; return; }
    el.innerHTML = msgs.map(m => {
      const avHtml = m.avatar && m.avatar.length > 50
        ? `<div class="av"><img src="data:image/png;base64,${m.avatar}"></div>`
        : `<div class="av">${esc(m.avatar || m.username.charAt(0).toUpperCase())}</div>`;
      return `<div style="display:flex;align-items:flex-start;gap:10px;padding:8px;border-radius:8px;background:#161824">
        ${avHtml}
        <div style="flex:1;min-width:0">
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:2px">
            <strong style="font-size:13px">${esc(m.username)}</strong>
            <span style="color:#a0aec0;font-size:11px">${fmtTs(m.ts)}</span>
            <span style="flex:1"></span>
            <button class="btn-danger btn-sm" onclick="delChat(${m.id})">删除</button>
          </div>
          <div style="color:#c8ccff;word-break:break-word">${esc(m.content)}</div>
        </div>
      </div>`;
    }).join('');
  } catch(e) { toast('加载失败: '+e.message, true); }
}

async function delChat(id) {
  if (!confirm('确认删除该消息？')) return;
  try { await api('DELETE', `/api/chat/${id}`); toast('已删除'); loadChat(); }
  catch(e) { toast(e.message, true); }
}

// ── FORUM ─────────────────────────────────────────────────────────────────────
let forumPage = 1;
async function loadForum(page=1) {
  forumPage = page;
  document.getElementById('forumList').style.display='block';
  document.getElementById('forumDetail').style.display='none';
  try {
    const d = await api('GET', `/api/forum/posts?page=${page}`);
    const tbody = document.getElementById('forumTbody');
    tbody.innerHTML = (d.posts||[]).map(p => {
      const avHtml = p.avatar && p.avatar.length > 50
        ? `<div class="av" style="width:24px;height:24px;font-size:10px;display:inline-flex"><img src="data:image/png;base64,${p.avatar}"></div>`
        : `<div class="av" style="width:24px;height:24px;font-size:10px;display:inline-flex">${esc(p.avatar||p.author.charAt(0).toUpperCase())}</div>`;
      return `<tr>
        <td>${p.id}</td>
        <td style="max-width:320px;white-space:normal"><a href="#" onclick="viewPost(${p.id})" style="color:#7c83ff">${esc(p.title)}</a></td>
        <td style="display:flex;align-items:center;gap:6px">${avHtml} ${esc(p.author)}</td>
        <td>${p.replies}</td>
        <td>${fmtTs(p.created_at)}</td>
        <td><button class="btn-danger btn-sm" onclick="delPost(${p.id})">删除</button></td>
      </tr>`;
    }).join('');
    renderPagination('forumPagination', d.page, Math.ceil(d.total/20), loadForum);
  } catch(e) { toast('加载失败: '+e.message, true); }
}

async function viewPost(pid) {
  document.getElementById('forumList').style.display='none';
  const det = document.getElementById('forumDetail');
  det.style.display='block';
  det.innerHTML='<div class="panel"><p style="color:#a0aec0">加载中…</p></div>';
  try {
    const d = await api('GET', `/api/forum/posts/${pid}`);
    const p = d.post;
    const avHtml = p.avatar && p.avatar.length > 50
      ? `<div class="av" style="width:40px;height:40px;font-size:16px"><img src="data:image/png;base64,${p.avatar}"></div>`
      : `<div class="av" style="width:40px;height:40px;font-size:16px">${esc(p.avatar||p.author.charAt(0).toUpperCase())}</div>`;
    const comments = (d.comments||[]).map(c => {
      const cav = c.avatar && c.avatar.length > 50
        ? `<div class="av" style="width:28px;height:28px;font-size:11px"><img src="data:image/png;base64,${c.avatar}"></div>`
        : `<div class="av" style="width:28px;height:28px;font-size:11px">${esc(c.avatar||c.author.charAt(0).toUpperCase())}</div>`;
      return `<div style="display:flex;gap:10px;padding:10px;border-radius:8px;background:#252840;margin-bottom:8px">
        ${cav}
        <div style="flex:1;min-width:0">
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">
            <strong style="font-size:12px">${esc(c.author)}</strong>
            <span style="color:#a0aec0;font-size:11px">${fmtTs(c.created_at)}</span>
          </div>
          <div style="color:#c8ccff;word-break:break-word;font-size:13px">${esc(c.content)}</div>
        </div>
      </div>`;
    }).join('');
    det.innerHTML = `<div class="panel">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
        <button class="btn-secondary btn-sm" onclick="loadForum(${forumPage})">← 返回列表</button>
        <button class="btn-danger btn-sm" onclick="delPost(${p.id})">🗑 删除帖子</button>
      </div>
      <div style="display:flex;gap:14px;align-items:flex-start;margin-bottom:16px">
        ${avHtml}
        <div>
          <h2>${esc(p.title)}</h2>
          <div style="color:#a0aec0;font-size:12px;margin-top:4px">${esc(p.author)} · ${fmtTs(p.created_at)}</div>
        </div>
      </div>
      <div class="post-content">${esc(p.content)}</div>
      <h3 style="margin-top:20px;margin-bottom:12px">💬 ${d.comments.length} 条回复</h3>
      ${comments || '<p style="color:#a0aec0;font-size:13px">暂无回复</p>'}
    </div>`;
  } catch(e) { det.innerHTML=`<div class="panel" style="color:#f08080">加载失败: ${e.message}</div>`; }
}

async function delPost(pid) {
  if (!confirm('确认删除该帖子及所有回复？')) return;
  try { await api('DELETE', `/api/forum/posts/${pid}`); toast('已删除'); loadForum(forumPage); }
  catch(e) { toast(e.message, true); }
}

// ── CLOUD ─────────────────────────────────────────────────────────────────────
let cloudPage = 1;
async function loadCloud(page=1) {
  cloudPage = page;
  const q = document.getElementById('cloudUserSearch').value;
  try {
    const d = await api('GET', `/admin/cloud/files?username=${encodeURIComponent(q)}&page=${page}`);
    const tbody = document.getElementById('cloudTbody');
    const files = d.files || [];

    // 按用户分组
    const groups = {};
    for (const f of files) {
      if (!groups[f.owner]) groups[f.owner] = [];
      groups[f.owner].push(f);
    }

    let html = '';
    for (const owner of Object.keys(groups).sort()) {
      const ufiles = groups[owner];
      const uBytes = ufiles.reduce((s,f)=>s+f.size, 0);
      // 用户分组标题行
      html += `<tr style="background:#161824">
        <td colspan="5" style="padding:8px 12px">
          <span style="font-weight:700;color:#7c83ff">👤 ${esc(owner)}</span>
          <span style="color:#a0aec0;font-size:12px;margin-left:10px">${ufiles.length} 个文件 · ${fmtSize(uBytes)}</span>
        </td>
      </tr>`;
      for (const f of ufiles) {
        html += `<tr>
          <td style="color:#a0aec0;padding-left:24px">└</td>
          <td title="${esc(f.filename)}">${esc(f.filename)}</td>
          <td>${fmtSize(f.size)}</td>
          <td>${fmtTs(f.created_at)}</td>
          <td style="white-space:nowrap">
            <button class="btn-success btn-sm" onclick="downloadFile('${f.id}','${esc(f.filename)}')">⬇ 下载</button>
            <button class="btn-danger btn-sm" onclick="delCloudFile('${f.id}','${esc(f.owner)}')">🗑 删除</button>
          </td>
        </tr>`;
      }
    }
    if (!html) html = `<tr><td colspan="5" style="color:#a0aec0;text-align:center;padding:20px">暂无文件</td></tr>`;
    tbody.innerHTML = html;

    renderPagination('cloudPagination', d.page||1, d.pages||1, loadCloud);
    const totalBytes = files.reduce((s,f)=>s+f.size, 0);
    document.getElementById('cloudStats').textContent =
      `共 ${d.total||files.length} 个文件 · ${Object.keys(groups).length} 位用户 · 本页合计 ${fmtSize(totalBytes)}`;
  } catch(e) { toast('加载失败: '+e.message, true); }
}

async function downloadFile(fid, fname) {
  try {
    toast('⏳ 准备下载…');
    const d = await api('GET', `/admin/cloud/download/${fid}`);
    const b64 = d.data;
    const raw = atob(b64);
    const bytes = new Uint8Array(raw.length);
    for (let i=0;i<raw.length;i++) bytes[i]=raw.charCodeAt(i);
    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download=fname; a.click();
    URL.revokeObjectURL(url);
    toast('✅ 下载完成');
  } catch(e) { toast('下载失败: '+e.message, true); }
}

async function delCloudFile(id, owner) {
  if (!confirm(`确认删除 ${owner} 的文件？`)) return;
  try { await api('DELETE', `/admin/cloud/files/${id}`); toast('已删除'); loadCloud(cloudPage); }
  catch(e) { toast(e.message, true); }
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function renderPagination(elId, page, pages, fn) {
  const el = document.getElementById(elId);
  if (!pages || pages <= 1) { el.innerHTML=''; return; }
  let html = `<button ${page<=1?'disabled':''} onclick="${fn.name}(${page-1})">‹ 上一页</button>`;
  const start = Math.max(1, page-2), end = Math.min(pages, page+2);
  if (start>1) html += `<button onclick="${fn.name}(1)">1</button>${start>2?'<span style="color:#a0aec0">…</span>':''}`;
  for (let i=start;i<=end;i++) html+=`<button class="${i===page?'active':''}" onclick="${fn.name}(${i})">${i}</button>`;
  if (end<pages) html+=`${end<pages-1?'<span style="color:#a0aec0">…</span>':''}<button onclick="${fn.name}(${pages})">${pages}</button>`;
  html += `<button ${page>=pages?'disabled':''} onclick="${fn.name}(${page+1})">下一页 ›</button>`;
  html += `<span style="color:#a0aec0;font-size:12px">第 ${page} / ${pages} 页</span>`;
  el.innerHTML = html;
}

function fmtSize(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

function fmtTs(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString('zh-CN') + ' ' + d.toLocaleTimeString('zh-CN', {hour:'2-digit',minute:'2-digit'});
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>
"""
