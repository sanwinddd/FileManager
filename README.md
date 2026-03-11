# File Manager Pro — 认证服务器

Python + FastAPI + SQLite，免费部署到 Railway。

## 接口说明

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /auth/register | 注册账户 |
| POST | /auth/login    | 登录，返回 token |
| GET  | /auth/me       | 查看自身信息（需 token）|
| POST | /auth/change-password | 修改密码（需 token）|
| GET  | /admin         | 管理后台网页 |

## 部署到 Railway（免费）

1. 注册 https://railway.app（GitHub 登录即可）
2. New Project → Deploy from GitHub repo → 选择此仓库
3. 在 Variables 面板添加：
   - SECRET_KEY = 任意随机字符串（如 `openssl rand -hex 32` 的输出）
   - ADMIN_PASSWORD = 你的管理员密码
4. 添加 Volume（持久化数据库）：
   - Storage → Add Volume → Mount Path: /app/data
   - 设置 DB_PATH=/app/data/users.db
5. 部署完成后访问 https://你的域名.railway.app/admin

## 本地运行

```bash
pip install -r requirements.txt
SECRET_KEY=test ADMIN_PASSWORD=admin123 uvicorn main:app --reload
```

访问 http://localhost:8000/admin

## App 端配置

登录界面「服务器」填写：https://你的域名.railway.app
