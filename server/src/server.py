# server_merged.py
# 合并版本：整合了两个文件的功能和安全修复
# 包含完整的API功能、Web界面支持和安全增强

import os
import io
import json
import uuid
import hashlib
import pathlib
import secrets
import tempfile
import mimetypes
from contextlib import contextmanager
from typing import Optional, Callable
from datetime import datetime, timezone
from functools import wraps
from importlib import util as importlib_util

from flask import Flask, jsonify, request, g, send_file, current_app, render_template, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from rmap_routes import rmap_bp

# 数据库支持：同时支持PyMySQL和SQLAlchemy
try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import IntegrityError
    HAS_SQLALCHEMY = True
except ImportError:
    import pymysql
    HAS_SQLALCHEMY = False

# Pickle支持
try:
    import dill as _pickle
except ImportError:
    import pickle as _pickle

# 水印工具导入
import watermarking_utils as WMUtils
try:
    from watermarking_method import WatermarkingMethod
except ImportError:
    WatermarkingMethod = object  # fallback

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
def create_app():
    app = Flask(__name__)
    
    #WJJ: REGISTER RMAP BLUEPRINT
    app.register_blueprint(rmap_bp, url_prefix="/rmap")

    # --- 安全配置 ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
    if not app.config["SECRET_KEY"]:
        raise ValueError("SECRET_KEY environment variable is required")
    
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))
    app.config["MAX_UPLOAD_MB"] = int(os.environ.get("MAX_UPLOAD_MB", "20"))

    # --- 数据库配置 ---
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "127.0.0.1")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    # --- 存储配置 ---
    app.config["STORAGE_DIR"] = pathlib.Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    
    # 创建存储目录
    storage_dir = app.config["STORAGE_DIR"]
    for subdir in ("files", "versions", "public", "tmp", "documents"):
        (storage_dir / subdir).mkdir(parents=True, exist_ok=True)

    # 禁用动态插件加载以防止RCE
    DYNAMIC_PLUGIN_LOADING = False

    # -----------------------------------------------------------------------------
    # 数据库连接 - 双重支持
    # -----------------------------------------------------------------------------
    if HAS_SQLALCHEMY:
        def db_url() -> str:
            return (
                f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
                f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}"
                f"?charset=utf8mb4&ssl_disabled=true"
            )

        def get_engine():
            eng = app.config.get("_ENGINE")
            if eng is None:
                eng = create_engine(
                    db_url(),
                    pool_pre_ping=True,
                    future=True,
                    connect_args={"ssl": {"disabled": True}},
                )
                app.config["_ENGINE"] = eng
            return eng
        
        def db_connect():
            return get_engine().connect()
        
        def db_begin():
            return get_engine().begin()
    else:
        @contextmanager
        def db_connect():
            conn = pymysql.connect(
                host=app.config["DB_HOST"],
                port=app.config["DB_PORT"],
                user=app.config["DB_USER"],
                password=app.config["DB_PASSWORD"],
                database=app.config["DB_NAME"],
                charset="utf8mb4",
                cursorclass=pymysql.cursors.Cursor,
                autocommit=False,
            )
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    # -----------------------------------------------------------------------------
    # 认证和权限控制
    # -----------------------------------------------------------------------------
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _version_serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-version")

    def _extract_bearer_token() -> Optional[str]:
        auth = request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        # 也检查Cookie
        return request.cookies.get("auth_token")

    def _verify_token(token: str) -> Optional[dict]:
        try:
            data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            if not isinstance(data, dict) or "uid" not in data:
                return None
            return data
        except (BadSignature, SignatureExpired):
            return None

    def require_auth(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return jsonify({"error": "unauthorized"}), 401
            data = _verify_token(token)
            if not data:
                return jsonify({"error": "unauthorized"}), 401
            
            g.user = {
                "id": int(data["uid"]),
                "login": data.get("login"),
                "email": data.get("email"),
                "roles": data.get("roles", [])
            }
            return fn(*args, **kwargs)
        return wrapper

    def require_auth_web(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return redirect(url_for("page_login"))
            
            data = _verify_token(token)
            if not data:
                return redirect(url_for("page_login"))
            
            g.user = {
                "id": int(data["uid"]),
                "login": data.get("login"),
                "email": data.get("email"),
                "roles": data.get("roles", [])
            }
            return view(*args, **kwargs)
        return wrapper

    def require_admin(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            roles = (g.user or {}).get("roles", [])
            if "admin" not in roles:
                return jsonify({"error": "admin_only"}), 403
            return f(*args, **kwargs)
        return wrapper

    # -----------------------------------------------------------------------------
    # 安全工具函数
    # -----------------------------------------------------------------------------
    def _safe_resolve_under_storage(p: str, storage_root: pathlib.Path) -> pathlib.Path:
        """安全路径解析，防止路径遍历攻击"""
        storage_root = storage_root.resolve()
        fp = pathlib.Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        try:
            fp.relative_to(storage_root)
        except ValueError:
            raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    def _is_pdf_bytes(b: bytes) -> bool:
        """增强的PDF验证"""
        if len(b) < 5:
            return False
        # 检查PDF头部标识
        if not b.startswith(b"%PDF-"):
            return False
        # 简单的PDF结构验证
        if b"trailer" not in b or b"startxref" not in b:
            return False
        return True

    def _save_pdf_and_hash(data: bytes) -> tuple[pathlib.Path, str]:
        """安全保存PDF并计算哈希"""
        if not _is_pdf_bytes(data):
            raise ValueError("Invalid PDF data")
        
        sha = hashlib.sha256(data).hexdigest()
        filename = f"{sha}.pdf"
        storage_dir = app.config["STORAGE_DIR"]
        out_path = storage_dir / "files" / filename
        
        if not out_path.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
        return out_path, sha

    def _rel_storage_path(p: pathlib.Path) -> str:
        """返回相对于存储根目录的POSIX路径"""
        return str(p.relative_to(app.config["STORAGE_DIR"])).replace("\\", "/")

    # -----------------------------------------------------------------------------
    # 水印处理 - 增强版本
    # -----------------------------------------------------------------------------
    def _wm_table():
        """获取水印方法表"""
        try:
            return WMUtils.METHODS
        except AttributeError:
            return getattr(WMUtils, "METHODS", {})

    def _apply_watermark(method_obj, infile: str, outfile: str, *,
                         position: str = "eof",
                         secret: Optional[str] = None,
                         key: Optional[str] = None):
        """安全的水印应用"""
        # 首选：add_watermark方法
        if hasattr(method_obj, "add_watermark"):
            fn = getattr(method_obj, "add_watermark")
            with open(infile, "rb") as f:
                data = f.read()
            
            # 尝试不同的参数组合
            for params in [
                {"secret": secret, "key": key, "position": position},
                {"secret": secret, "position": position},
                {"secret": secret},
            ]:
                if all(v is not None for v in params.values()):
                    try:
                        out = fn(data, **params)
                        if isinstance(out, (bytes, bytearray)):
                            with open(outfile, "wb") as g:
                                g.write(out)
                            return
                    except Exception:
                        continue
        
        # 备选方法
        for name in ("embed", "apply", "run", "process", "watermark"):
            if hasattr(method_obj, name):
                fn = getattr(method_obj, name)
                try:
                    fn(infile, outfile, position=position)
                    return
                except Exception:
                    try:
                        fn(infile, outfile)
                        return
                    except Exception:
                        continue
        
        raise RuntimeError("Unsupported watermark method API")

    # -----------------------------------------------------------------------------
    # 路由：健康检查和基础
    # -----------------------------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        try:
            if HAS_SQLALCHEMY:
                with get_engine().connect() as conn:
                    conn.execute(text("SELECT 1"))
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT 1")
                    cur.fetchone()
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # -----------------------------------------------------------------------------
    # 路由：用户管理
    # -----------------------------------------------------------------------------
    @app.post("/api/create-user")
    def create_user():
        """创建用户账户 - 使用安全密码哈希"""
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            payload = request.form.to_dict()

        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""

        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        # 使用werkzeug的安全密码哈希而不是简单的SHA-256
        hpw = generate_password_hash(password)

        try:
            if HAS_SQLALCHEMY:
                with db_begin() as conn:
                    res = conn.execute(
                        text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                        {"email": email, "hpw": hpw, "login": login},
                    )
                    uid = int(res.lastrowid)
                    row = conn.execute(
                        text("SELECT id, email, login FROM Users WHERE id = :id"),
                        {"id": uid},
                    ).one()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute(
                        "INSERT INTO Users (email, hpassword, login) VALUES (%s, %s, %s)",
                        (email, hpw, login),
                    )
                    uid = conn.lastrowid
                    cur.execute("SELECT id, email, login FROM Users WHERE id = %s", (uid,))
                    row = cur.fetchone()
                    # 创建类似SQLAlchemy的结果对象
                    class Row:
                        def __init__(self, data):
                            self.id, self.email, self.login = data
                    row = Row(row)

        except Exception as e:
            # 检查是否是完整性约束错误
            if "Duplicate entry" in str(e) or "UNIQUE constraint failed" in str(e):
                return jsonify({"error": "email or login already exists"}), 409
            app.logger.exception("create_user failed")
            return jsonify({"error": "internal server error"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    @app.post("/api/login")
    def login():
        """用户登录"""
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            if HAS_SQLALCHEMY:
                with db_connect() as conn:
                    row = conn.execute(
                        text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                        {"email": email},
                    ).first()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, email, login, hpassword FROM Users WHERE email = %s LIMIT 1", (email,))
                    row_data = cur.fetchone()
                    if row_data:
                        class Row:
                            def __init__(self, data):
                                self.id, self.email, self.login, self.hpassword = data
                        row = Row(row_data)
                    else:
                        row = None

        except Exception:
            app.logger.exception("Login query failed")
            return jsonify({"error": "internal server error"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({
            "uid": int(row.id),
            "login": row.login,
            "email": row.email,
            "roles": []  # 可以从数据库查询用户角色
        })
        
        return jsonify({
            "token": token,
            "token_type": "bearer",
            "expires_in": app.config["TOKEN_TTL_SECONDS"]
        }), 200

    @app.post("/auth/session")
    def auth_session():
        """设置会话Cookie"""
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "token required"}), 400
        
        resp = jsonify({"ok": True})
        resp.set_cookie("auth_token", token,
                        httponly=True,
                        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
                        samesite=os.getenv("COOKIE_SAMESITE", "Lax"))
        return resp, 200

    @app.post("/logout")
    def logout():
        """用户登出"""
        resp = jsonify({"ok": True})
        resp.delete_cookie("auth_token")
        return resp, 200

    # -----------------------------------------------------------------------------
    # 路由：文档管理
    # -----------------------------------------------------------------------------
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        """列出用户的所有文档"""
        try:
            if HAS_SQLALCHEMY:
                with db_connect() as conn:
                    rows = conn.execute(
                        text("SELECT id, name, path, size, sha256, creation FROM Documents WHERE ownerid = :uid"),
                        {"uid": int(g.user["id"])},
                    ).all()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, path, size, sha256, creation FROM Documents WHERE ownerid = %s", (int(g.user["id"]),))
                    rows = cur.fetchall()

        except Exception:
            app.logger.exception("DB error listing documents")
            return jsonify({"error": "internal server error"}), 503

        docs = []
        for row in rows:
            if HAS_SQLALCHEMY:
                sha256_val = row.sha256.hex() if isinstance(row.sha256, (bytes, bytearray)) else str(row.sha256)
                creation_val = row.creation.isoformat() if row.creation else None
            else:
                sha256_val = row[4].hex() if isinstance(row[4], (bytes, bytearray)) else str(row[4])
                creation_val = row[5].isoformat() if row[5] else None
            
            docs.append({
                "id": int(row[0] if not HAS_SQLALCHEMY else row.id),
                "name": row[1] if not HAS_SQLALCHEMY else row.name,
                "path": row[2] if not HAS_SQLALCHEMY else row.path,
                "size": int(row[3] if not HAS_SQLALCHEMY else row.size),
                "sha256": sha256_val,
                "creation": creation_val,
            })

        return jsonify({"documents": docs}), 200

    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        """上传PDF文档 - 增强安全性"""
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "no_file"}), 400

        file = request.files["file"]
        if not file or not getattr(file, "filename", ""):
            return jsonify({"ok": False, "error": "filename_missing"}), 400

        # 安全文件名处理
        original_name = secure_filename(file.filename)
        display_name = secure_filename(request.form.get("name", "")) or original_name

        # MIME类型验证
        allowed_mimes = {"application/pdf"}
        mime = file.mimetype or mimetypes.guess_type(original_name)[0] or "application/octet-stream"
        if mime not in allowed_mimes:
            return jsonify({"ok": False, "error": "unsupported_media_type"}), 415

        # 文件大小限制
        max_bytes = app.config["MAX_UPLOAD_MB"] * 1024 * 1024
        storage_root = app.config["STORAGE_DIR"]
        docs_dir = storage_root / "documents" / str(int(g.user["id"]))
        tmp_dir = storage_root / "tmp"
        
        docs_dir.mkdir(parents=True, exist_ok=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # 流式读取并验证
        sha256_hash = hashlib.sha256()
        total_size = 0
        chunks = []

        try:
            while True:
                chunk = file.stream.read(1024 * 1024)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_bytes:
                    return jsonify({"ok": False, "error": "payload_too_large", "limit_mb": app.config["MAX_UPLOAD_MB"]}), 413
                sha256_hash.update(chunk)
                chunks.append(chunk)

            # 合并所有chunk
            raw_data = b''.join(chunks)
            
            # PDF格式验证
            if not _is_pdf_bytes(raw_data):
                return jsonify({"ok": False, "error": "invalid_pdf"}), 400

        except Exception:
            app.logger.exception("upload: file processing failed")
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # 保存文件
        digest = sha256_hash.hexdigest()
        base = display_name.rsplit(".", 1)[0] if "." in display_name else display_name
        base = base or "document"
        unique = f"{uuid.uuid4().hex}_{base}.pdf"
        final_path = docs_dir / unique
        rel_path = final_path.relative_to(storage_root).as_posix()

        try:
            final_path.write_bytes(raw_data)
        except Exception:
            app.logger.exception("upload: write file failed")
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # 插入数据库
        try:
            if HAS_SQLALCHEMY:
                with db_begin() as conn:
                    res = conn.execute(
                        text("""
                            INSERT INTO Documents (name, path, ownerid, sha256, size)
                            VALUES (:name, :path, :ownerid, :sha256, :size)
                        """),
                        {
                            "name": display_name,
                            "path": rel_path,
                            "ownerid": int(g.user["id"]),
                            "sha256": bytes.fromhex(digest),
                            "size": int(total_size),
                        },
                    )
                    doc_id = getattr(res, "lastrowid", None) or conn.execute(text("SELECT LAST_INSERT_ID()")).scalar()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute(
                        "INSERT INTO Documents (name, path, ownerid, sha256, size) VALUES (%s, %s, %s, %s, %s)",
                        (display_name, rel_path, int(g.user["id"]), bytes.fromhex(digest), int(total_size)),
                    )
                    doc_id = conn.lastrowid

        except Exception:
            app.logger.exception("upload: db insert failed")
            try:
                final_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"ok": False, "error": "internal_error"}), 500

        return jsonify({
            "ok": True,
            "id": int(doc_id),
            "name": display_name,
            "path": rel_path,
            "size": total_size,
            "sha256": digest,
        }), 201

    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int):
        """获取文档文件"""
        try:
            if HAS_SQLALCHEMY:
                with db_connect() as conn:
                    row = conn.execute(
                        text("SELECT id, name, path FROM Documents WHERE id=:id AND ownerid=:uid"),
                        {"id": document_id, "uid": int(g.user["id"])},
                    ).first()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, path FROM Documents WHERE id=%s AND ownerid=%s", (document_id, int(g.user["id"])))
                    row_data = cur.fetchone()
                    if row_data:
                        class Row:
                            def __init__(self, data):
                                self.id, self.name, self.path = data
                        row = Row(row_data)
                    else:
                        row = None

        except Exception:
            app.logger.exception("get_document query failed")
            return jsonify({"error": "internal server error"}), 503

        if not row:
            return jsonify({"error": "not_found"}), 404

        storage_root = app.config["STORAGE_DIR"]
        file_path = _safe_resolve_under_storage(row.path, storage_root)
        if not file_path.exists():
            return jsonify({"error": "gone"}), 410

        return send_file(file_path, mimetype="application/pdf",
                        as_attachment=False, download_name=row.name)

    @app.delete("/api/delete-document/<int:document_id>")
    @require_auth
    def delete_document(document_id: int):
        """删除文档及其版本"""
        uid = int(g.user["id"])
        storage_root = app.config["STORAGE_DIR"]

        try:
            if HAS_SQLALCHEMY:
                with db_begin() as conn:
                    doc = conn.execute(
                        text("SELECT id, path FROM Documents WHERE id=:id AND ownerid=:uid"),
                        {"id": document_id, "uid": uid},
                    ).first()
                    if not doc:
                        return jsonify({"error": "not_found"}), 404

                    vers = conn.execute(
                        text("SELECT path FROM Versions WHERE documentid=:did"),
                        {"did": int(document_id)},
                    ).all()

                    conn.execute(text("DELETE FROM Versions WHERE documentid=:did"), {"did": int(document_id)})
                    conn.execute(text("DELETE FROM Documents WHERE id=:id AND ownerid=:uid"), {"id": int(document_id), "uid": uid})
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, path FROM Documents WHERE id=%s AND ownerid=%s", (document_id, uid))
                    doc_data = cur.fetchone()
                    if not doc_data:
                        return jsonify({"error": "not_found"}), 404
                    
                    class Doc:
                        def __init__(self, data):
                            self.id, self.path = data
                    doc = Doc(doc_data)

                    cur.execute("SELECT path FROM Versions WHERE documentid=%s", (int(document_id),))
                    vers_data = cur.fetchall()
                    class Ver:
                        def __init__(self, data):
                            self.path = data[0]
                    vers = [Ver(v) for v in vers_data]

                    cur.execute("DELETE FROM Versions WHERE documentid=%s", (int(document_id),))
                    cur.execute("DELETE FROM Documents WHERE id=%s AND ownerid=%s", (int(document_id), uid))

            # 清理磁盘文件
            try:
                pathlib.Path(_safe_resolve_under_storage(doc.path, storage_root)).unlink(missing_ok=True)
            except Exception:
                app.logger.warning("delete_document: failed to remove main file")
            
            for v in vers:
                try:
                    pathlib.Path(_safe_resolve_under_storage(v.path, storage_root)).unlink(missing_ok=True)
                except Exception:
                    pass

        except Exception:
            app.logger.exception("delete_document failed")
            return jsonify({"error": "internal server error"}), 503

        return jsonify({"ok": True}), 200

    # -----------------------------------------------------------------------------
    # 路由：水印管理
    # -----------------------------------------------------------------------------
    @app.get("/api/get-watermarking-methods")
    @require_auth
    def get_watermarking_methods():
        """获取可用的水印方法"""
        methods = []
        for name, inst in _wm_table().items():
            desc = ""
            try:
                desc = getattr(inst, "description", "") or inst.get_usage()
            except Exception:
                desc = ""
            methods.append({"name": name, "description": desc})
        return jsonify({"methods": methods}), 200

    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        """列出文档的所有版本"""
        if document_id is None:
            payload = request.get_json(silent=True) or {}
            try:
                document_id = int(payload.get("id") or 0)
            except Exception:
                return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400

        if not document_id:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400

        uid = int(g.user["id"])

        try:
            if HAS_SQLALCHEMY:
                with db_connect() as conn:
                    rows = conn.execute(
                        text("""
                            SELECT
                                v.id,
                                v.documentid,
                                v.link,
                                v.intended_for,
                                v.method,
                                v.position,
                                v.path,
                                CASE WHEN v.secret IS NULL THEN 0 ELSE 1 END AS has_secret
                            FROM Users u
                            JOIN Documents d ON d.ownerid = u.id
                            JOIN Versions v ON d.id = v.documentid
                            WHERE u.id = :uid
                            AND d.id = :did
                            ORDER BY v.id DESC
                        """),
                        {"uid": uid, "did": int(document_id)},
                    ).all()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT
                            v.id,
                            v.documentid,
                            v.link,
                            v.intended_for,
                            v.method,
                            v.position,
                            v.path,
                            CASE WHEN v.secret IS NULL THEN 0 ELSE 1 END AS has_secret
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.id = %s AND d.id = %s
                        ORDER BY v.id DESC
                    """, (uid, int(document_id)))
                    rows = cur.fetchall()

        except Exception:
            app.logger.exception("DB error listing versions")
            return jsonify({"ok": False, "error": "internal_error"}), 500

        versions = []
        for r in rows:
            if HAS_SQLALCHEMY:
                versions.append({
                    "id": int(r.id),
                    "documentid": int(r.documentid),
                    "link": r.link,
                    "intended_for": r.intended_for,
                    "has_secret": bool(getattr(r, "has_secret", 0)),
                    "method": r.method,
                    "position": r.position,
                    "path": r.path,
                })
            else:
                versions.append({
                    "id": int(r[0]),
                    "documentid": int(r[1]),
                    "link": r[2],
                    "intended_for": r[3],
                    "method": r[4],
                    "position": r[5],
                    "path": r[6],
                    "has_secret": bool(r[7]),
                })

        return jsonify({
            "ok": True,
            "documentid": int(document_id),
            "count": len(versions),
            "versions": versions,
        }), 200

    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        """创建水印版本 - 增强安全性"""
        payload = request.get_json(silent=True) or {}
        method = (payload.get("method") or "").strip()
        position = payload.get("position") or None
        
        # 密文参数
        secret = payload.get("secret")
        if secret is None:
            secret = payload.get("key")
        
        intended_for = (payload.get("intended_for") or "").strip() or None

        # 参数验证
        try:
            doc_id = int(document_id or payload.get("id") or 0)
        except Exception:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400

        if not doc_id:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400
        if not isinstance(method, str) or not method:
            return jsonify({"ok": False, "error": "bad_request", "detail": "method_required"}), 400
        if not isinstance(secret, str) or not secret:
            return jsonify({"ok": False, "error": "bad_request", "detail": "secret_required"}), 400

        # 获取文档（带owner校验）
        try:
            if HAS_SQLALCHEMY:
                with db_connect() as conn:
                    row = conn.execute(
                        text("SELECT id, name, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                        {"id": doc_id, "uid": int(g.user["id"])},
                    ).first()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, path FROM Documents WHERE id = %s AND ownerid = %s", (doc_id, int(g.user["id"])))
                    row_data = cur.fetchone()
                    if row_data:
                        class Row:
                            def __init__(self, data):
                                self.id, self.name, self.path = data
                        row = Row(row_data)
                    else:
                        row = None

        except Exception:
            app.logger.exception("DB error create_watermark (doc_id=%s, user=%s)", doc_id, g.user.get("id"))
            return jsonify({"ok": False, "error": "internal_error"}), 500

        if not row:
            return jsonify({"ok": False, "error": "not_found"}), 404

        # 原文件存在性检查
        src_path = _safe_resolve_under_storage(row.path, app.config["STORAGE_DIR"])
        if not src_path.exists():
            return jsonify({"ok": False, "error": "gone"}), 410

        # 生成水印
        try:
            wm_bytes = WMUtils.apply_watermark(
                method=method,
                pdf=str(src_path),
                secret=secret,
                position=position
            )
        except KeyError:
            app.logger.warning("create_watermark unknown method: %s", method)
            return jsonify({"ok": False, "error": "bad_request", "detail": "unknown_method"}), 400
        except ValueError:
            app.logger.warning("create_watermark bad params (doc_id=%s, method=%s)", doc_id, method)
            return jsonify({"ok": False, "error": "bad_request"}), 400
        except Exception:
            app.logger.exception("create_watermark unexpected failure (doc_id=%s)", doc_id)
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # 保存新版本文件
        try:
            versions_dir = app.config["STORAGE_DIR"] / "versions" / str(doc_id)
            versions_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            out_name = f"{stamp}_{method}.pdf"
            out_path = versions_dir / out_name

            with open(out_path, "wb") as f:
                f.write(wm_bytes)

            rel_out_path = out_path.relative_to(app.config["STORAGE_DIR"]).as_posix()
        except Exception:
            app.logger.exception("create_watermark write file failed (doc_id=%s)", doc_id)
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # 写Versions表
        link_token = secrets.token_urlsafe(24)
        try:
            if HAS_SQLALCHEMY:
                with db_begin() as conn:
                    res = conn.execute(
                        text("""
                            INSERT INTO Versions
                            (documentid, link, intended_for, secret, method, position, path)
                            VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                        """),
                        {
                            "documentid": doc_id,
                            "link": link_token,
                            "intended_for": intended_for,
                            "secret": secret,
                            "method": method,
                            "position": position,
                            "path": rel_out_path,
                        },
                    )
                    vid = getattr(res, "lastrowid", None) or conn.execute(text("SELECT LAST_INSERT_ID()")).scalar()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO Versions
                        (documentid, link, intended_for, secret, method, position, path)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (doc_id, link_token, intended_for, secret, method, position, rel_out_path))
                    vid = conn.lastrowid

        except Exception:
            app.logger.exception("create_watermark DB insert version failed (doc_id=%s)", doc_id)
            return jsonify({"ok": False, "error": "internal_error"}), 500

        return jsonify({
            "ok": True,
            "vid": int(vid),
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "path": rel_out_path,
        }), 201

    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        """读取水印"""
        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        link = (payload.get("link") or "").strip() or None
        use_latest = bool(payload.get("latest"))

        # 基础校验
        try:
            doc_id = int(document_id or payload.get("id") or 0)
        except Exception:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400

        if not doc_id:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400
        if not isinstance(method, str) or not method.strip():
            return jsonify({"ok": False, "error": "bad_request", "detail": "method_required"}), 400

        # 获取文档行（校验所有权）
        try:
            if HAS_SQLALCHEMY:
                with db_connect() as conn:
                    doc_row = conn.execute(
                        text("SELECT id, name, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                        {"id": doc_id, "uid": int(g.user["id"])},
                    ).first()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, path FROM Documents WHERE id = %s AND ownerid = %s", (doc_id, int(g.user["id"])))
                    row_data = cur.fetchone()
                    if row_data:
                        class DocRow:
                            def __init__(self, data):
                                self.id, self.name, self.path = data
                        doc_row = DocRow(row_data)
                    else:
                        doc_row = None

        except Exception:
            app.logger.exception("DB error reading watermark (doc_id=%s, user=%s)", doc_id, g.user.get("id"))
            return jsonify({"ok": False, "error": "internal_error"}), 500

        if not doc_row:
            return jsonify({"ok": False, "error": "not_found"}), 404

        storage_root = app.config["STORAGE_DIR"]

        # 决定读取哪个PDF：指定版本/最新版本/原始文件
        target_path: pathlib.Path
        if link:
            try:
                if HAS_SQLALCHEMY:
                    with db_connect() as conn:
                        v = conn.execute(
                            text("""
                                SELECT v.path
                                FROM Versions v
                                JOIN Documents d ON v.documentid = d.id
                                WHERE v.link = :link AND d.ownerid = :uid
                                LIMIT 1
                            """),
                            {"link": link, "uid": int(g.user["id"])},
                        ).first()
                else:
                    with db_connect() as conn:
                        cur = conn.cursor()
                        cur.execute("""
                            SELECT v.path
                            FROM Versions v
                            JOIN Documents d ON v.documentid = d.id
                            WHERE v.link = %s AND d.ownerid = %s
                            LIMIT 1
                        """, (link, int(g.user["id"])))
                        v_data = cur.fetchone()
                        if v_data:
                            class VerRow:
                                def __init__(self, data):
                                    self.path = data[0]
                            v = VerRow(v_data)
                        else:
                            v = None
            except Exception:
                return jsonify({"ok": False, "error": "internal_error"}), 500

            if not v:
                return jsonify({"ok": False, "error": "not_found"}), 404
            target_path = _safe_resolve_under_storage(v.path, storage_root)

        elif use_latest:
            try:
                if HAS_SQLALCHEMY:
                    with db_connect() as conn:
                        v = conn.execute(
                            text("SELECT path FROM Versions WHERE documentid = :did ORDER BY id DESC LIMIT 1"),
                            {"did": doc_id},
                        ).first()
                else:
                    with db_connect() as conn:
                        cur = conn.cursor()
                        cur.execute("SELECT path FROM Versions WHERE documentid = %s ORDER BY id DESC LIMIT 1", (doc_id,))
                        v_data = cur.fetchone()
                        if v_data:
                            class VerRow:
                                def __init__(self, data):
                                    self.path = data[0]
                            v = VerRow(v_data)
                        else:
                            v = None
            except Exception:
                return jsonify({"ok": False, "error": "internal_error"}), 500

            if not v:
                return jsonify({"ok": False, "error": "not_found", "detail": "no_versions"}), 404
            target_path = _safe_resolve_under_storage(v.path, storage_root)
        else:
            # 默认读原始文档
            target_path = _safe_resolve_under_storage(doc_row.path, storage_root)

        if not target_path.exists():
            return jsonify({"ok": False, "error": "gone"}), 410

        # 真正读取
        try:
            secret = WMUtils.read_watermark(method=method, pdf=str(target_path))
        except FileNotFoundError:
            app.logger.warning("read_watermark file not found on disk: %s", target_path)
            return jsonify({"ok": False, "error": "not_found"}), 404
        except ValueError:
            app.logger.warning("read_watermark bad params (doc_id=%s, method=%s)", doc_id, method)
            return jsonify({"ok": False, "error": "bad_request"}), 400
        except Exception:
            app.logger.exception("read_watermark unexpected failure (doc_id=%s)", doc_id)
            return jsonify({"ok": False, "error": "internal_error"}), 500

        return jsonify({
            "secret": secret,
        }), 200

    @app.get("/api/get-version/<string:link>")
    @require_auth
    def get_version(link: str):
        """通过不可预测link定位版本，同时确保该版本属于当前用户"""
        try:
            if HAS_SQLALCHEMY:
                with db_connect() as conn:
                    row = conn.execute(
                        text("""
                            SELECT v.path
                            FROM Versions v
                            JOIN Documents d ON v.documentid = d.id
                            WHERE v.link = :link AND d.ownerid = :uid
                            LIMIT 1
                        """),
                        {"link": link, "uid": int(g.user["id"])},
                    ).first()
            else:
                with db_connect() as conn:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT v.path
                        FROM Versions v
                        JOIN Documents d ON v.documentid = d.id
                        WHERE v.link = %s AND d.ownerid = %s
                        LIMIT 1
                    """, (link, int(g.user["id"])))
                    row_data = cur.fetchone()
                    if row_data:
                        class Row:
                            def __init__(self, data):
                                self.path = data[0]
                        row = Row(row_data)
                    else:
                        row = None

        except Exception:
            app.logger.exception("get_version query failed")
            return jsonify({"error": "internal server error"}), 503

        if not row:
            return jsonify({"error": "not_found"}), 404

        storage_root = app.config["STORAGE_DIR"]
        file_path = _safe_resolve_under_storage(row.path, storage_root)
        if not file_path.exists():
            return jsonify({"error": "gone"}), 410

        return send_file(file_path, mimetype="application/pdf",
                        as_attachment=False, download_name=f"{link}.pdf")

    # -----------------------------------------------------------------------------
    # 路由：插件管理（高风险，需要管理员权限）
    # -----------------------------------------------------------------------------
    @app.post("/api/load-plugin")
    @require_auth
    @require_admin
    def load_plugin():
        """加载插件 - 仅管理员，高度安全化"""
        payload = request.get_json(silent=True) or {}
        filename = secure_filename((payload.get("filename") or "").strip())
        
        if not filename or not filename.endswith(".py"):
            return jsonify({"error": "Only .py files allowed"}), 400

        plugin_path = _safe_resolve_under_storage(
            pathlib.Path("files") / "plugins" / filename,
            app.config["STORAGE_DIR"]
        )
        
        if not plugin_path.exists():
            return jsonify({"error": "Plugin file does not exist"}), 404

        # 加载插件模块
        try:
            spec = importlib_util.spec_from_file_location("plugin_module", plugin_path)
            if spec is None or spec.loader is None:
                return jsonify({"error": "Cannot create plugin specification"}), 400
                
            module = importlib_util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as e:
            app.logger.exception("Plugin loading failed")
            return jsonify({"error": "Failed to load plugin", "detail": str(e)}), 500

        # 验证插件类
        plugin_cls = getattr(module, "Plugin", None)
        if not isinstance(plugin_cls, type):
            return jsonify({"error": "Plugin must define a Plugin class"}), 400
            
        if WatermarkingMethod != object and not issubclass(plugin_cls, WatermarkingMethod):
            return jsonify({"error": "Plugin class must inherit from WatermarkingMethod"}), 400

        # 注册方法
        method_name = getattr(plugin_cls, "name", plugin_cls.__name__)
        methods_table = _wm_table()
        
        if method_name in methods_table and not payload.get("overwrite"):
            return jsonify({"error": "Method already exists; enable overwrite flag"}), 409

        methods_table[method_name] = plugin_cls()
        
        app.logger.info("Plugin loaded successfully: %s -> %s", filename, method_name)
        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name
        }), 201

    # -----------------------------------------------------------------------------
    # 路由：Web页面
    # -----------------------------------------------------------------------------
    @app.get("/")
    def page_index():
        """首页"""
        return render_template("index.html")

    @app.get("/login")
    def page_login():
        """登录页"""
        return render_template("login.html")

    @app.get("/signup")
    def page_signup():
        """注册页"""
        return render_template("signup.html")

    @app.get("/documents")
    @require_auth_web
    def page_documents():
        """文档管理页"""
        return render_template("documents.html")

    # -----------------------------------------------------------------------------
    # 兼容性路由（支持旧API调用方式）
    # -----------------------------------------------------------------------------
    @app.get("/api/healthz")
    def api_healthz():
        """API健康检查 - 兼容旧版本"""
        return healthz()

    return app

# -----------------------------------------------------------------------------
# WSGI入口点
# -----------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    
    app.logger.info("Starting Tatou server on %s:%d (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug)
