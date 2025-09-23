# server.py
# Fixed by Shen 9.20:
# - Removed duplicate _safe_resolve_under_storage definition
# - Removed database error detail leaks -> return generic "internal server error"
# - list_versions no longer exposes secret -> replaced with has_secret boolean
# - get_version uses unpredictable link generation with secrets.token_urlsafe (still public for experimental use only)
# - read_watermark enforces ownerid check to prevent unauthorized access
# - load_plugin: added secure_filename and warning comment about RCE risk
# - Kept Niu's previous fixes and comments

import os
import io
import hashlib, mimetypes, tempfile
import secrets  # Shen 9.20: for unpredictable link generation
from pathlib import Path
from functools import wraps
from importlib import util as importlib_util
from uuid import uuid4
from datetime import datetime, timezone

from flask import Flask, jsonify, request, g, send_file, render_template, redirect, send_from_directory, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import pickle as _std_pickle
try:
    import dill as _pickle
except Exception:
    _pickle = _std_pickle

import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod

def require_admin(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        roles = (g.user or {}).get("roles") or []
        if "admin" not in roles:
            return jsonify({"error": "admin_only"}), 403
        return f(*args, **kwargs)
    return _wrap

def create_app():
    app = Flask(__name__)

    # --- Config ---
    # dev-secret-change-me has been removed - Niu 9.17, after flag leaked
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    def _get_web_token():
        # 先从 Cookie 取；没有就尝试 Authorization: Bearer
        auth_token = request.cookies.get("auth_token")
        if not auth_token:
            ah = request.headers.get("Authorization", "")
            if ah.lower().startswith("bearer "):
                auth_token = ah.split(" ",1)[1].strip()
        return auth_token

    def require_auth_web(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            # 先尝试 Authorization 头，兼容你调试
            auth = request.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1].strip()
            else:
                # 再从 Cookie 里取（登录后我们会把 token 写在 auth_token）
                token = request.cookies.get("auth_token")

            if not token:
                return redirect(url_for("page_login"))

            # 与 API 同样的校验逻辑（用你已有的 _serializer / TOKEN_TTL_SECONDS）
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except Exception:
                return redirect(url_for("page_login"))

            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return view(*args, **kwargs)
        return wrapper

    # === 新增：会话设置/清除（前端登录后把 token 写入 Cookie） ===
    @app.post("/auth/session")
    def auth_session():
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "token required"}), 400
        resp = jsonify({"ok": True})
        # 生产建议 secure=True；这里从环境变量控制，兼容本地调试
        resp.set_cookie("auth_token", token,
                        httponly=True,
                        secure=os.getenv("COOKIE_SECURE", "false").lower()=="true",
                        samesite=os.getenv("COOKIE_SAMESITE", "Lax"))
        return resp, 200

    
    # --- DB engine ---
    def db_url() -> str:
    # Shen 9.20: force disable SSL to avoid self-signed cert issues
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}"
            f"?charset=utf8mb4&ssl_disabled=true"
    )


    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
        # Shen 9.20: force-disable TLS at driver level to avoid self-signed cert issues
            eng = create_engine(
            db_url(),
            pool_pre_ping=True,
            future=True,
            connect_args={"ssl": {"disabled": True}},  # <- key change
        )
        app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    # Module Checked by Niu at 9.17, no issues
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # Shen 9.20: keep only one definition, removed duplicate earlier version
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        try:
            fp.relative_to(storage_root)
        except ValueError:
            raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # --- Routes ---

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception:
            # Shen 9.20: hide DB error details from response
            app.logger.exception("DB error creating user")
            return jsonify({"error": "internal server error"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        # if someone trigger error here with malicious? - Niu
        except Exception:
            # Shen 9.20: hide DB error details from response
            app.logger.exception("Login query failed")
            return jsonify({"error": "internal server error"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # GET /api/list-versions #需要检查修改
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
    # 要求提供 document_id（路径或 body），否则无法限定范围
        if document_id is None:
            # 兼容从 JSON 传递 id 的情况
            payload = request.get_json(silent=True) or {}
            try:
                document_id = int(payload.get("id") or 0)
            except Exception:
                return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400
        if not document_id:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400

        uid = int(g.user["id"])

        try:
            with get_engine().connect() as conn:
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
        except Exception:
            app.logger.exception("DB error listing versions")
            return jsonify({"ok": False, "error": "internal_error"}), 500

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "has_secret": bool(getattr(r, "has_secret", 0)),
            "method": r.method,
            "position": r.position,
            "path": r.path,
        } for r in rows]

        return jsonify({
            "ok": True,
            "documentid": int(document_id),
            "count": len(versions),
            "versions": versions,
        }), 200

    # POST /api/create-watermark 需要检查修复
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        payload = request.get_json(silent=True) or {}
        method = (payload.get("method") or "").strip()
        position = payload.get("position") or None

        # 约定：真正要嵌入的密文用 "secret" 传；兼容老参数 "key"
        secret = payload.get("secret")
        if secret is None:
            secret = payload.get("key")

        intended_for = (payload.get("intended_for") or "").strip() or None

        # 1) 参数校验
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

        # 2) 取文档（带 owner 校验）
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, name, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("DB error create_watermark (doc_id=%s, user=%s)", doc_id, g.user.get("id"))
            return jsonify({"ok": False, "error": "internal_error"}), 500
        if not row:
            return jsonify({"ok": False, "error": "not_found"}), 404

        # 3) 原文件存在性
        src_path = _safe_resolve_under_storage(row.path, Path(app.config["STORAGE_DIR"]))
        if not src_path.exists():
            return jsonify({"ok": False, "error": "gone"}), 410

        # 4) 生成水印（得到 bytes）——使用 watermarking_utils 的公有 API
        try:
            wm_bytes = WMUtils.apply_watermark(
                method=method,              # 字符串方法名
                pdf=str(src_path),          # 可传路径
                secret=secret,              # 要嵌入的密文
                position=position           # 可选位置提示
            )  # ← API 见 watermarking_utils.apply_watermark(...) 
        except KeyError:
            # 未注册的方法名
            app.logger.warning("create_watermark unknown method: %s", method)
            return jsonify({"ok": False, "error": "bad_request", "detail": "unknown_method"}), 400
        except ValueError:
            app.logger.warning("create_watermark bad params (doc_id=%s, method=%s)", doc_id, method)
            return jsonify({"ok": False, "error": "bad_request"}), 400
        except Exception:
            app.logger.exception("create_watermark unexpected failure (doc_id=%s)", doc_id)
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # 5) 落盘新版本文件
        try:
            versions_dir = Path(app.config["STORAGE_DIR"]) / "versions" / str(doc_id)
            versions_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            out_name = f"{stamp}_{method}.pdf"
            out_path = versions_dir / out_name
            with open(out_path, "wb") as f:
                f.write(wm_bytes)

            rel_out_path = out_path.relative_to(Path(app.config["STORAGE_DIR"])).as_posix()
        except Exception:
            app.logger.exception("create_watermark write file failed (doc_id=%s)", doc_id)
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # 6) 写 Versions 表 —— 按 tatou.sql 的列名
        link_token = secrets.token_urlsafe(24)   # 唯一不可预测 token（满足 UNIQUE link）
        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("""
                        INSERT INTO Versions
                        (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,  # 可为 None
                        "secret": secret,              # 存入密文本身
                        "method": method,
                        "position": position,
                        "path": rel_out_path,
                    },
                )
                vid = getattr(res, "lastrowid", None) or conn.execute(text("SELECT LAST_INSERT_ID()")).scalar()
        except Exception:
            app.logger.exception("create_watermark DB insert version failed (doc_id=%s)", doc_id)
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # 7) 成功返回：不回传二进制，也不回 secret
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

    @app.post("/api/load-plugin")
    # Remote control problem - Niu 9.17
    # RCE Re-fixed from Shen - Niu 9.23 需要检查修改
    @require_auth
    @require_admin # 添加了admin要求
    def load_plugin():
        payload = request.get_json(silent=True) or {}
        filename = secure_filename((payload.get("filename") or "").strip())
        if not filename or not filename.endswith(".py"):
            return jsonify({"error": "Only .py files allowed"}), 400

        plugin_path = _safe_resolve_under_storage(
            Path("files") / "plugins" / filename,
            Path(app.config["STORAGE_DIR"])
        )
        if not plugin_path.exists():
            return jsonify({"error": "No plugin exist"}), 404

        spec = importlib_util.spec_from_file_location("plugin_module", plugin_path)
        module = importlib_util.module_from_spec(spec)
        loader = spec.loader
        if loader is None:
            return jsonify({"error": "Cannot load plugins successfully"}), 400
        loader.exec_module(module)

        plugin_cls = getattr(module, "Plugin", None)
        if not isinstance(plugin_cls, type) or not issubclass(plugin_cls, WatermarkingMethod):
            return jsonify({"error": "Plugins must define a Plugin class and inherit from WatermarkingMethod."}), 400

        method_name = getattr(plugin_cls, "name", plugin_cls.__name__)
        if method_name in WMUtils.METHODS and not payload.get("overwrite"):
            return jsonify({"error": "The method already exists; enable overwrite."}), 409

        WMUtils.METHODS[method_name] = plugin_cls()
        return jsonify({"loaded": True, "filename": filename, "registered_as": method_name}), 201

    # 需要检查修复
    # /api/read-watermark 与 /api/read-watermark/<int:document_id>
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        payload   = request.get_json(silent=True) or {}
        method    = payload.get("method")
        position  = payload.get("position") or None
        link      = (payload.get("link") or "").strip() or None
        use_latest = bool(payload.get("latest"))

        # 1) 基础校验
        try:
            doc_id = int(document_id or payload.get("id") or 0)
        except Exception:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400
        if not doc_id:
            return jsonify({"ok": False, "error": "bad_request", "detail": "document_id_required"}), 400
        if not isinstance(method, str) or not method.strip():
            return jsonify({"ok": False, "error": "bad_request", "detail": "method_required"}), 400

        # 2) 取文档行（校验所有权）
        try:
            with get_engine().connect() as conn:
                doc_row = conn.execute(
                    text("SELECT id, name, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("DB error reading watermark (doc_id=%s, user=%s)", doc_id, g.user.get("id"))
            return jsonify({"ok": False, "error": "internal_error"}), 500

        if not doc_row:
            return jsonify({"ok": False, "error": "not_found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"])

        # 3) 决定读取哪个 PDF：指定版本 / 最新版本 / 原始文件
        target_path: Path
        if link:
            with get_engine().connect() as conn:
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
            if not v:
                return jsonify({"ok": False, "error": "not_found"}), 404
            target_path = _safe_resolve_under_storage(v.path, storage_root)
        elif use_latest:
            with get_engine().connect() as conn:
                v = conn.execute(
                    text("SELECT path FROM Versions WHERE documentid = :did ORDER BY id DESC LIMIT 1"),
                    {"did": doc_id},
                ).first()
            if not v:
                return jsonify({"ok": False, "error": "not_found", "detail": "no_versions"}), 404
            target_path = _safe_resolve_under_storage(v.path, storage_root)
        else:
            # 兼容旧用法：默认读原始文档（当前实现就是读原文件，见现有代码）:contentReference[oaicite:0]{index=0}
            target_path = _safe_resolve_under_storage(doc_row.path, storage_root)

        if not target_path.exists():
            return jsonify({"ok": False, "error": "gone"}), 410

        # 4) 真正读取
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
            "ok": True,
            "documentid": doc_id,
            "secret": secret,
        }), 200

    
     # -------------------------
    # Shen 9.21: New API routes
    # -------------------------

    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        """Return all documents owned by the authenticated user."""
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("SELECT id, name, path, size, sha256, creation FROM Documents WHERE ownerid = :uid"),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception:
            app.logger.exception("DB error listing documents")
            return jsonify({"error": "internal server error"}), 503

        docs = [
            {
                "id": int(r.id),
                "name": r.name,
                "path": r.path,
                "size": int(r.size),
                "sha256": r.sha256.hex() if isinstance(r.sha256, (bytes, bytearray)) else str(r.sha256),
                "creation": r.creation.isoformat() if r.creation else None,
            }
            for r in rows
        ]
        return jsonify({"documents": docs}), 200

    # 需要检查修复
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        """
        接收 multipart/form-data:
        - file: 要上传的 PDF 文件
        - name: (可选) 展示名，默认用上传文件名
        写入存储目录与 Documents 表，并返回新建文档的元信息。
        """
        # ---- 0) 基础校验 ----
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "bad_request", "detail": "file_missing"}), 400
        file = request.files["file"]
        if not file or not getattr(file, "filename", ""):
            return jsonify({"ok": False, "error": "bad_request", "detail": "filename_missing"}), 400

        # 允许类型（如需扩展，可把 set 改大）
        allowed_mimes = {"application/pdf"}
        original_name = secure_filename(file.filename)
        display_name = secure_filename(request.form.get("name", "")) or original_name

        # 推断 MIME
        mime = file.mimetype or mimetypes.guess_type(original_name)[0] or "application/octet-stream"
        if mime not in allowed_mimes:
            return jsonify({"ok": False, "error": "unsupported_media_type"}), 415

        # 最大体积（MB），默认 20
        max_mb = int(app.config.get("MAX_UPLOAD_MB", 20))
        max_bytes = max_mb * 1024 * 1024

        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        docs_dir = storage_root / "documents" / str(int(g.user["id"]))
        tmp_dir = storage_root / "tmp"
        docs_dir.mkdir(parents=True, exist_ok=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # ---- 1) 流式写入临时文件 + 计算 sha256 + 统计大小 ----
        sha256 = hashlib.sha256()
        total = 0
        try:
            # 用临时文件避免半写入污染目标目录
            with tempfile.NamedTemporaryFile("wb", delete=False, dir=tmp_dir) as tf:
                tmp_path = Path(tf.name)
                chunk = file.stream.read(1024 * 1024)
                while chunk:
                    total += len(chunk)
                    if total > max_bytes:
                        tf.flush(); tf.close()
                        try: tmp_path.unlink(missing_ok=True)
                        except Exception: pass
                        return jsonify({"ok": False, "error": "payload_too_large", "limit_mb": max_mb}), 413
                    sha256.update(chunk)
                    tf.write(chunk)
                    chunk = file.stream.read(1024 * 1024)
        except Exception:
            app.logger.exception("upload: write temp & hash failed")
            return jsonify({"ok": False, "error": "internal_error"}), 500

        digest = sha256.hexdigest()

        # ---- 2) 目标文件路径（按用户分目录，文件名唯一）----
        # 统一用 {uuid}_{safeName or 'document'}.pdf 的形式，避免覆盖
        base = display_name.rsplit(".", 1)[0] if "." in display_name else display_name
        base = base or "document"
        unique = f"{uuid4().hex}_{base}.pdf"
        final_path = docs_dir / unique

        # 相对路径写库（避免泄露绝对路径）
        rel_path = final_path.relative_to(storage_root).as_posix()

        # ---- 3) 将临时文件移动到最终位置 ----
        try:
            # 如果目标文件名偶然存在，换一个 uuid（极低概率）
            tries = 0
            while final_path.exists() and tries < 3:
                unique = f"{uuid4().hex}_{base}.pdf"
                final_path = docs_dir / unique
                rel_path = final_path.relative_to(storage_root).as_posix()
                tries += 1
            tmp_path.replace(final_path)
        except Exception:
            app.logger.exception("upload: move temp file failed")
            # 清理临时文件
            try: tmp_path.unlink(missing_ok=True)
            except Exception: pass
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # ---- 4) 插入数据库 ----
        # 假设 Documents 表字段: id (PK), ownerid, name, path, size, mime, sha256, created_at
        # 如果你的表结构不同，请把字段名改成你自己的
        doc_id = None
        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, :sha256, :size)
                    """),
                    {
                        "name": display_name,
                        "path": rel_path,
                        "ownerid": int(g.user["id"]),
                        # 存原始32字节，而不是hex字符串
                        "sha256": bytes.fromhex(digest),
                        "size": int(total),
                    },
                )
                doc_id = getattr(res, "lastrowid", None) or conn.execute(text("SELECT LAST_INSERT_ID()")).scalar()
        except Exception:
            app.logger.exception("upload: db insert failed, will remove file %s", final_path)
            try: final_path.unlink(missing_ok=True)
            except Exception: pass
            return jsonify({"ok": False, "error": "internal_error"}), 500

        # ---- 5) 返回 201 Created ----
        return jsonify({
            "ok": True,
            "id": int(doc_id),
            "name": display_name,
            "path": rel_path,
            "size": total,
            "sha256": digest,   # 仍可返回 hex 方便前端展示；库里存的是原始字节
        }), 201

    @app.get("/api/get-watermarking-methods")
    @require_auth
    def get_watermarking_methods():
        # 返回 {name, description} 列表；description 用方法的 get_usage() 兜底
        methods = []
        for name, inst in WMUtils.METHODS.items():
            desc = ""
            try:
                # 若实现类暴露 description 属性则使用，否则用 get_usage()
                desc = getattr(inst, "description", "") or inst.get_usage()
            except Exception:
                desc = ""
            methods.append({"name": name, "description": desc})
        return jsonify({"methods": methods}), 200


    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int):
        # 仅允许文档所有者读取
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, name, path FROM Documents WHERE id=:id AND ownerid=:uid"),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("get_document query failed")
            return jsonify({"error": "internal server error"}), 503
        if not row:
            return jsonify({"error": "not_found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"])
        file_path = _safe_resolve_under_storage(row.path, storage_root)
        if not file_path.exists():
            return jsonify({"error": "gone"}), 410

        return send_file(file_path, mimetype="application/pdf",
                        as_attachment=False, download_name=row.name)


    @app.delete("/api/delete-document/<int:document_id>")
    @require_auth
    def delete_document(document_id: int):
        uid = int(g.user["id"])
        storage_root = Path(app.config["STORAGE_DIR"])

        try:
            with get_engine().begin() as conn:
                # 校验所有权并取到主文件与版本文件
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

                # 先删版本，再删文档
                conn.execute(text("DELETE FROM Versions WHERE documentid=:did"),
                            {"did": int(document_id)})
                conn.execute(text("DELETE FROM Documents WHERE id=:id AND ownerid=:uid"),
                            {"id": int(document_id), "uid": uid})

            # 清理磁盘文件（失败不影响整体结果）
            try:
                Path(_safe_resolve_under_storage(doc.path, storage_root)).unlink(missing_ok=True)
            except Exception:
                app.logger.warning("delete_document: failed to remove main file")
            for v in vers:
                try:
                    Path(_safe_resolve_under_storage(v.path, storage_root)).unlink(missing_ok=True)
                except Exception:
                    pass

        except Exception:
            app.logger.exception("delete_document failed")
            return jsonify({"error": "internal server error"}), 503

        return jsonify({"ok": True}), 200


    @app.get("/api/get-version/<string:link>")
    @require_auth
    def get_version(link: str):
        # 通过不可预测 link 定位版本，同时确保该版本属于当前用户
        try:
            with get_engine().connect() as conn:
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
        except Exception:
            app.logger.exception("get_version query failed")
            return jsonify({"error": "internal server error"}), 503

        if not row:
            return jsonify({"error": "not_found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"])
        file_path = _safe_resolve_under_storage(row.path, storage_root)
        if not file_path.exists():
            return jsonify({"error": "gone"}), 410

        return send_file(file_path, mimetype="application/pdf",
                        as_attachment=False, download_name=f"{link}.pdf")

    @app.post("/logout")
    def logout():
        resp = jsonify({"ok": True})
        resp.delete_cookie("auth_token")
        return resp, 200

    # === 新增：页面路由 ===
    @app.get("/")
    def page_index():
        return render_template("index.html")

    @app.get("/login")
    def page_login():
        return render_template("login.html")

    @app.get("/signup")
    def page_signup():
        return render_template("signup.html")

    @app.get("/documents")
    @require_auth_web
    def page_documents():
        return render_template("documents.html")

    return app

# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", "5000"))
    # 可选：开启/关闭 debug
    app.run(host="0.0.0.0", port=port)
