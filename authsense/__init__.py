"""Application factory with local defaults and explicit failure behavior."""
import os
import secrets
import stat
import sqlite3
import time
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException, SecurityError

from . import db, security


def local_key(path, factory):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            info=os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:
                raise RuntimeError('Key must be an owner-only regular file: '+str(path))
            value=handle.read()
            if len(value) not in (32,44):raise RuntimeError('Invalid local key length: '+str(path))
            return value
    with os.fdopen(fd, 'wb') as handle:
        value=factory();handle.write(value);handle.flush();os.fsync(handle.fileno())
    return value


def create_app(test_config=None):
    root = Path(__file__).resolve().parent.parent
    instance = Path((test_config or {}).get("INSTANCE_PATH", root / "instance"))
    if instance.is_symlink():raise RuntimeError('Instance path must not be a symlink.')
    if (instance/'authsense.sqlite3').exists():
        with sqlite3.connect(instance/'authsense.sqlite3') as existing:
            migrated=existing.execute('PRAGMA user_version').fetchone()[0]>=2
        required=('session.key','encryption.key')+ (('profiles.key','feature-alias.key') if migrated else ())
        for name in required:
            if not (instance/name).exists():raise RuntimeError('Existing database requires its original '+name)
    instance.mkdir(parents=True, exist_ok=True, mode=0o700)
    instance.chmod(0o700)
    app = Flask(__name__, instance_path=str(instance))
    app.config.update(
        SECRET_KEY=local_key(instance / "session.key", lambda: secrets.token_bytes(32)),
        DATABASE=str(instance / "authsense.sqlite3"), CLOCK=time.time,
        MAX_CONTENT_LENGTH=32768, MAX_FORM_MEMORY_SIZE=16384,
        SESSION_COOKIE_NAME="authsense", SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=False,
        TRUSTED_HOSTS=["127.0.0.1", "localhost", "[::1]"],
        SESSION_SECONDS=8 * 3600, IDLE_SECONDS=30 * 60,
        FRESH_MFA_SECONDS=120, TELEMETRY_TTL=45,
        WEBAUTHN_RP_ID="localhost", WEBAUTHN_ORIGIN="http://localhost:5000",
        MIN_SAMPLES=30, MIN_ROUNDS=3, MIN_ROUND_SAMPLES=10,
        MAX_ROUND_SAMPLES=40, MAX_TOTAL_SAMPLES=160,
        DUMMY_HASH=security.password_hash(secrets.token_urlsafe(24)),
    )
    if test_config:
        app.config.update(test_config)
    encryption_key = local_key(instance / "encryption.key", Fernet.generate_key)
    app.extensions["fernet"] = Fernet(encryption_key)
    app.extensions["profile_aead"] = AESGCM(local_key(instance / "profiles.key", lambda: secrets.token_bytes(32)))
    app.extensions["feature_alias_key"] = local_key(instance / "feature-alias.key", lambda: secrets.token_bytes(32))
    app.before_request(security.check_csrf)
    app.before_request(security.load_identity)
    app.teardown_appcontext(db.close_db)
    app.jinja_env.globals["csrf_token"] = security.csrf_token
    app.jinja_env.filters["clock"] = lambda x: time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(x))

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        # Host validation can fail before Flask has a URL adapter for templates.
        if isinstance(error, SecurityError):
            return error.get_response()
        if request.path.startswith("/api/"):
            return jsonify(error=error.name, message=error.description), error.code
        return render_template("error.html", message=error.description, code=error.code), error.code

    @app.errorhandler(500)
    def internal_error(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="server_error", message="Action unavailable. No access was granted."), 500
        return render_template("error.html", code=500,
                               message="Action unavailable. Check the local server log."), 500

    from .views import bp
    app.register_blueprint(bp)
    from .passkeys import bp as passkey_bp
    app.register_blueprint(passkey_bp)
    from .maintenance import bp as maintenance_bp
    app.register_blueprint(maintenance_bp)
    with app.app_context():
        db.init_db()
        Path(app.config["DATABASE"]).chmod(0o600)
        db.get_db().execute("DELETE FROM sessions WHERE expires_at<?", (db.now(),))
    return app
