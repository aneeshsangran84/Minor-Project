"""Authentication, one-use factors and server-side session state."""
import hashlib
import hmac
import re
import secrets
from functools import wraps

import pyotp
from flask import abort, current_app, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import audit, get_db, now


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    supplied = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    if not expected or not supplied or not hmac.compare_digest(expected.encode(), supplied.encode()):
        abort(400, description="The form expired or its CSRF token is missing. Reload the page.")


def load_identity():
    g.user = g.auth = None
    g.session_hash = None
    token = session.get("sid")
    if not isinstance(token, str):
        return
    token_hash = digest(token)
    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
    if row is None:
        session.pop("sid", None)
        return
    idle_limit = current_app.config["IDLE_SECONDS"]
    if row["expires_at"] <= now() or now() - row["last_activity"] > idle_limit:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        session.pop("sid", None)
        return
    g.auth = row
    g.user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    g.session_hash = token_hash
    # Polling never extends the idle lifetime.
    if request.method == "POST":
        db.execute("UPDATE sessions SET last_activity=? WHERE token_hash=?", (now(), token_hash))


def start_session(user_id, stage="active", strong=False):
    db = get_db()
    if getattr(g, "session_hash", None):
        db.execute("DELETE FROM sessions WHERE token_hash=?", (g.session_hash,))
    token = secrets.token_urlsafe(32)
    token_hash = digest(token)
    session.clear()
    session["sid"] = token
    csrf_token()
    lifetime = current_app.config["SESSION_SECONDS"] if stage == "active" else 600
    db.execute("INSERT INTO sessions(token_hash,user_id,stage,created_at,last_activity,"
               "expires_at,strong_at,nonce) VALUES(?,?,?,?,?,?,?,?)",
               (token_hash, user_id, stage, now(), now(), now() + lifetime,
                now() if strong else 0, secrets.token_urlsafe(24)))
    g.session_hash = token_hash
    g.user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    db.execute("UPDATE sessions SET nonce_issued=? WHERE token_hash=?", (now(),token_hash))
    g.auth = db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
    return token_hash


def require_stage(stage="active"):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if g.auth is None or g.auth["stage"] != stage:
                if request.path.startswith("/api/"):
                    return jsonify(error="authentication_required", next=url_for("web.login")), 401
                return redirect(url_for("web.login"))
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def throttle(bucket, maximum, seconds=300):
    """Atomic fixed-window throttle. Bucket input is hashed before persistence."""
    db = get_db()
    key = digest(bucket)
    row = db.execute(
        "INSERT INTO limits(bucket,start,count) VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET "
        "count=CASE WHEN start<=? THEN 1 ELSE count+1 END, "
        "start=CASE WHEN start<=? THEN excluded.start ELSE start END RETURNING count",
        (key, now(), now() - seconds, now() - seconds)).fetchone()
    db.execute("DELETE FROM limits WHERE start<?", (now() - 86400,))
    return row["count"] <= maximum


def password_hash(password):
    return generate_password_hash(password, method="scrypt:32768:8:1")


def password_matches(user, password):
    stored = user["password_hash"] if user else current_app.config["DUMMY_HASH"]
    return check_password_hash(stored, password) and user is not None


def encrypt_secret(secret):
    return current_app.extensions["fernet"].encrypt(secret.encode()).decode()


def decrypt_secret(user):
    return current_app.extensions["fernet"].decrypt(user["totp_secret"].encode()).decode()


def consume_factor(user, code, allow_recovery=True):
    """TOTP counter or recovery code consumed atomically, including across sessions."""
    code = code.strip()
    db = get_db()
    if re.fullmatch(r"[0-9]{6}", code):
        totp = pyotp.TOTP(decrypt_secret(user))
        counter = int(now() // 30)
        for candidate in (counter, counter - 1, counter + 1):
            if hmac.compare_digest(totp.at(candidate * 30), code):
                updated = db.execute(
                    "UPDATE users SET last_totp_counter=? WHERE id=? AND last_totp_counter<?",
                    (candidate, user["id"], candidate)).rowcount
                return updated == 1
        return False
    normalized = code.replace("-", "").lower()
    if allow_recovery and re.fullmatch(r"[0-9a-f]{32}", normalized):
        deleted = db.execute("DELETE FROM recovery_codes WHERE user_id=? AND code_hash=?",
                             (user["id"], digest(normalized))).rowcount
        if deleted:
            audit("recovery_code_used", user_id=user["id"])
        return deleted == 1
    return False


def new_recovery_codes(user_id):
    db = get_db()
    codes = [secrets.token_hex(16) for _ in range(5)]
    db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
    db.executemany("INSERT INTO recovery_codes(user_id,code_hash) VALUES(?,?)",
                   [(user_id, digest(code)) for code in codes])
    return ["-".join(code[i:i + 8] for i in range(0, 32, 8)) for code in codes]


def consume_grant(scope):
    return get_db().execute(
        "UPDATE sessions SET grant_scope=NULL, grant_until=0 WHERE token_hash=? "
        "AND grant_scope=? AND grant_until>?",
        (g.session_hash, scope, now())).rowcount == 1
