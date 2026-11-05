"""Application routes. Every protected action checks authoritative server state."""
import csv
import io
import json
import re
import secrets
import sqlite3

import pyotp
import qrcode
import qrcode.image.svg
from flask import Blueprint, Response, abort, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for
from markupsafe import Markup

from .behavior import FEATURES, get_model, train_profile, validate_window
from .db import audit, get_db, now, atomic
from .storage import seal, read_sample, read_profile, write_profile
from .risk import decide
from .security import consume_factor, consume_grant, decrypt_secret, digest, encrypt_secret, new_recovery_codes, password_hash, password_matches, require_stage, start_session, throttle


bp = Blueprint("web", __name__)
PURPOSES = {"session", "enroll", "train", "export", "reset", "delete", "authenticator", "passkey", "revoke_passkeys", "adapt", "candidate", "probe", "promote", "rollback"}


def auth_limit(tag, maximum=8):
    identity = str(g.user["id"]) if g.user else request.form.get("username", "").strip().lower()[:32]
    ip = request.remote_addr or "local"
    return throttle(f"{tag}:ip:{ip}", maximum * 3) and throttle(f"{tag}:account:{identity}", maximum)


def clear_account_failures(tag):
    identity = str(g.user["id"]) if g.user else request.form.get("username", "").strip().lower()[:32]
    get_db().execute("DELETE FROM limits WHERE bucket=?", (digest(f"{tag}:account:{identity}"),))


@bp.get("/")
def index():
    if g.auth and g.auth["stage"] == "active":
        return redirect(url_for("web.dashboard"))
    return render_template("index.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not auth_limit("register", 5):
            abort(429, description="Too many registration attempts. Try again in five minutes.")
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", username):
            flash("Use 3–32 lowercase letters, numbers or underscores; start with a letter.", "error")
        elif not 15 <= len(password) <= 128:
            flash("Use a password or passphrase between 15 and 128 characters.", "error")
        elif request.form.get("consent") != "yes":
            flash("Read and accept the prototype data notice to create an account.", "error")
        else:
            try:
                row = get_db().execute(
                    "INSERT INTO users(username,password_hash,totp_secret,created_at) VALUES(?,?,?,?)",
                    (username, password_hash(password), encrypt_secret(pyotp.random_base32()), now()))
            except sqlite3.IntegrityError:
                flash("That account name is unavailable. Choose another or sign in.", "error")
            else:
                start_session(row.lastrowid, "setup")
                audit("account_created", "Authenticator setup pending")
                return redirect(url_for("web.setup"))
    return render_template("register.html")


@bp.route("/setup", methods=["GET", "POST"])
@require_stage("setup")
def setup():
    secret = decrypt_secret(g.user)
    if request.method == "POST":
        if not auth_limit("setup"):
            abort(429, description="Too many code attempts. Try again in five minutes.")
        if consume_factor(g.user, request.form.get("code", ""), allow_recovery=False):
            clear_account_failures("setup")
            get_db().execute("UPDATE users SET totp_enabled=1 WHERE id=?", (g.user["id"],))
            codes = new_recovery_codes(g.user["id"])
            start_session(g.user["id"], strong=True)
            audit("authenticator_confirmed")
            return render_template("recovery.html", codes=codes)
        flash("Invalid or already used code. Wait for the next code and check your device time.", "error")
    uri = pyotp.TOTP(secret).provisioning_uri(g.user["username"], issuer_name="AuthSense Local")
    qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    return render_template("setup.html", secret=secret, qr=Markup(qr.to_string(encoding="unicode")))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not auth_limit("login", 10):
            abort(429, description="Too many sign-in attempts. Try again in five minutes.")
        username = request.form.get("username", "").strip().lower()[:32]
        password = request.form.get("password", "")[:129]
        user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if password_matches(user, password):
            clear_account_failures("login")
            start_session(user["id"], "mfa" if user["totp_enabled"] else "setup")
            return redirect(url_for("web.mfa" if user["totp_enabled"] else "web.setup"))
        flash("Sign-in failed. Check your account name and password.", "error")
    return render_template("login.html")


@bp.route("/mfa", methods=["GET", "POST"])
@require_stage("mfa")
def mfa():
    if request.method == "POST":
        if not auth_limit("mfa"):
            abort(429, description="Too many code attempts. Try again in five minutes.")
        if consume_factor(g.user, request.form.get("code", "")):
            clear_account_failures("mfa")
            start_session(g.user["id"], strong=True)
            audit("login_succeeded")
            return redirect(url_for("web.dashboard"))
        flash("Invalid or already used code. Use a new authenticator code or an unused recovery code.", "error")
    return render_template("mfa.html")


@bp.post("/logout")
def logout():
    if g.auth:
        audit("logged_out")
        get_db().execute("DELETE FROM sessions WHERE token_hash=?", (g.session_hash,))
    session.clear()
    return redirect(url_for("web.index"))


@bp.route("/verify", methods=["GET", "POST"])
@require_stage()
def verify():
    purpose = request.args.get("purpose", "session")
    if purpose not in PURPOSES:
        abort(400, description="Unknown verification purpose.")
    if request.method == "POST":
        if not auth_limit("verify", 5):
            audit("verification_throttled", "Session revoked after too many attempts")
            get_db().execute("DELETE FROM sessions WHERE token_hash=?", (g.session_hash,))
            session.clear()
            abort(429, description="Session ended after too many attempts. Sign in later.")
        valid = password_matches(g.user, request.form.get("password", "")[:129])
        if valid and consume_factor(g.user, request.form.get("code", "")):
            clear_account_failures("verify")
            start_session(g.user["id"], strong=True)
            if purpose != "session":
                get_db().execute("UPDATE sessions SET grant_scope=?,grant_until=? WHERE token_hash=?",
                                 (purpose, now() + 120, g.session_hash))
            audit("extra_verification_passed", {"purpose": purpose})
            return redirect(url_for("web.enroll" if purpose in ("enroll","adapt","probe") else "web.settings"
                                    if purpose != "session" else "web.dashboard"))
        audit("extra_verification_failed")
        flash("Verification failed. Check the password and use a fresh code.", "error")
    return render_template("verify.html", purpose=purpose)


def profile_row():
    return get_db().execute("SELECT * FROM profiles WHERE user_id=?", (g.user["id"],)).fetchone()


def progress():
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM samples s JOIN rounds r ON s.round_id=r.id "
                       "WHERE s.user_id=? AND r.completed=1 AND r.schema_version=2 AND r.purpose='enroll'", (g.user["id"],)).fetchone()[0]
    rounds = db.execute("SELECT COUNT(*) FROM rounds WHERE user_id=? AND completed=1 AND schema_version=2 AND purpose='enroll'",
                        (g.user["id"],)).fetchone()[0]
    return {"windows": count, "rounds": rounds}


@bp.get("/dashboard")
@require_stage()
def dashboard():
    p = profile_row()
    stats=None
    if p:
        try:
            get_model(read_profile(p)); stats=json.loads(p["stats"])
        except (ValueError,KeyError,TypeError):
            flash("Profile unavailable or incompatible. Use factor verification and re-enroll if necessary.","error")
    return render_template("dashboard.html", profile=p if stats else None, progress=progress(),stats=stats)


def policy_decision():
    row=get_db().execute('SELECT * FROM sessions WHERE token_hash=?',(g.session_hash,)).fetchone()
    p=profile_row(); ready=False
    if p:
        try:get_model(read_profile(p));ready=True
        except (ValueError,KeyError,TypeError):pass
    return decide(row,now=now(),model_ready=ready,model_version=p['version'] if ready else None,
                  fresh_seconds=current_app.config['FRESH_MFA_SECONDS'],ttl=current_app.config['TELEMETRY_TTL'])


def access_policy():
    d=policy_decision();return d['allowed'],d['policy_reason']


@bp.get("/api/status")
@require_stage()
def status():
    decision=policy_decision()
    db=get_db()
    db.execute('UPDATE sessions SET nonce=?,nonce_issued=? WHERE token_hash=? AND nonce_issued<?',
               (secrets.token_urlsafe(24),now(),g.session_hash,now()-90))
    row=db.execute('SELECT * FROM sessions WHERE token_hash=?',(g.session_hash,)).fetchone()
    observation=row['observation']
    if row['last_sample'] is None or now()-row['last_sample']>current_app.config['TELEMETRY_TTL']:
        observation='stale' if row['last_sample'] else 'unknown'
    return jsonify(**decision,observation=observation,must_verify=bool(row['must_verify']),
                   risk_index=row['risk_index'],reasons=json.loads(row['reasons']),nonce=row['nonce'],seq=row['sequence'],
                   trained=decision['model_version'] is not None,progress=progress(),schema_version=2,
                   collecting=bool(row['collecting']),freshness_seconds=current_app.config['TELEMETRY_TTL'])


@bp.post('/api/consent')
@require_stage()
@atomic
def consent():
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or set(data)!={'enabled'} or type(data['enabled']) is not bool:abort(400)
    enabled=int(data['enabled']);db=get_db()
    db.execute('UPDATE users SET behavior_consent=? WHERE id=?',(enabled,g.user['id']))
    if enabled:db.execute('UPDATE sessions SET collecting=1 WHERE token_hash=?',(g.session_hash,))
    else:
        db.execute("UPDATE sessions SET collecting=0,last_sample=NULL,observation='unknown' WHERE user_id=?",(g.user['id'],))
    audit('collection_enabled' if enabled else 'collection_disabled')
    return jsonify(enabled=bool(enabled))


@bp.get("/enroll")
@require_stage()
def enroll():
    requested=g.auth["grant_scope"] or request.args.get("mode")
    mode=requested if requested in ("adapt","probe") else "enroll"
    ready = g.auth["grant_scope"] == mode and g.auth["grant_until"] > now()
    return render_template("enroll.html", ready=ready, mode=mode, progress=progress())


@bp.post("/api/enroll/start")
@require_stage()
@atomic
def start_round():
    p=profile_row()
    if p:
        try:get_model(read_profile(p))
        except ValueError:pass
        else:abort(409,description='Use verified maintenance for an existing profile, or explicitly reset it.')
    if not consume_grant("enroll"):
        return jsonify(error="verification_required", next=url_for("web.verify", purpose="enroll")), 403
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM samples s JOIN rounds r ON s.round_id=r.id WHERE s.user_id=? AND r.schema_version=2 AND r.purpose='enroll'", (g.user["id"],)).fetchone()[0]
    if count >= current_app.config["MAX_TOTAL_SAMPLES"]:
        return jsonify(error="sample_limit", message="Reset the profile before collecting a new dataset."), 409
    # Remove abandoned rounds and their partial samples before opening another.
    db.execute("DELETE FROM rounds WHERE user_id=? AND completed=0", (g.user["id"],))
    round_id = secrets.token_urlsafe(20)
    db.execute("INSERT INTO rounds(id,user_id,session_hash,started_at,expires_at,schema_version) VALUES(?,?,?,?,?,2)",
               (round_id, g.user["id"], g.session_hash, now(), now() + 600))
    audit("enrollment_started")
    return jsonify(round_id=round_id, minimum=current_app.config["MIN_ROUND_SAMPLES"])


@bp.post("/api/enroll/finish")
@require_stage()
@atomic
def finish_round():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or not isinstance(payload.get("round_id"), str):
        abort(400, description="Missing enrollment round.")
    db = get_db()
    row = db.execute("SELECT * FROM rounds WHERE id=? AND user_id=? AND session_hash=? "
                     "AND completed=0 AND expires_at>?",
                     (payload["round_id"], g.user["id"], g.session_hash, now())).fetchone()
    if row is None:
        abort(409, description="The enrollment round expired. Start a new verified round.")
    count = db.execute("SELECT COUNT(*) FROM samples WHERE round_id=?", (row["id"],)).fetchone()[0]
    if count < current_app.config["MIN_ROUND_SAMPLES"]:
        abort(400, description="Collect at least ten windows in this round.")
    db.execute("UPDATE rounds SET completed=1 WHERE id=?", (row["id"],))
    audit("enrollment_completed", {"windows": count})
    return jsonify(progress=progress())


@bp.post("/api/telemetry")
@require_stage()
@atomic
def telemetry():
    if not throttle(f"telemetry:{g.session_hash}", 30, seconds=60):
        abort(429, description="Telemetry rate exceeded. Slow down and refresh the collector.")
    if not g.auth['collecting'] or not get_db().execute('SELECT behavior_consent FROM users WHERE id=?',(g.user['id'],)).fetchone()[0]:
        abort(403,description='Enable consent-based collection first.')
    payload = request.get_json(silent=True)
    try:
        vector = validate_window(payload)
    except ValueError as error:
        get_db().execute("UPDATE sessions SET observation='invalid',last_sample=NULL WHERE token_hash=?",(g.session_hash,))
        return jsonify(error='insufficient_evidence',message=str(error)),400
    db = get_db()
    new_nonce = secrets.token_urlsafe(24)
    # A conditional update prevents reuse even under concurrent requests.
    updated = db.execute("UPDATE sessions SET nonce=?,sequence=sequence+1 WHERE token_hash=? "
                         "AND nonce=? AND sequence=? AND nonce_issued>?", (new_nonce, g.session_hash, payload["nonce"],
                         payload["seq"] - 1,now()-90)).rowcount
    if not updated:
        abort(409, description="Stale telemetry nonce or sequence. Reload collector state.")
    db.execute('UPDATE sessions SET nonce_issued=? WHERE token_hash=?',(now(),g.session_hash))
    if payload.get("round_id"):
        row = db.execute("SELECT * FROM rounds WHERE id=? AND user_id=? AND session_hash=? "
                         "AND completed=0 AND expires_at>?", (payload["round_id"], g.user["id"],
                         g.session_hash, now())).fetchone()
        if row is None:
            abort(403, description="A verified enrollment round is required.")
        count = db.execute("SELECT COUNT(*) FROM samples WHERE round_id=?", (row["id"],)).fetchone()[0]
        total = db.execute("SELECT COUNT(*) FROM samples s JOIN rounds r ON r.id=s.round_id WHERE s.user_id=? AND r.schema_version=2 AND r.purpose=?",(g.user["id"],row["purpose"])).fetchone()[0]
        limit={"enroll":current_app.config["MAX_TOTAL_SAMPLES"],"adapt":100,"probe":1000}[row["purpose"]]
        if count >= current_app.config["MAX_ROUND_SAMPLES"] or total >= limit:
            abort(409, description="Enrollment sample limit reached. Finish this round.")
        if row['purpose']=='adapt':
            if profile_row() is None or row['base_version']!=profile_row()['version'] or get_model(read_profile(profile_row())).assess(vector)['anomalous']:
                return jsonify(error='untrusted_maintenance',message='Anomalous observations cannot enter maintenance.'),400
        cursor=db.execute('INSERT INTO samples(user_id,round_id,created_at,features,schema_version) VALUES(?,?,?,?,2)',
                          (g.user['id'],row['id'],now(),''))
        encrypted=seal(dict(zip(FEATURES,vector)),'sample',g.user['id'],cursor.lastrowid)
        db.execute('UPDATE samples SET features=? WHERE id=?',(encrypted,cursor.lastrowid))
        return jsonify(nonce=new_nonce, seq=payload["seq"], enrollment_count=count + 1)
    p = profile_row()
    if p is None:
        # Valid data does not create trust before enrollment or update training data.
        return jsonify(nonce=new_nonce, seq=payload["seq"], observation="untrained")
    try:
        result = get_model(read_profile(p)).assess(vector)
    except Exception:
        current_app.logger.warning("Behavioral scoring unavailable; verification required")
        db.execute("UPDATE sessions SET observation='unavailable',last_sample=NULL WHERE token_hash=?",
                   (g.session_hash,))
        return jsonify(nonce=new_nonce, seq=payload["seq"], observation="unavailable"), 503
    # Serial requests from the collector; state transition itself is atomic.
    row = db.execute(
        "UPDATE sessions SET strikes=CASE WHEN ? THEN strikes+1 ELSE 0 END, "
        "must_verify=CASE WHEN ? AND strikes>=1 THEN 1 ELSE must_verify END, "
        "step_up_required=CASE WHEN ? THEN 1 ELSE step_up_required END, "
        "observation=?,risk_index=?,reasons=?,last_sample=?,last_model_version=? WHERE token_hash=? RETURNING *",
        (result["anomalous"], result["anomalous"], result["anomalous"], "unusual" if result["anomalous"] else "normal",
         result["risk_index"], json.dumps(result["reasons"]), now(), p["version"], g.session_hash)).fetchone()
    if result["anomalous"]:
        audit("behavioral_anomaly", {"risk_index": result["risk_index"], "verification_required": bool(row["must_verify"])})
    return jsonify(nonce=new_nonce, seq=payload["seq"], observation=row["observation"],
                   risk_index=result["risk_index"], must_verify=bool(row["must_verify"]))


@bp.get("/settings")
@require_stage()
def settings():
    grant = g.auth["grant_scope"] if g.auth["grant_until"] > now() else None
    return render_template("settings.html", grant=grant, progress=progress(), profile=profile_row(),versions=get_db().execute("SELECT version FROM profile_versions WHERE user_id=? ORDER BY version DESC",(g.user["id"],)).fetchall())


@bp.post("/model/train")
@require_stage()
@atomic
def train():
    if not consume_grant("train"):
        return redirect(url_for("web.verify", purpose="train"))
    rows = get_db().execute("SELECT s.* FROM samples s JOIN rounds r ON r.id=s.round_id "
                            "WHERE s.user_id=? AND r.completed=1 AND r.schema_version=2 AND r.purpose='enroll' ORDER BY s.id", (g.user["id"],)).fetchall()
    try:
        payload, stats = train_profile([{"session_id": row["round_id"], "features": read_sample(row)}
                                        for row in rows], current_app.config["MIN_SAMPLES"], current_app.config["MIN_ROUNDS"],
                hash_key=current_app.extensions["feature_alias_key"],profile_id=str(g.user["id"]))
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("web.settings"))
    if profile_row():
        try:get_model(read_profile(profile_row()))
        except ValueError:pass
        else:abort(409,description='A trusted profile requires guarded maintenance, not retraining from live data.')
    write_profile(g.user['id'],payload,stats)
    audit("profile_trained", stats)
    flash("Profile trained. Turn on the dashboard collector to observe new windows.", "success")
    return redirect(url_for("web.dashboard"))


@bp.post("/vault/open")
@require_stage()
@atomic
def vault():
    from .passkeys import consume_vault_grant
    if consume_vault_grant():
        audit("protected_action_allowed", {"basis":"one_use_passkey","action":"vault"})
        return render_template("vault.html",allowed=True,reason="One-use passkey verification for this action")
    allowed, reason = access_policy()
    if not allowed:
        audit("protected_action_denied", policy_decision())
        return render_template("vault.html", allowed=False, reason=reason), 403
    audit("protected_action_allowed", policy_decision())
    return render_template("vault.html", allowed=True, reason=reason)


@bp.get("/audit")
@require_stage()
def audit_page():
    events = get_db().execute("SELECT * FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 100",
                              (g.user["id"],)).fetchall()
    return render_template("audit.html", events=events)


@bp.post("/data/export")
@require_stage()
def export():
    if not consume_grant("export"):
        return redirect(url_for("web.verify", purpose="export"))
    dataset=request.form.get("dataset","enroll")
    if dataset not in ("enroll","probe"):abort(400,description="Unknown export dataset.")
    rows = get_db().execute("SELECT s.* FROM samples s JOIN rounds r ON r.id=s.round_id "
                            "WHERE s.user_id=? AND r.completed=1 AND r.schema_version=2 AND r.purpose=? ORDER BY s.id", (g.user["id"],dataset)).fetchall()
    output = io.StringIO(newline="")
    if request.form.get("latest_only") == "yes" and rows:
        latest = rows[-1]["round_id"]
        rows = [row for row in rows if row["round_id"] == latest]
    writer = csv.DictWriter(output, fieldnames=["session_id", *FEATURES])
    writer.writeheader()
    for row in rows:
        writer.writerow({"session_id": row["round_id"], **read_sample(row)})
    audit("profile_data_exported", {"windows": len(rows)})
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="authsense-{dataset}.csv"'})


@bp.post("/profile/reset")
@require_stage()
def reset():
    if not consume_grant("reset"):
        return redirect(url_for("web.verify", purpose="reset"))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("DELETE FROM profiles WHERE user_id=?", (g.user["id"],))
        for table in ('profile_versions','candidates','validation_sets'):
            db.execute('DELETE FROM '+table+' WHERE user_id=?',(g.user['id'],))
        db.execute("DELETE FROM rounds WHERE user_id=?", (g.user["id"],))
        db.execute("UPDATE sessions SET observation='unknown',last_sample=NULL,must_verify=1 WHERE user_id=?",
                   (g.user["id"],))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    get_model.cache_clear()
    start_session(g.user["id"], strong=True)
    audit("profile_reset")
    flash("Behavioral data deleted. Account authentication remains active.", "success")
    return redirect(url_for("web.dashboard"))


@bp.post("/account/delete")
@require_stage()
def delete():
    if not consume_grant("delete"):
        return redirect(url_for("web.verify", purpose="delete"))
    get_db().execute("DELETE FROM users WHERE id=?", (g.user["id"],))
    get_model.cache_clear()
    session.clear()
    flash("Account and its associated application records deleted.", "success")
    return redirect(url_for("web.index"))


@bp.post("/account/authenticator")
@require_stage()
def replace_authenticator():
    if not consume_grant("authenticator"):
        return redirect(url_for("web.verify", purpose="authenticator"))
    user_id = g.user["id"]
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("UPDATE users SET totp_secret=?,totp_enabled=0,last_totp_counter=-1 WHERE id=?",
                   (encrypt_secret(pyotp.random_base32()), user_id))
        db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    start_session(user_id, "setup")
    audit("authenticator_replacement_started")
    return redirect(url_for("web.setup"))


@bp.post('/api/probes/start')
@require_stage()
@atomic
def start_probe():
    if not consume_grant('probe'):return jsonify(error='verification_required'),403
    db=get_db();db.execute("DELETE FROM rounds WHERE user_id=? AND purpose='probe' AND completed=0",(g.user['id'],))
    rid=secrets.token_urlsafe(20)
    db.execute("INSERT INTO rounds(id,user_id,session_hash,started_at,expires_at,purpose,schema_version) VALUES(?,?,?,?,?,'probe',2)",
        (rid,g.user['id'],g.session_hash,now(),now()+600))
    audit('evaluation_probe_started')
    return jsonify(round_id=rid,minimum=10)
