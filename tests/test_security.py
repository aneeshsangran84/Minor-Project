import json

from authsense.db import get_db
from authsense.security import digest
from conftest import PASSWORD, code, csrf, enroll_train, post, register, verify, window


def test_csrf_and_protected_routes(client):
    assert client.post("/register", data={}).status_code == 400
    assert client.get("/api/status").status_code == 401
    assert post(client, "/api/telemetry", json={}).status_code == 401
    assert post(client, "/vault/open").status_code == 302
    csrf(client)
    assert client.post("/login", data={"csrf_token": "\u2603"}).status_code == 400


def test_setup_required_and_qr_renders(app, client):
    post(client, "/register", {"username": "alice", "password": PASSWORD, "consent": "yes"})
    assert client.get("/api/status").status_code == 401
    page = client.get("/setup")
    assert page.status_code == 200 and b"<svg" in page.data
    assert b"Content-Security-Policy" not in page.data


def test_complete_login_rotation_logout(app, client):
    register(app, client)
    with client.session_transaction() as s:
        first_sid = s["sid"]
    assert post(client, "/vault/open").status_code == 200
    post(client, "/logout")
    assert client.get("/api/status").status_code == 401
    assert post(client, "/login", {"username": "alice", "password": PASSWORD}).status_code == 302
    assert client.get("/api/status").status_code == 401
    assert post(client, "/mfa", {"code": code(app)}).status_code == 302
    with client.session_transaction() as s:
        assert s["sid"] != first_sid
    with app.app_context():
        assert get_db().execute("SELECT 1 FROM sessions WHERE token_hash=?", (digest(first_sid),)).fetchone() is None


def test_otp_replay_and_one_use_recovery(app, client):
    backups = register(app, client)
    used = code(app, advance=False)
    post(client, "/logout")
    post(client, "/login", {"username": "alice", "password": PASSWORD})
    assert post(client, "/mfa", {"code": used}).status_code == 200
    assert client.get("/api/status").status_code == 401
    assert post(client, "/mfa", {"code": backups[0]}).status_code == 302
    post(client, "/logout")
    post(client, "/login", {"username": "alice", "password": PASSWORD})
    assert post(client, "/mfa", {"code": backups[0]}).status_code == 200
    assert client.get("/api/status").status_code == 401


def test_password_validation_and_login_throttle(app, client):
    assert post(client, "/register", {"username": "alice", "password": "short", "consent": "yes"}).status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    for _ in range(10):
        assert post(client, "/login", {"username": "missing", "password": "incorrect"}).status_code == 200
    assert post(client, "/login", {"username": "missing", "password": "incorrect"}).status_code == 429


def test_stale_evidence_cannot_open_vault(app, client):
    register(app, client)
    app.test_clock[0] += 121
    assert client.get("/api/status").get_json()["allowed"] is False
    denied = post(client, "/vault/open")
    assert denied.status_code == 403
    assert b"AUTHSENSE-LAB-ACCESS-CONFIRMED" not in denied.data


def test_nonce_replay_rejected_and_text_not_accepted(app, client):
    register(app, client)
    payload = window(client)
    assert post(client, "/api/telemetry", json=payload).status_code == 200
    assert post(client, "/api/telemetry", json=payload).status_code == 409
    payload = window(client)
    payload["text"] = "This must never be accepted"
    assert post(client, "/api/telemetry", json=payload).status_code == 400


def test_unverified_enrollment_and_grant_scope(app, client):
    register(app, client)
    assert post(client, "/api/enroll/start", json={}).status_code == 403
    verify(app, client, "export")
    assert post(client, "/api/enroll/start", json={}).status_code == 403
    verify(app, client, "enroll")
    assert post(client, "/api/enroll/start", json={}).status_code == 200
    assert post(client, "/api/enroll/start", json={}).status_code == 403


def test_grants_expire(app, client):
    register(app, client)
    verify(app, client, "enroll")
    app.test_clock[0] += 121
    assert post(client, "/api/enroll/start", json={}).status_code == 403


def test_anomaly_latches_and_cannot_be_cleared_by_normal_data(app, client):
    register(app, client)
    enroll_train(app, client)
    for _ in range(2):
        assert post(client, "/api/telemetry", json=window(client, alien=True)).status_code == 200
    state = client.get("/api/status").get_json()
    assert state["must_verify"] and not state["allowed"]
    assert post(client, "/vault/open").status_code == 403
    post(client, "/api/telemetry", json=window(client))
    assert client.get("/api/status").get_json()["must_verify"]
    verify(app, client)
    assert post(client, "/vault/open").status_code == 200


def test_normal_live_data_then_stale_policy(app, client):
    register(app, client)
    enroll_train(app, client)
    app.test_clock[0] += 121
    result = post(client, "/api/telemetry", json=window(client, seed=200)).get_json()
    assert result["observation"] == "normal"
    assert post(client, "/vault/open").status_code == 200
    app.test_clock[0] += 46
    assert post(client, "/vault/open").status_code == 403
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 30


def test_corrupt_model_falls_back_to_verification(app, client):
    register(app, client)
    enroll_train(app, client)
    with app.app_context():
        get_db().execute("UPDATE profiles SET payload='not-json'")
    app.test_clock[0] += 121
    assert post(client, "/api/telemetry", json=window(client)).status_code == 503
    assert post(client, "/vault/open").status_code == 403
    verify(app, client)
    assert post(client, "/vault/open").status_code == 200


def test_data_isolation_export_and_delete(app, client):
    register(app, client)
    enroll_train(app, client)
    other = app.test_client()
    register(app, other, "bob")
    assert other.get("/api/status").get_json()["progress"]["windows"] == 0
    assert not other.get("/api/status").get_json()["trained"]
    verify(app, client, "export")
    export = post(client, "/data/export")
    assert export.status_code == 200 and len(export.data.splitlines()) == 31
    assert b"dwell_median_ms" in export.data and b"password" not in export.data
    assert post(client, "/data/export").status_code == 302
    verify(app, client, "delete")
    assert post(client, "/account/delete").status_code == 302
    assert client.get("/api/status").status_code == 401
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert get_db().execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 0


def test_reset_removes_profile_and_data(app, client):
    register(app, client)
    enroll_train(app, client)
    verify(app, client, "reset")
    post(client, "/profile/reset")
    state = client.get("/api/status").get_json()
    assert state["progress"] == {"windows": 0, "rounds": 0}
    assert state["trained"] is False


def test_authenticator_replacement_revokes_other_sessions(app, client):
    backups = register(app, client)
    other = app.test_client()
    post(other, "/login", {"username": "alice", "password": PASSWORD})
    post(other, "/mfa", {"code": code(app)})
    verify(app, client, "authenticator")
    post(client, "/account/authenticator")
    assert other.get("/api/status").status_code == 401
    assert client.get("/api/status").status_code == 401
    response = post(client, "/setup", {"code": code(app)})
    assert response.status_code == 200 and b"Your recovery codes" in response.data


def test_polling_does_not_extend_idle_timeout(app, client):
    register(app, client)
    for _ in range(6):
        app.test_clock[0] += 290
        assert client.get("/api/status").status_code == 200
    app.test_clock[0] += 61
    assert client.get("/api/status").status_code == 401


def test_security_headers_and_host_restriction(client):
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert "HttpOnly" in response.headers["Set-Cookie"]
    assert "SameSite=Strict" in response.headers["Set-Cookie"]
    assert client.get("/", headers={"Host": "attacker.invalid"}).status_code == 400


def test_secrets_are_not_plaintext_in_database(app, client):
    register(app, client)
    with app.app_context():
        user = get_db().execute("SELECT * FROM users").fetchone()
        assert user["password_hash"].startswith("scrypt:")
        assert user["totp_secret"].startswith("gAAAA")
        assert len(get_db().execute("SELECT code_hash FROM recovery_codes").fetchone()[0]) == 64


def test_unicode_digits_do_not_crash_factor_verification(app, client):
    register(app, client)
    post(client, "/logout")
    post(client, "/login", {"username": "alice", "password": PASSWORD})
    assert post(client, "/mfa", {"code": "\u0661\u0662\u0663\u0664\u0665\u0666"}).status_code == 200
    assert client.get("/api/status").status_code == 401
