import re

import numpy as np
import pyotp
import pytest

from authsense import create_app
from authsense.behavior import FEATURES
from authsense.db import get_db
from authsense.security import decrypt_secret


PASSWORD = "correct horse planet orbit 42"


@pytest.fixture
def app(tmp_path):
    clock = [1_800_000_000.0]
    app = create_app({"TESTING": True, "INSTANCE_PATH": tmp_path, "CLOCK": lambda: clock[0]})
    app.test_clock = clock
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    with client.session_transaction() as s:
        if "csrf" not in s:
            s["csrf"] = "test-csrf-token"
        return s["csrf"]


def post(client, path, data=None, json=None):
    if json is not None:
        return client.post(path, json=json, headers={"X-CSRF-Token": csrf(client)})
    return client.post(path, data={"csrf_token": csrf(client), **(data or {})})


def code(app, username="alice", advance=True):
    if advance:
        app.test_clock[0] += 31
    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return pyotp.TOTP(decrypt_secret(user)).at(app.test_clock[0])


def register(app, client, username="alice"):
    response = post(client, "/register", {"username": username, "password": PASSWORD, "consent": "yes"})
    assert response.status_code == 302
    response = post(client, "/setup", {"code": code(app, username)})
    assert response.status_code == 200
    recovery = re.findall(r"[a-f0-9]{8}(?:-[a-f0-9]{8}){3}", response.get_data(as_text=True))
    assert len(recovery) == 5
    post(client,"/api/consent",json={"enabled":True})
    return recovery


def verify(app, client, purpose="session", username="alice"):
    response = post(client, f"/verify?purpose={purpose}", {"password": PASSWORD, "code": code(app, username)})
    assert response.status_code == 302
    post(client,"/api/consent",json={"enabled":True})


def features(seed=1, alien=False):
    rng = np.random.default_rng(seed)
    center = np.array([90,22,120,90,35,140,180,45,245], dtype=float)
    if alien: center=np.array([600,100,730,350,150,500,950,200,1240],dtype=float)
    values = center + rng.normal(0,[4,2,5,4,2,5,7,3,8])
    values = [*values, values[0]/values[6],values[7]/values[6],30*1000/6500]
    return dict(zip(FEATURES,values))


def window(client, seed=1, alien=False, round_id=None):
    state = client.get("/api/status").get_json()
    result = {"v": 2, "nonce": state["nonce"], "seq": state["seq"] + 1,
              "count": 30, "interval_count": 29, "duration_ms": 6500,
              "features": features(seed, alien)}
    if round_id:
        result["round_id"] = round_id
    return result


def enroll_train(app, client, username="alice"):
    for group in range(3):
        verify(app, client, "enroll", username)
        rid = post(client, "/api/enroll/start", json={}).get_json()["round_id"]
        for i in range(10):
            app.test_clock[0] += 6
            r = post(client, "/api/telemetry", json=window(client, group * 10 + i, round_id=rid))
            assert r.status_code == 200, r.get_json()
        assert post(client, "/api/enroll/finish", json={"round_id": rid}).status_code == 200
    verify(app, client, "train", username)
    response = post(client, "/model/train")
    assert response.status_code == 302
    assert client.get("/api/status").get_json()["trained"]
