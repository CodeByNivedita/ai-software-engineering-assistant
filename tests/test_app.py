import jwt
import time
import config
import app


def test_login_success(monkeypatch):
    monkeypatch.setenv("AUTH_VALIDATION_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", "testsecret")
    config.AUTH_VALIDATION_ENABLED = True
    config.JWT_SECRET = "testsecret"

    token = jwt.encode({"sub": "alice", "jti": "jid-1", "exp": int(time.time()) + 60}, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    resp, status = app.login(token)
    assert status == 200
    assert resp["status"] == "ok"
    assert "session_id" in resp


def test_login_invalid(monkeypatch):
    monkeypatch.setenv("AUTH_VALIDATION_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", "testsecret")
    config.AUTH_VALIDATION_ENABLED = True
    config.JWT_SECRET = "testsecret"

    resp, status = app.login(None)
    assert status == 401
    assert resp["status"] == "error"
