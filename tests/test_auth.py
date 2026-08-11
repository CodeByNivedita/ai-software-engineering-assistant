import time
import jwt
import config
import auth
from tokens import TokenValidationResult


def test_validate_valid_jwt(monkeypatch):
    # configure secret for HS256
    monkeypatch.setenv("AUTH_VALIDATION_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", "testsecret")
    config.AUTH_VALIDATION_ENABLED = True
    config.JWT_SECRET = "testsecret"

    payload = {"sub": "user1", "jti": "jid123"}
    token = jwt.encode({**payload, "exp": int(time.time()) + 60}, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    res = auth.validate_token(token)
    assert res.valid is True
    assert res.user_id == "user1"
    assert res.jti == "jid123"


def test_validate_expired_jwt(monkeypatch):
    monkeypatch.setenv("AUTH_VALIDATION_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", "testsecret")
    config.AUTH_VALIDATION_ENABLED = True
    config.JWT_SECRET = "testsecret"

    token = jwt.encode({"sub": "user1", "exp": int(time.time()) - 10}, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    res = auth.validate_token(token)
    assert res.valid is False
    assert res.reason == "expired"


def test_validate_invalid_signature(monkeypatch):
    monkeypatch.setenv("AUTH_VALIDATION_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", "testsecret")
    config.AUTH_VALIDATION_ENABLED = True
    config.JWT_SECRET = "testsecret"

    token = jwt.encode({"sub": "user1", "exp": int(time.time()) + 60}, "wrongsecret", algorithm=config.JWT_ALGORITHM)
    res = auth.validate_token(token)
    assert res.valid is False
    assert res.reason == "invalid_signature"


def test_validate_malformed_token(monkeypatch):
    monkeypatch.setenv("AUTH_VALIDATION_ENABLED", "true")
    config.AUTH_VALIDATION_ENABLED = True
    res = auth.validate_token("not-a.jwt.token")
    assert res.valid is False
    assert res.reason in ("malformed", "validation_error")
