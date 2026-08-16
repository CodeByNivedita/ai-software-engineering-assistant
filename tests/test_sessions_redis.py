import os
import tempfile
import time

try:
    import fakeredis
except Exception:
    fakeredis = None

import pytest

from sessions_redis import create_session, get_session, get_session_by_refresh_token, rotate_refresh_token, revoke_session, hash_refresh_token


@pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")
def test_create_and_get_session(monkeypatch):
    # Use fakeredis by patching get_redis to return a fake client
    import redis_client
    fake = fakeredis.FakeRedis()
    monkeypatch.setattr(redis_client.RedisClient, 'get_client', lambda cls, url=None: fake)

    s = create_session('user123', 'jti-1', {'foo': 'bar'}, ttl_seconds=5)
    assert 'session_id' in s
    assert 'refresh_token' in s

    sid = s['session_id']
    sess = get_session(sid)
    assert sess is not None
    assert sess['user_id'] == 'user123'

    # fetch by refresh token
    rt = s['refresh_token']
    sess2 = get_session_by_refresh_token(rt)
    assert sess2 is not None
    assert sess2['session_id'] == sid

    # rotate
    new_rt = 'new-' + rt
    ok = rotate_refresh_token(sid, rt, new_rt, ttl_seconds=5)
    assert ok

    # old token no longer works
    assert get_session_by_refresh_token(rt) is None
    assert get_session_by_refresh_token(new_rt) is not None

    # revoke
    assert revoke_session(sid)
    assert get_session(sid) is None


@pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")
def test_hash_refresh_token():
    h1 = hash_refresh_token('abc')
    h2 = hash_refresh_token('abc')
    assert h1 == h2
    assert isinstance(h1, str)
