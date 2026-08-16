"""Redis-backed session store implementation.

This module implements a simple Redis-backed session store with the following
API (intended to be compatible with an existing in-memory sessions module):

- create_session(user_id, access_jti, metadata, ttl_seconds) -> dict with session details including refresh_token
- get_session(session_id) -> session dict or None
- get_session_by_refresh_token(refresh_token) -> session dict or None
- rotate_refresh_token(session_id, old_refresh_token, new_refresh_token) -> bool
- revoke_session(session_id) -> bool

Refresh tokens are stored hashed (sha256) in Redis to avoid logging raw tokens.
Atomic rotate is implemented via a Lua script.
"""
from __future__ import annotations

import json
import uuid
import time
import hashlib
import socket
import logging
from typing import Optional, Dict, Any

from redis_client import get_redis
import os
from metrics import session_create_total, session_revoke_total, session_rotate_total

logger = logging.getLogger(__name__)

REDIS_PREFIX = os.environ.get("SESSION_REDIS_PREFIX", "session")
DEFAULT_TTL = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))

# Lua script for atomic rotate: check that refresh:<old_hash> == session_id,
# then delete old mapping and set new mapping with given ttl.
_ROTATE_LUA = r"""
local old_key = KEYS[1]
local new_key = KEYS[2]
local session_key = ARGV[1]
local ttl = tonumber(ARGV[2])
local cur = redis.call('GET', old_key)
if cur == false then
    return {err='old_missing'}
end
if cur ~= session_key then
    return {err='mismatch'}
end
redis.call('DEL', old_key)
redis.call('SET', new_key, session_key, 'EX', ttl)
return {ok='OK'}
"""

_redis = None
_rotate_sha = None


def _get_redis():
    global _redis, _rotate_sha
    if _redis is None:
        _redis = get_redis()
        try:
            _rotate_sha = _redis.script_load(_ROTATE_LUA)
        except Exception:
            _rotate_sha = None
    return _redis


def hash_refresh_token(refresh_token: str) -> str:
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def _session_key(session_id: str) -> str:
    return f"{REDIS_PREFIX}:session:{session_id}"


def _refresh_key(refresh_hash: str) -> str:
    return f"{REDIS_PREFIX}:refresh:{refresh_hash}"


def _now_ts() -> int:
    return int(time.time())


def create_session(user_id: str, access_jti: Optional[str], metadata: Optional[Dict[str, Any]] = None, ttl_seconds: int = DEFAULT_TTL) -> Dict[str, Any]:
    """Create a new session stored in Redis and return the session data including raw refresh_token.

    Note: callers are responsible for sending the raw refresh_token to the client
    (e.g., in an HttpOnly Secure cookie). The raw token is NOT stored in logs.
    """
    redis = _get_redis()
    session_id = str(uuid.uuid4())
    refresh_token = str(uuid.uuid4())
    refresh_hash = hash_refresh_token(refresh_token)

    now = _now_ts()
    expires_at = now + ttl_seconds

    session = {
        "session_id": session_id,
        "user_id": user_id,
        "access_jti": access_jti,
        "metadata": metadata or {},
        "created_at": now,
        "expires_at": expires_at,
        # store refresh_hash for convenience (do not store raw token)
        "refresh_hash": refresh_hash,
    }

    session_key = _session_key(session_id)
    refresh_key = _refresh_key(refresh_hash)

    # store session JSON and mapping with EXPIRE TTL
    pipe = redis.pipeline()
    pipe.set(session_key, json.dumps(session), ex=ttl_seconds)
    pipe.set(refresh_key, session_id, ex=ttl_seconds)
    try:
        pipe.execute()
    except Exception:
        logger.exception("Failed to write session to Redis")
        raise

    # metrics and structured log
    try:
        session_create_total.inc()
    except Exception:
        pass

    logger.info("session_created", extra={
        "session_id": session_id,
        "user_id": user_id,
        "refresh_hash": refresh_hash,
        "backend_node": socket.gethostname(),
        "expires_at": expires_at,
    })

    # return raw refresh_token so caller can set cookie
    return {"session_id": session_id, "refresh_token": refresh_token, "expires_at": expires_at}


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    redis = _get_redis()
    val = redis.get(_session_key(session_id))
    if not val:
        return None
    try:
        return json.loads(val)
    except Exception:
        logger.exception("Failed to decode session JSON for %s", session_id)
        return None


def get_session_by_refresh_token(refresh_token: str) -> Optional[Dict[str, Any]]:
    redis = _get_redis()
    refresh_hash = hash_refresh_token(refresh_token)
    sid = redis.get(_refresh_key(refresh_hash))
    if not sid:
        return None
    sid = sid.decode() if isinstance(sid, bytes) else sid
    return get_session(sid)


def rotate_refresh_token(session_id: str, old_refresh_token: str, new_refresh_token: str, ttl_seconds: int = DEFAULT_TTL) -> bool:
    """Atomically replace mapping from old refresh token to new refresh token for a session.

    Returns True on success, False if old mapping not present or mismatch.
    """
    redis = _get_redis()
    old_hash = hash_refresh_token(old_refresh_token)
    new_hash = hash_refresh_token(new_refresh_token)
    old_key = _refresh_key(old_hash)
    new_key = _refresh_key(new_hash)

    try:
        # Try Lua script first (atomic)
        if _rotate_sha:
            res = redis.evalsha(_rotate_sha, 2, old_key, new_key, session_id, str(ttl_seconds))
            if isinstance(res, bytes):
                res = res.decode()
            if res == 'OK' or (isinstance(res, dict) and res.get('ok') == 'OK'):
                session_rotate_total.inc()
                logger.info("refresh_rotated", extra={
                    "session_id": session_id,
                    "old_refresh_hash": old_hash,
                    "new_refresh_hash": new_hash,
                    "backend_node": socket.gethostname(),
                })
                # update session object's refresh_hash
                try:
                    session = get_session(session_id)
                    if session:
                        session['refresh_hash'] = new_hash
                        redis.set(_session_key(session_id), json.dumps(session), ex=ttl_seconds)
                except Exception:
                    logger.exception("Failed to update session refresh_hash after rotate")
                return True
            else:
                # script returned an error
                logger.warning("rotate_lua_returned_error", extra={"res": str(res)})
                return False
        # Fallback: WATCH / MULTI
        with redis.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(old_key)
                    cur = pipe.get(old_key)
                    if not cur:
                        pipe.unwatch()
                        return False
                    cur_sid = cur.decode() if isinstance(cur, bytes) else cur
                    if cur_sid != session_id:
                        pipe.unwatch()
                        return False
                    pipe.multi()
                    pipe.delete(old_key)
                    pipe.set(new_key, session_id, ex=ttl_seconds)
                    pipe.execute()
                    session_rotate_total.inc()
                    logger.info("refresh_rotated", extra={
                        "session_id": session_id,
                        "old_refresh_hash": old_hash,
                        "new_refresh_hash": new_hash,
                        "backend_node": socket.gethostname(),
                    })
                    try:
                        session = get_session(session_id)
                        if session:
                            session['refresh_hash'] = new_hash
                            redis.set(_session_key(session_id), json.dumps(session), ex=ttl_seconds)
                    except Exception:
                        logger.exception("Failed to update session refresh_hash after rotate")
                    return True
                except redis.WatchError:
                    continue
    except Exception:
        logger.exception("Failed to rotate refresh token for session %s", session_id)
        return False


def revoke_session(session_id: str) -> bool:
    redis = _get_redis()
    session = get_session(session_id)
    if not session:
        return False
    refresh_hash = session.get('refresh_hash')
    try:
        pipe = redis.pipeline()
        pipe.delete(_session_key(session_id))
        if refresh_hash:
            pipe.delete(_refresh_key(refresh_hash))
        pipe.execute()
        try:
            session_revoke_total.inc()
        except Exception:
            pass
        logger.info("session_revoked", extra={
            "session_id": session_id,
            "user_id": session.get('user_id'),
            "refresh_hash": refresh_hash,
            "backend_node": socket.gethostname(),
        })
        return True
    except Exception:
        logger.exception("Failed to revoke session %s", session_id)
        return False
