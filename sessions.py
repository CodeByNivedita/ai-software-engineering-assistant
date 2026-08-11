import time
import uuid
from typing import Optional, Dict, Any
import threading

import config
from logger_config import get_logger

logger = get_logger(__name__)

# Simple in-memory session store for demo/testing. In production, swap for Redis-backed implementation.
_lock = threading.Lock()
_sessions: Dict[str, Dict[str, Any]] = {}
_refresh_index: Dict[str, str] = {}  # refresh_token -> session_id


def create_session(user_id: Optional[str], access_jti: Optional[str], metadata: Optional[Dict[str, Any]] = None, ttl: int = 3600) -> str:
    session_id = str(uuid.uuid4())
    now = int(time.time())
    refresh_token = str(uuid.uuid4())
    with _lock:
        _sessions[session_id] = {
            "session_id": session_id,
            "user_id": user_id,
            "access_jti": access_jti,
            "created_at": now,
            "expires_at": now + ttl,
            "metadata": metadata or {},
            "refresh_token": refresh_token,
        }
        _refresh_index[refresh_token] = session_id
    logger.debug("session_created", extra={"session_id": session_id, "user_id": user_id})
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        s = _sessions.get(session_id)
        if not s:
            return None
        # check expiry
        if s.get("expires_at") and s["expires_at"] < int(time.time()):
            # expire it
            _sessions.pop(session_id, None)
            _refresh_index.pop(s.get("refresh_token"), None)
            return None
        return s.copy()


def get_session_by_refresh_token(refresh_token: str) -> Optional[Dict[str, Any]]:
    with _lock:
        session_id = _refresh_index.get(refresh_token)
        if not session_id:
            return None
        return get_session(session_id)


def revoke_session(session_id: str) -> None:
    with _lock:
        s = _sessions.pop(session_id, None)
        if s:
            _refresh_index.pop(s.get("refresh_token"), None)
            logger.info("session_revoked", extra={"session_id": session_id})


def rotate_refresh_token(session_id: str, old_refresh: str, new_refresh: str) -> bool:
    with _lock:
        s = _sessions.get(session_id)
        if not s:
            return False
        if s.get("refresh_token") != old_refresh:
            return False
        s["refresh_token"] = new_refresh
        _refresh_index.pop(old_refresh, None)
        _refresh_index[new_refresh] = session_id
        logger.info("refresh_token_rotated", extra={"session_id": session_id})
        return True
