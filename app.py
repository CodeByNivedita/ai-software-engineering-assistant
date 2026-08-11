import uuid
import logging
from typing import Optional

import auth
import tokens
import sessions
import config
from logger_config import get_logger

logger = get_logger(__name__)


def login(token: Optional[str]):
    """
    Attempt to authenticate using the provided token.
    Returns a tuple (response_dict, status_code) to keep HTTP semantics explicit.
    """
    result = auth.validate_token(token)
    if result.valid:
        # create a session record
        session_id = sessions.create_session(result.user_id, result.jti, {"raw_claims": result.raw_claims}, ttl=config.SESSION_TTL_SECONDS)
        logger.info("login_success", extra={"user_id": result.user_id, "jti": result.jti, "session_id": session_id})
        return {"status": "ok", "session_id": session_id, "user_id": result.user_id}, 200

    logger.info("login_failure", extra={"reason": result.reason, "token_id": tokens.token_identifier(token)})
    return {"status": "error", "reason": result.reason}, 401


def refresh(refresh_token: str):
    """
    Refresh a session given a refresh token (this example uses session store rotation).
    Returns (response, status_code).
    """
    session = sessions.get_session_by_refresh_token(refresh_token)
    if not session:
        logger.info("refresh_failure", extra={"reason": "invalid_refresh_token"})
        return {"status": "error", "reason": "invalid_refresh_token"}, 401

    # rotate refresh token
    new_refresh = str(uuid.uuid4())
    sessions.rotate_refresh_token(session["session_id"], refresh_token, new_refresh)

    logger.info("refresh_success", extra={"user_id": session.get("user_id"), "session_id": session.get("session_id")})
    # In a real system we'd issue a new access token; here return placeholder
    return {"status": "ok", "new_refresh_token": new_refresh}, 200


def logout(session_id: Optional[str] = None, refresh_token: Optional[str] = None):
    """
    Revoke a session by session_id or refresh_token.
    """
    if refresh_token:
        session = sessions.get_session_by_refresh_token(refresh_token)
        if not session:
            return {"status": "error", "reason": "invalid_refresh_token"}, 400
        sessions.revoke_session(session["session_id"])
        logger.info("logout_success", extra={"session_id": session["session_id"]})
        return {"status": "ok"}, 200

    if session_id:
        sessions.revoke_session(session_id)
        logger.info("logout_success", extra={"session_id": session_id})
        return {"status": "ok"}, 200

    return {"status": "error", "reason": "missing_parameter"}, 400
