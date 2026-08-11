import os
import time
import logging
from typing import Optional, Dict, Any

import jwt
import requests

from tokens import TokenValidationResult, token_identifier
import config
import jwks_client
from logger_config import get_logger

logger = get_logger(__name__)


def is_authenticated(token: Optional[str]) -> bool:
    """Backward-compatible boolean helper."""
    return validate_token(token).valid


def validate_token(token: Optional[str]) -> TokenValidationResult:
    """
    Validate a token (JWT or opaque). Returns a TokenValidationResult describing validity and metadata.
    This function is conservative: on any validation error it returns valid=False with a reason string.
    Feature-flagged by config.AUTH_VALIDATION_ENABLED: when disabled, falls back to legacy "token is not None" behavior.
    """
    if not token:
        logger.info("validate_token: no token provided")
        return TokenValidationResult(valid=False, reason="no_token")

    if not config.AUTH_VALIDATION_ENABLED:
        # Legacy behavior for safe rollout
        logger.info("validate_token: AUTH_VALIDATION_ENABLED=false, using legacy non-empty check")
        return TokenValidationResult(valid=True, user_id=None, jti=token_identifier(token))

    # Heuristic: JWTs have two dots
    if token.count('.') == 2:
        return _validate_jwt(token)

    # Opaque token handling (introspection) - not implemented fully here, return informative reason
    if config.INTROSPECTION_URL:
        try:
            resp = requests.post(
                config.INTROSPECTION_URL,
                data={"token": token},
                auth=config.INTROSPECTION_AUTH,
                timeout=5,
            )
            if resp.status_code != 200:
                return TokenValidationResult(valid=False, reason=f"introspection_status_{resp.status_code}")
            data = resp.json()
            if data.get("active"):
                return TokenValidationResult(
                    valid=True,
                    user_id=data.get("sub") or data.get("username") or data.get("user_id"),
                    jti=data.get("jti"),
                    exp=data.get("exp"),
                    raw_claims=data,
                )
            else:
                return TokenValidationResult(valid=False, reason="introspection_inactive")
        except Exception as e:
            logger.exception("introspection call failed")
            return TokenValidationResult(valid=False, reason="introspection_error")

    return TokenValidationResult(valid=False, reason="opaque_no_introspection")


def _validate_jwt(token: str) -> TokenValidationResult:
    try:
        # Try to get verification key. Prefer symmetric secret if provided, else JWKS/public key.
        key = None
        algorithms = [config.JWT_ALGORITHM]
        if config.JWT_SECRET:
            key = config.JWT_SECRET
        elif config.JWT_PUBLIC_KEY:
            key = config.JWT_PUBLIC_KEY
        elif config.JWKS_URL:
            # get kid from header
            try:
                unverified_header = jwt.get_unverified_header(token)
                kid = unverified_header.get("kid")
                key = jwks_client.get_public_key(kid)
            except Exception:
                logger.exception("failed to obtain key from JWKS")
                return TokenValidationResult(valid=False, reason="jwks_fetch_failed")
        else:
            logger.warning("No JWT verification key/configured; rejecting token")
            return TokenValidationResult(valid=False, reason="no_verification_key")

        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "require_exp": False,
        }
        decode_kwargs: Dict[str, Any] = {
            "key": key,
            "algorithms": algorithms,
            "options": options,
        }
        if config.JWT_AUDIENCE:
            decode_kwargs["audience"] = config.JWT_AUDIENCE
        if config.JWT_ISSUER:
            decode_kwargs["issuer"] = config.JWT_ISSUER

        # jwt.decode will raise exceptions for expired or invalid tokens
        claims = jwt.decode(token, **decode_kwargs, leeway=config.JWT_LEEWAY_SECONDS)

        return TokenValidationResult(
            valid=True,
            user_id=claims.get("sub"),
            jti=claims.get("jti"),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            raw_claims=claims,
        )

    except jwt.ExpiredSignatureError:
        logger.info("JWT expired")
        return TokenValidationResult(valid=False, reason="expired")
    except jwt.InvalidSignatureError:
        logger.info("JWT invalid signature")
        return TokenValidationResult(valid=False, reason="invalid_signature")
    except jwt.DecodeError:
        logger.info("JWT decode error / malformed")
        return TokenValidationResult(valid=False, reason="malformed")
    except Exception as e:
        logger.exception("Unexpected error validating JWT")
        return TokenValidationResult(valid=False, reason="validation_error")
