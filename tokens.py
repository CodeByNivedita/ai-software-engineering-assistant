from dataclasses import dataclass
from typing import Optional, Dict, Any
import hashlib
import jwt
import config


@dataclass
class TokenValidationResult:
    valid: bool
    user_id: Optional[str] = None
    jti: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    reason: Optional[str] = None
    raw_claims: Optional[Dict[str, Any]] = None


def token_identifier(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        # if JWT, try to get jti without verifying
        if token.count('.') == 2:
            unverified = jwt.decode(token, options={"verify_signature": False})
            jti = unverified.get("jti")
            if jti:
                return jti
    except Exception:
        pass

    # fallback to hashed fingerprint
    h = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return h[:16]


def create_access_token(payload: Dict[str, Any], expires_in: int = 300) -> str:
    """Create a simple HS256 token if JWT_SECRET is configured. Used for tests/demos only."""
    if not config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET not configured for token issuance")
    data = payload.copy()
    import time

    data["exp"] = int(time.time()) + expires_in
    return jwt.encode(data, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
