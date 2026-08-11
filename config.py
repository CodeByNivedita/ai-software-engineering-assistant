import os
from typing import Optional, Tuple

# Authentication/Token configuration
AUTH_VALIDATION_ENABLED = os.getenv("AUTH_VALIDATION_ENABLED", "false").lower() in ("1", "true", "yes")
JWT_SECRET = os.getenv("JWT_SECRET")  # symmetric secret for HS256 (for testing/local)
JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY")  # PEM public key for RS256
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ISSUER = os.getenv("JWT_ISSUER")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE")
JWT_LEEWAY_SECONDS = int(os.getenv("JWT_LEEWAY_SECONDS", "60"))

# JWKS / introspection
JWKS_URL = os.getenv("JWKS_URL")
INTROSPECTION_URL = os.getenv("INTROSPECTION_URL")
# Basic auth for introspection: expected as "user:pass" or None
_INTROSPECTION_AUTH = os.getenv("INTROSPECTION_AUTH")
INTROSPECTION_AUTH = tuple(_INTROSPECTION_AUTH.split(":", 1)) if _INTROSPECTION_AUTH and ":" in _INTROSPECTION_AUTH else None

# Session store
REDIS_URL = os.getenv("REDIS_URL")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))

# Refresh cookie settings (if used)
REFRESH_COOKIE_SECURE = os.getenv("REFRESH_COOKIE_SECURE", "true").lower() in ("1", "true", "yes")
REFRESH_COOKIE_HTTPONLY = os.getenv("REFRESH_COOKIE_HTTPONLY", "true").lower() in ("1", "true", "yes")
REFRESH_COOKIE_SAMESITE = os.getenv("REFRESH_COOKIE_SAMESITE", "Lax")
REFRESH_COOKIE_DOMAIN = os.getenv("REFRESH_COOKIE_DOMAIN")
REFRESH_COOKIE_PATH = os.getenv("REFRESH_COOKIE_PATH", "/")
REFRESH_COOKIE_MAX_AGE = int(os.getenv("REFRESH_COOKIE_MAX_AGE", "1209600"))  # 14 days

# Introspection basic auth tuple available as INTROSPECTION_AUTH

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
