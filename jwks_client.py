import time
import requests
import threading
from typing import Optional
import config

_lock = threading.Lock()
_cached = {"keys": None, "fetched_at": 0}
_CACHE_TTL = 300


def fetch_jwks() -> Optional[dict]:
    if not config.JWKS_URL:
        return None
    with _lock:
        now = time.time()
        if _cached["keys"] and now - _cached["fetched_at"] < _CACHE_TTL:
            return _cached["keys"]
        try:
            resp = requests.get(config.JWKS_URL, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            _cached["keys"] = data
            _cached["fetched_at"] = now
            return data
        except Exception:
            # Do not raise here; caller should handle missing keys
            return _cached["keys"]


def get_public_key(kid: Optional[str]):
    jwks = fetch_jwks()
    if not jwks:
        raise RuntimeError("no_jwks_available")
    keys = jwks.get("keys", [])
    for k in keys:
        if k.get("kid") == kid:
            return k  # let caller handle conversion to PEM if needed
    raise RuntimeError("kid_not_found")
