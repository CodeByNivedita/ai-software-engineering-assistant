import os
import logging
from typing import Optional

try:
    import redis
except Exception:
    redis = None

logger = logging.getLogger(__name__)


class RedisClient:
    """Simple Redis client factory/wrapper. Uses REDIS_URL env var or default.

    Provide get_client() to obtain a redis.Redis instance. This file is intentionally
    small and dependency-light so it can be integrated into an existing codebase
    incrementally.
    """

    _client = None

    @classmethod
    def get_client(cls, url: Optional[str] = None):
        if cls._client is not None:
            return cls._client
        if redis is None:
            raise RuntimeError("redis package is not installed")
        url = url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        try:
            cls._client = redis.from_url(url)
            # Test connection lazily - do not raise on import
            cls._client.ping()
        except Exception as e:
            logger.exception("Failed to connect to Redis: %s", e)
            # re-raise so caller can handle
            raise
        return cls._client


def get_redis(url: Optional[str] = None):
    return RedisClient.get_client(url)
