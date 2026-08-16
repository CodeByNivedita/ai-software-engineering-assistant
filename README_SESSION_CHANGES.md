Overview of added session improvements

Files added:
- redis_client.py: Redis connection helper
- sessions_redis.py: Redis-backed session store compatible API
- metrics.py: Prometheus metrics helper (no-op if prometheus_client unavailable)
- tests/test_sessions_redis.py: unit tests using fakeredis
- docs/runbook.md: brief runbook for alerts

How to enable:
- Set environment variable REDIS_URL to point to your Redis instance (e.g. redis://localhost:6379/0)
- The sessions_redis module reads SESSION_TTL_SECONDS env var for TTL (defaults to 3600)

Integration notes:
- Replace usages of existing sessions.create_session/get_session with the functions in sessions_redis
- Use create_session return value to set HttpOnly Secure refresh cookie on login
- Rotate and revoke functions are provided for refresh and logout flows

Security notes:
- Refresh tokens are stored hashed in Redis; raw tokens are only returned to the caller so they can be set as HttpOnly cookies.
- Logs include only refresh_hash, not raw tokens.
