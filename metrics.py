"""Prometheus metrics helpers for session and auth instrumentation.

This module defines a small set of counters/histograms used by the Redis session
store and auth modules. It uses prometheus_client but falls back gracefully if
not available (so the project can be integrated incrementally).
"""
from typing import Optional
import logging

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Histogram, Gauge
    _PROM_AVAILABLE = True
except Exception:
    _PROM_AVAILABLE = False


if _PROM_AVAILABLE:
    session_create_total = Counter(
        "session_create_total",
        "Total number of sessions created",
    )
    session_revoke_total = Counter(
        "session_revoke_total",
        "Total number of sessions revoked",
    )
    session_rotate_total = Counter(
        "session_rotate_total",
        "Total number of refresh token rotations",
    )

    refresh_success_total = Counter(
        "refresh_success_total",
        "Total number of successful refresh operations",
    )
    refresh_failure_total = Counter(
        "refresh_failure_total",
        "Total number of failed refresh operations",
        ["reason"],
    )

    jwks_fetch_failures_total = Counter(
        "jwks_fetch_failures_total",
        "Total JWKS fetch failures",
    )

    idp_introspect_failures_total = Counter(
        "idp_introspect_failures_total",
        "IdP introspection failures",
        ["status", "reason"],
    )

    idp_introspect_latency_seconds = Histogram(
        "idp_introspect_latency_seconds",
        "IdP introspection latency seconds",
    )

    active_sessions = Gauge(
        "active_sessions",
        "Approximate number of active sessions (best-effort)",
    )
else:
    # no-op stubs
    def _noop(*_, **__):
        return None

    session_create_total = _noop
    session_revoke_total = _noop
    session_rotate_total = _noop

    refresh_success_total = _noop
    def refresh_failure_total(reason):
        return _noop

    jwks_fetch_failures_total = _noop
    def idp_introspect_failures_total(status, reason):
        return _noop

    class idp_introspect_latency_seconds:
        @staticmethod
        def observe(_):
            return None

    active_sessions = _noop
