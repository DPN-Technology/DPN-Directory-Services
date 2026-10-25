"""Sanitized, structured security event stream for downstream journal collection.

Only named API paths, HTTP statuses and pseudonymous actor fingerprints
are logged. Never serialize headers, token claims, request bodies or queries.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

from fastapi import Request

from dpn_ds.identity import ENDPOINT_ROLES, Identity

LOGGER = logging.getLogger("dpn_ds.security_audit")


def emit_audit_event(request: Request, status: int, elapsed_ms: int) -> None:
    identity: Identity | None = getattr(request.state, "operator", None)
    path = request.url.path
    # Do not let attacker-controlled URL path fragments reach the log.
    endpoint = path if path in ENDPOINT_ROLES else "unmatched_api_route"
    record = {
        "event": "dpn_ds.api_access",
        "timestamp": datetime.now(UTC).isoformat(),
        "method": request.method if request.method in ("GET", "POST", "PUT", "DELETE") else "OTHER",
        "endpoint": endpoint,
        "status": status,
        "authorized": 200 <= status < 400,
        "auth_type": identity.method if identity else "unverified",
        "actor": identity.subject_fingerprint if identity else None,
        "role": identity.role if identity else None,
        "elapsed_ms": min(max(elapsed_ms, 0), 120000),
    }
    LOGGER.info(json.dumps(record, separators=(",", ":"), sort_keys=True))


def elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
