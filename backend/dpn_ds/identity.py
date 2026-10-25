"""Pinned-key JWT validation and delegated read-only permissions.

This validates access tokens produced by a separately deployed OIDC identity
provider. It does NOT implement the provider's login, MFA or authorization
code / PKCE flows. No token-supplied discovery, JWKS URI, or algorithm is used.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from dataclasses import dataclass

import jwt
from fastapi import HTTPException, Request

from dpn_ds.config import Settings

# Increasing read-only privileges. Even "security" cannot mutate the directory.
ROLE_RANK = {"viewer": 1, "operator": 2, "security": 3}
ENDPOINT_ROLES = {
    "/api/v1/overview": "viewer",
    "/api/v1/users": "viewer",
    "/api/v1/groups": "viewer",
    "/api/v1/devices": "viewer",
    "/api/v1/diagnostics": "operator",
    "/api/v1/advanced-health": "security",
    "/api/v1/session": "viewer",
}
BEARER_HEADERS = {"WWW-Authenticate": "Bearer"}


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str
    method: str

    @property
    def subject_fingerprint(self) -> str:
        # Stable, pseudonymous log identifier without raw usernames, tokens or emails.
        return hashlib.sha256(self.subject.encode("utf-8")).hexdigest()[:20]


def read_pinned_public_key(path: str) -> str:
    """Read trusted public key only from a local deployment-owned regular PEM file."""
    if not os.path.isabs(path):
        raise ValueError("OIDC public key must use an absolute path")
    try:
        data = os.lstat(path)
        if not stat.S_ISREG(data.st_mode) or data.st_mode & 0o022:
            raise ValueError("OIDC public key must be an unmodifiable regular file")
        if data.st_uid not in (os.geteuid(), 0) or not 1 <= data.st_size <= 16384:
            raise ValueError("OIDC public key metadata is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_ino != data.st_ino:
                raise ValueError("OIDC key changed while opening")
            if opened.st_mode & 0o022 or opened.st_uid not in (os.geteuid(), 0):
                raise ValueError("OIDC public key permissions changed")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                payload = stream.read(16385)
        finally:
            os.close(fd)
        if len(payload) > 16384:
            raise ValueError("OIDC key exceeds size limit")
        result = payload.decode("ascii")
        if not result.startswith("-----BEGIN PUBLIC KEY-----"):
            raise ValueError("OIDC key must be an RSA public PEM key")
        return result
    except OSError as exc:
        raise ValueError("OIDC public key cannot be read") from exc


class OperatorAuthenticator:
    """Authenticates and authorizes all /api/v1 requests, without redirects."""

    def __init__(self, settings: Settings, public_key: str | None = None):
        self.settings = settings
        self.public_key = None
        if settings.auth_mode == "oidc":
            self.public_key = public_key or read_pinned_public_key(settings.oidc_public_key_file)

    def _legacy(self, supplied: str) -> Identity:
        if not self.settings.api_token:
            raise HTTPException(503, "API authentication is not configured")
        if not hmac.compare_digest(supplied.encode(), self.settings.api_token.encode()):
            raise HTTPException(401, "Unauthorized", headers=BEARER_HEADERS)
        # Legacy token is an evaluation-only shared secret; it has no per-user RBAC.
        return Identity("legacy-evaluation-token", "security", "legacy")

    def _oidc(self, supplied: str) -> Identity:
        if len(supplied) > 8192 or not supplied:
            raise HTTPException(401, "Unauthorized", headers=BEARER_HEADERS)
        try:
            header = jwt.get_unverified_header(supplied)
            if header.get("alg") != "RS256":
                raise jwt.InvalidTokenError("Disallowed signature algorithm")
            # The trusted, operator-pinned PEM key determines verification.
            # Header kid/jku/jwk/x5u can never influence key selection or network access.
            claims = jwt.decode(
                supplied, self.public_key, algorithms=["RS256"],
                issuer=self.settings.oidc_issuer,
                audience=self.settings.oidc_audience,
                options={"require": ["iss", "aud", "sub", "iat", "exp"]},
                leeway=10,
            )
        except (jwt.PyJWTError, ValueError, TypeError):
            raise HTTPException(401, "Unauthorized", headers=BEARER_HEADERS) from None
        if claims.get("token_use") != "access":
            raise HTTPException(401, "API requires an access token", headers=BEARER_HEADERS)
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 256:
            raise HTTPException(401, "Invalid subject", headers=BEARER_HEADERS)
        issued_at = claims.get("iat")
        expiry = claims.get("exp")
        if (
            not isinstance(issued_at, (int, float))
            or isinstance(issued_at, bool)
            or not isinstance(expiry, (int, float))
            or isinstance(expiry, bool)
            or expiry - issued_at > self.settings.oidc_max_token_age_seconds
        ):
            raise HTTPException(401, "Token lifetime not permitted", headers=BEARER_HEADERS)
        amr = claims.get("amr")
        if not isinstance(amr, list) or self.settings.oidc_mfa_amr not in amr:
            raise HTTPException(403, "Multi-factor authentication is required")
        role_claim = claims.get("dpn_roles")
        roles = role_claim if isinstance(role_claim, list) else []
        roles = [role for role in roles if isinstance(role, str) and role in ROLE_RANK]
        if not roles:
            raise HTTPException(403, "DPN DS access role is required")
        return Identity(
            f"{self.settings.oidc_issuer}:{subject}",
            max(roles, key=lambda x: ROLE_RANK[x]),
            "oidc",
        )

    def verify(self, request: Request) -> Identity:
        auth = request.headers.get("authorization", "")
        scheme, separator, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not separator:
            raise HTTPException(401, "Unauthorized", headers=BEARER_HEADERS)
        if self.settings.auth_mode == "oidc":
            actor = self._oidc(token)
        else:
            actor = self._legacy(token)
        needed = ENDPOINT_ROLES.get(request.url.path)
        if needed is None or ROLE_RANK[actor.role] < ROLE_RANK[needed]:
            raise HTTPException(403, "Insufficient privileges")
        request.state.operator = actor
        return actor
