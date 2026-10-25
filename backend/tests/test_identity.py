"""Offline tests for pinned RS256 JWT acceptance, RBAC, MFA, and audit hygiene."""

import json
import logging
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from dpn_ds.app import create_app
from dpn_ds.config import Settings
from dpn_ds.directory import DemoDirectory


@pytest.fixture(scope="module")
def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
    )


def configuration(**custom):
    values = {
        "api_token": "legacy-should-never-work-in-oidc-mode",
        "auth_mode": "oidc",
        "mode": "demo",
        "oidc_issuer": "https://identity.example.test/realms/dpn",
        "oidc_audience": "dpn-directory-services",
        "oidc_public_key_file": "/etc/dpn-ds/issuer-public.pem",
        "oidc_mfa_amr": "mfa",
    }
    return Settings(**{**values, **custom})


def signed_token(keys, **override):
    now = int(time.time())
    claims = {
        "iss": "https://identity.example.test/realms/dpn",
        "aud": "dpn-directory-services",
        "sub": "operator-123",
        "iat": now - 5,
        "exp": now + 240,
        "amr": ["pwd", "mfa"],
        "dpn_roles": ["viewer"],
        "token_use": "access",
    }
    claims.update(override)
    return jwt.encode(claims, keys[0], algorithm="RS256")


def test_viewer_operator_security_role_matrix(keys):
    c = TestClient(create_app(configuration(), directory=DemoDirectory(), public_key=keys[1]))
    viewer = {"Authorization": "Bearer " + signed_token(keys)}
    operator = {"Authorization": "Bearer " + signed_token(keys, dpn_roles=["operator"])}
    security = {"Authorization": "Bearer " + signed_token(keys, dpn_roles=["security"])}
    assert c.get("/api/v1/users", headers=viewer).status_code == 200
    assert c.get("/api/v1/diagnostics", headers=viewer).status_code == 403
    assert c.get("/api/v1/diagnostics", headers=operator).status_code == 200
    assert c.get("/api/v1/advanced-health", headers=operator).status_code == 403
    assert c.get("/api/v1/advanced-health", headers=security).status_code == 200
    info = c.get("/api/v1/session", headers=security).json()
    assert info["role"] == "security"
    assert info["auth_mode"] == "oidc"
    assert "operator-123" not in str(info)


@pytest.mark.parametrize("change", [
    {"iss": "https://bad-issuer.test"},
    {"aud": "wrong-audience"},
    {"exp": 1},
    {"amr": ["pwd"]},
    {"dpn_roles": ["superadmin"]},
    {"token_use": "id"},
    {"exp": int(time.time()) + 86400},
])
def test_rejects_invalid_or_insufficient_tokens(keys, change):
    c = TestClient(create_app(configuration(), directory=DemoDirectory(), public_key=keys[1]))
    result = c.get(
        "/api/v1/overview",
        headers={"Authorization": "Bearer " + signed_token(keys, **change)},
    )
    assert result.status_code in (401, 403)


def test_unsigned_alg_none_and_legacy_bypass_rejected(keys):
    c = TestClient(create_app(configuration(), directory=DemoDirectory(), public_key=keys[1]))
    assert c.get("/api/v1/overview", headers={
        "Authorization": "Bearer legacy-should-never-work-in-oidc-mode"
    }).status_code == 401
    bad = jwt.encode({"sub": "attacker"}, key="", algorithm="none")
    assert c.get("/api/v1/overview", headers={
        "Authorization": "Bearer " + bad
    }).status_code == 401
    assert c.get("/api/v1/overview").status_code == 401


def test_audit_contains_no_raw_subject_or_credentials(keys, caplog):
    c = TestClient(create_app(configuration(), directory=DemoDirectory(), public_key=keys[1]))
    token = signed_token(keys, dpn_roles=["security"])
    with caplog.at_level(logging.INFO, logger="dpn_ds.security_audit"):
        response = c.get("/api/v1/advanced-health", headers={"Authorization": "Bearer " + token})
        assert response.status_code == 200
    records = [json.loads(x.message) for x in caplog.records if "dpn_ds.api_access" in x.message]
    assert records
    entry = records[-1]
    assert entry["endpoint"] == "/api/v1/advanced-health"
    assert entry["role"] == "security"
    assert entry["auth_type"] == "oidc"
    assert entry["actor"] and len(entry["actor"]) == 20
    assert token not in str(entry)
    assert "operator-123" not in str(entry)


def test_unauthorized_attempt_is_audited(keys, caplog):
    c = TestClient(create_app(configuration(), directory=DemoDirectory(), public_key=keys[1]))
    with caplog.at_level(logging.INFO, logger="dpn_ds.security_audit"):
        result = c.get("/api/v1/overview?token=NEVERLOG", headers={
            "Authorization": "Bearer wrong"
        })
    assert result.status_code == 401
    record = [x.message for x in caplog.records if "dpn_ds.api_access" in x.message][-1]
    assert "NEVERLOG" not in record
    assert "wrong" not in record
    assert '"status":401' in record
