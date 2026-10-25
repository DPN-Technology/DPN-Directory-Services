# DPN DS — Operator identity, RBAC and audit (Phase 4)

## Implemented

The backend validates **existing IdP-issued RS256 API access tokens** using an operator-pinned PEM public key. It checks issuer, API audience, signature, subject, issued-at, expiry, token lifetime, token_use=access, MFA amr claim and a trusted issuer-signed dpn_roles claim.

**This is access-token validation, not an interactive OIDC login client.** There is no built-in sign-in redirect, authorization-code + PKCE, refresh token rotation, session cookies, MFA registration, logout at IdP or automatic key rotation. Use a separately managed IdP that enforces MFA and controls role issuance. The console accepts an already-issued API access token in memory.

The backend does not fetch keys from user-supplied token headers (such as jku, x5u or jwk), nor follow a dynamically configured JWKS URL. Public-key rotation currently requires a reviewed PEM replacement and API restart.

## Authorization matrix

| Endpoint | viewer | operator | security |
|---|---|---|---|
| Overview, user/group/computer inventory | Read | Read | Read |
| DNS, TCP and NTP diagnostics | Denied | Read | Read |
| Authenticated LDAPS, Kerberos and DRS diagnostics | Denied | Denied | Read |
| Session metadata (role and auth mode only) | Read | Read | Read |
| Directory writes or credential changes | Denied | Denied | Denied |

These roles are read-only API roles, not Windows or Samba Domain Admin memberships. Unknown or missing roles are denied. DPN DS does not trust client-controlled role values.

## Isolated lab deployment configuration

```ini
DPN_DS_AUTH_MODE=oidc
DPN_DS_RUNTIME_ENV=production
DPN_DS_OIDC_ISSUER=https://sso.example.com/realms/dpn
DPN_DS_OIDC_AUDIENCE=dpn-directory-services
DPN_DS_OIDC_PUBLIC_KEY_FILE=/etc/dpn-ds/issuer-public.pem
DPN_DS_OIDC_MFA_AMR=mfa
DPN_DS_OIDC_MAX_TOKEN_AGE_SECONDS=900
```

The public file must contain the trusted RS256 RSA PUBLIC KEY PEM copied from the IdP by the operator via a verified out-of-band process. It must not be writable by group/others. At startup a missing or unsafe key fails closed.

The external issuer must mint access tokens containing exact iss, aud, sub, iat, exp, token_use=access, an amr array containing mfa, and dpn_roles as an array with viewer/operator/security. Configure the IdP to protect the roles and MFA claims from end-user modification. A short token lifetime and audience dedicated to this API are mandatory.

Production runtime mode rejects legacy shared-token auth at startup. This alone does not imply production readiness. In legacy mode the shared token is explicitly evaluation-only and grants full read-only monitoring access.

## Audit security

All requests under /api/v1 emit a structured JSON event through the dpn_ds.security_audit logger, including rejected attempts. Only method, predefined endpoint, HTTP status, successful response flag, auth type, role, UTC timestamp, elapsed time and a pseudonymous actor hash are stored. No URLs with query strings, bearer tokens, passwords, JWT contents or raw subjects are logged.

The default service exposes the audit stream through stdout for systemd/journald or downstream collection. Immutable retention, collection pipeline, correlation, alerting and integrity protection are not implemented.

## Remaining production blockers

- OIDC authorization-code + PKCE browser login, refresh/session handling and issuer logout
- Token revocation strategy, automated signing-key rotation and provenance validation
- Key/role provisioning process with approvals
- Rate limiting, replay/abuse detection, audited retention and forwarding
- Security review and live Linux AD integration tests
- A separate least-privilege DRS monitoring agent; never run an internet-accessible root API

See README, SECURITY.md and ROADMAP.md.