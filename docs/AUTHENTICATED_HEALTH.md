# Authenticated domain checks — evaluation guide

DPN Directory Services now includes a separate, opt-in read-only health endpoint at GET /api/v1/advanced-health.

**Production warning:** This does not make the platform a production identity provider or domain controller. Keep the API bound to loopback and use an isolated lab. No browser credential submission and no directory write methods.

## Checks and limitations

| Check | What it proves | What it cannot prove |
|---|---|---|
| LDAPS service-account bind | Restricted service identity can authenticate to configured DC over port 636 with TLS certificate validation | Access authorization, replication, password policy, service availability elsewhere |
| Kerberos keytab request | Configured principal obtains a TGT with a keytab from KDC in a disposable cache | Service ticket issuance, end-user logins, resource access |
| Samba DRS showrepl | Last inbound replication attempt state + failure counters from local Samba JSON report | Freshness, actual cross-DC convergence, DNS/SYSVOL, multi-DC completeness |

Statuses: pass, fail, unknown, not_configured, simulated. An entirely unconfigured installation must report incomplete, not healthy. A single-DC environment without inbound partners reports unknown.

## Restrict credentials

Create a *dedicated non-administrator* domain identity. It should be allowed only to authenticate as itself; domain admin membership is not necessary for LDAP simple bind or a keytab ticket check. The operator provisions the identity and service keytab manually, not via this console.

Recommended deployment with systemd:

- Install the backend virtual environment in /opt/dpn-ds/backend/.venv, owned by root and read-only to the service.
- Store a freshly generated bearer token at /etc/dpn-ds/api-token, root:root, mode 0600.
- Deploy the reference systemd unit at deploy/systemd/dpn-ds.service. Its LoadCredential entry provides the token at %d/api_token; DPN_DS_API_TOKEN_FILE takes precedence over developer-only DPN_DS_API_TOKEN.
- Put non-secret domain settings into /etc/dpn-ds/service.env based on deploy/systemd/service.env.example.
- To enable LDAPS, configure DPN_DS_LDAP_BIND_USER with the restricted username and DPN_DS_LDAP_PASSWORD_FILE with the *absolute path* to a systemd LoadCredential file, protected for the service UID; optionally configure DPN_DS_LDAP_CA_FILE to the trusted internal CA PEM.
- To enable Kerberos, configure DPN_DS_KRB_PRINCIPAL and DPN_DS_KRB_KEYTAB_FILE with the absolute path to a protected keytab. The app creates an isolated temporary ticket cache, deletes it after each probe and never returns ticket data.
- To enable local DRS checks, set DPN_DS_ENABLE_DRS=true **only if** a least-privilege read-only Samba access path is already available. DynamicUser normally cannot read root-owned Samba state. Never run the API as root or give Domain Admin rights to make a diagnostic pass.

Sample systemd credential drop-in:

~~~ini
[Service]
LoadCredential=ldap_password:/etc/dpn-ds/ldap-password
LoadCredential=keytab:/etc/dpn-ds/monitor.keytab
Environment=DPN_DS_LDAP_PASSWORD_FILE=%d/ldap_password
Environment=DPN_DS_KRB_KEYTAB_FILE=%d/keytab
~~~

The root-owned source files should be mode 0600 and should never be committed. The systemd credential files are managed with restrictive permissions. For development without systemd, set absolute secret-file paths owned by the backend UID with mode 0600.

## Security boundaries

- LDAP uses port 636 only and ldap3 Tls with ssl.CERT_REQUIRED. Never disable validation.
- The authenticated LDAP connection has read_only=True, disables LDAP referrals and issues only a bind.
- Kerberos runs a fixed kinit command, with no shell and no operator-controlled CLI args.
- Replication uses only fixed samba-tool drs showrepl --json, never drs replicate/kcc.
- Malformed or inaccessible DRS output reports unknown, not success.
- No backend error details containing credentials are returned to browser.

## Deployment and testing

From the repository root, after setting up the virtual environment:

~~~bash
cd backend
python -m pip install -e ".[dev]"
ruff check .
python -m pytest -q
~~~

Follow docs/DEVELOPMENT.md for starting the frontend. To test the authenticated checks against a real lab domain, provide the restricted identity, CA and keytab as described above. CI runs only mocked tests; a green CI run is **not** proof of live domain compatibility.

Remaining requirements before production: OIDC/MFA, per-user RBAC, audited operator actions, rate limiting, privilege-isolated replication exporter, key rotation, signed deployments, tested backups and restore drills, security review and validated live integration.
