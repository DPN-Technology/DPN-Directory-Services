# DPN Directory Services — Architecture (v0.1)

## The boundaries

DPN DS is **not** a homegrown Active Directory implementation. Samba AD DC is authoritative for LDAP, Kerberos, DNS, and the directory database. DPN DS is an optional administration and observability plane.

- **Backend (FastAPI):** a narrow read-only, bearer-gated REST API.
- **Samba adapter:** a fixed allowlist of local samba-tool list commands: user, group, computer. No shell, arbitrary args, passwords, or mutations.
- **Demo adapter:** explicitly simulated records for UI development; never silently substituted for a failed Samba call.
- **Frontend (React/Vite):** a responsive console. Token is held in memory only. No localStorage, hardcoded API tokens, or demo credentials.
- **Future:** RBAC / OIDC, per-action audit trails, directory write procedures with approvals, DC replication metrics, configuration policy, Linux client SSSD enrollment assistance.

## Request flow

Browser (HTTPS in deployment) -> trusted reverse proxy -> loopback API -> Samba adapter -> local Samba AD DC.

The frontend and API should share one origin in deployment. An authorization header is required for every directory endpoint; unauthenticated /healthz discloses only process liveness.

## What v0.1 does NOT do

- Create or modify domain objects, groups, passwords, or devices
- Issue Kerberos tickets or manage users' secrets
- Provide a secure public multi-user administrator console
- Deploy Samba, join Linux clients, replicate DCs, set DNS, or alter sudo policies
- Guarantee that a locally unprivileged backend process can read Samba's private database

Before production: replace initial bearer-token operator access with OIDC/MFA + centrally audited RBAC; isolate Samba access in a least-privilege adapter/agent; prove backups and restores; enforce audit/alert handling; threat-model every mutation.
