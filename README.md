<div align="center">

# ⚡ DPN DIRECTORY SERVICES
### ENTERPRISE LINUX IDENTITY & DOMAIN OPERATIONS

**DEVELOP · PIONEER · NAVIGATE**

![Development](https://img.shields.io/badge/STATUS-ALPHA_0.1.0-BC2842?style=for-the-badge)
![Platform](https://img.shields.io/badge/LINUX-FIRST-11151D?style=for-the-badge)
![Directory](https://img.shields.io/badge/SAMBA-AD_DC-BC2842?style=for-the-badge)
![Access](https://img.shields.io/badge/API-READ_ONLY-11151D?style=for-the-badge)

**A secure operational interface for Linux-first Active Directory environments.**

</div>

---

## THE PLATFORM

DPN DS is a new DPN Technology management console built around the existing, proven Samba Active Directory Domain Controller. **It does not reimplement or replace LDAP, Kerberos, DNS, or the underlying domain controller.**

**First development milestone (v0.1)**

| Surface | Current delivery |
|---|---|
| Domain dashboard | Domain name, configured controller, backend mode and counts |
| Identity inventory | Read-only user enumeration |
| Security groups | Read-only domain group inventory |
| Computer objects | Read-only managed computer listing |
| Controller signal | Local samba-ad-dc systemd service status (not a replication or Kerberos check) |
| Domain readiness | Bounded DNS SRV, LDAP/Kerberos TCP, and local time-sync preflight (not authentication) |
| Authenticated preflight | Opt-in certificate-validated LDAPS bind, isolated Kerberos TGT test and inbound DRS metadata inspection |
| API security | Bearer-token gate for every /api/v1 route; no mutation endpoints |
| Backend adapters | Explicit Demo mode, or real Samba CLI list commands |
| Console | Responsive React/TypeScript interface, DPN black/red visual system |
| Quality gates | Python tests/lint, TypeScript/Vite build, dependency audits |

> **ALPHA / EVALUATION ONLY.** This is not a production-ready privileged domain administration service. No user creation, password reset, policy deployment, MFA/RBAC, or controller replication orchestration is present yet.

## DESIGN PRINCIPLES

- **Directory protocols belong to Samba.** We build the management plane, not a second authentication stack.
- **Fail closed.** API calls require an operator token; absence of a configured token yields 503, not open access.
- **Demo data is labeled.** Simulated results cannot be confused with a live domain.
- **No destructive commands.** Backend commands are fixed, allowlisted, read-only argument arrays. No user-provided command execution.
- **Progress through gates.** Changes arrive through pull requests, tests and security review.

## START THE EVALUATION BUILD

Requirements: **Python 3.11+**, **Node.js 20.19+** (or 22.12+) and npm. Two local terminals.

**1. API (demo data)**

~~~bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

# Create your OWN high-entropy token. Do not commit the value.
export DPN_DS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DPN_DS_MODE=demo
export DPN_DS_REALM=corp.example.com
export DPN_DS_CONTROLLER=dc01.corp.example.com
echo "Copy this API token into the console: $DPN_DS_API_TOKEN"
uvicorn dpn_ds.app:app --host 127.0.0.1 --port 8000
~~~

**2. Console (new terminal)**

~~~bash
cd frontend
npm install
npm run dev
~~~

Open **http://127.0.0.1:5173** and use the token generated in step 1. The token is held in page memory only, not localStorage.

**3. Switch to local Samba mode (isolated lab only)**

Set DPN_DS_MODE=samba and configure DPN_DS_REALM / DPN_DS_CONTROLLER; the API then queries locally installed samba-tool. The backend reports failure rather than silently switching back to fake data.

**Do not bind this API to 0.0.0.0 or publish it on the internet.** Samba directory access may require local privileges: a least-privilege agent and reviewed multi-user authentication architecture are prerequisites for production.

## DEVELOPMENT STRUCTURE

~~~text
backend/
  dpn_ds/
    app.py             # guarded REST API
    config.py          # environment-only settings
    directory.py       # fixed Samba CLI / explicit demo adapter
  tests/               # auth, allowlist, error isolation
frontend/
  src/
    App.tsx            # operational dashboard and inventories
    styles.css         # DPN identity visual system / responsive design
docs/
  ARCHITECTURE.md     # trust boundaries and product scope
  SECURITY.md         # controls, known gaps and blockers
  DEVELOPMENT.md      # step-by-step local developer setup
  ROADMAP.md          # planned workstreams and release gates
.github/workflows/ci.yml
~~~

## ENGINEERING ROADMAP

**Phase 01 — Foundation (this PR):** initial read-only dashboard and backend, demo adapter, Samba adapter, CI/security scans.

**Phase 02 — Domain readiness:** basic connection diagnostics and opt-in authenticated LDAPS/Kerberos/DRS checks implemented; full replication monitoring, account separation, inventory search/pagination remain upcoming.

**Phase 03 — Secure administration:** OIDC/MFA, scoped RBAC, reviewed and auditable user/group change workflows, approval controls and immutable audit events.

**Phase 04 — Linux operations:** SSSD enrollment workflows, fleet status, Linux-specific sudo/SSH/host access management and policy orchestration.

**Phase 05 — DPN platform integration:** DPN OS, Operational Control, WatchTower and central identity integration, backed by stable APIs.

[Authenticated checks](docs/AUTHENTICATED_HEALTH.md) · [Diagnostics guide](docs/DIAGNOSTICS.md) · [Read the full roadmap](docs/ROADMAP.md) · [Architecture](docs/ARCHITECTURE.md) · [Security](docs/SECURITY.md) · [Developer guide](docs/DEVELOPMENT.md)

## SECURITY AND OWNERSHIP

The platform is **evaluation software, not an identity provider or hardened internet-facing control panel**. See [SECURITY.md](docs/SECURITY.md) before deploying. Keep credentials and directory dumps out of GitHub issues.

**© 2026 DPN Technology. All rights reserved.** No open-source license is granted by this repository unless DPN Technology separately publishes one.
