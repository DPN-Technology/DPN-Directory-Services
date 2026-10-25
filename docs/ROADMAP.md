# DPN DS Roadmap

This document separates delivered implementation from intended capabilities. Labels are not claims that features currently exist.

## P0 — Development foundation (v0.1)
- [x] Initialize repository and engineering specifications
- [x] Build read-only API endpoints
- [x] Add explicit demo data adapter and Samba CLI adapter
- [x] Create responsive DPN administrative console
- [x] Add unit tests for API authentication, allowlisted commands, sanitized failure
- [x] Create CI gates and dependency auditing workflows
- [ ] Verify GitHub CI pass, review and merge

## P1 — Production architecture readiness
- [ ] Define LDAP-over-TLS / read-only service identity integration
- [x] Publish unprivileged systemd API service template with LoadCredential support
- [ ] Separate high-privilege local Samba operations from HTTP API process
- [x] Verify external OIDC access tokens using a pinned RS256 public key, issuer, audience, MFA assertion and read-only RBAC
- [ ] Interactive OIDC authorization code + PKCE, session management and token revocation
- [x] Sanitize and emit per-request JSON security audit events for journald ingestion
- [ ] Tamper-evident centralized audit forwarding, integrity and retention
- [ ] Threat modeling, security review, tested incident recovery procedure
- [ ] TLS proxy, secrets management, rate limiting, signed releases
- [ ] Reproducible dependency lockfiles, SBOM, and production packaging

## P2 — Domain infrastructure telemetry
- [x] Limited DNS SRV, TCP LDAP/Kerberos reachability and local NTP preflight
- [x] Opt-in credential-validated LDAPS bind and Kerberos keytab TGT checks
- [x] Local Samba DRS JSON inbound last-attempt summaries (not full replication monitoring)
- [ ] Measured domain clock offsets, service-ticket checks and live integration validation
- [ ] Domain controller replication convergence, DNS and SYSVOL state
- [ ] Machine account lifecycle and stale host detection
- [ ] Inventory paging, group membership, domain scope and search
- [ ] Alerting integration with DPN WatchTower

## P3 — Auditable change management
- [ ] Least privilege for individual directory operations
- [ ] Request/approval workflows with second-person review for privileged changes
- [ ] Create/disable users, access-group changes, account lifecycle
- [ ] Undo / rollback plans and operational change logs
- [ ] No password exposure in frontends, logs, subprocess args, or Git

## P4 — Linux fleet operations
- [ ] Assisted SSSD/realmd join, health, and de-enrollment
- [ ] Linux-specific sudo and SSH authorization strategy
- [ ] Policy baselines with signed configuration deployments and drift reports
- [ ] DPN OS integration

## Release policy
Security boundaries must not be weakened to pass tests. A green test suite is necessary but insufficient for production: successful lab deployments, documented restore tests, and an independent review are required.
