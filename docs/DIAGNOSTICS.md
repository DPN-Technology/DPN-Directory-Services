# Domain readiness diagnostics — alpha preflight

DPN DS runs five fixed, bounded **read-only** checks. They do not validate AD authentication, encryption, replication or SYSVOL integrity.

| Check | What it actually verifies | Important limitation |
|---|---|---|
| AD DC discovery | DNS SRV lookup for _ldap._tcp.dc._msdcs.DOMAIN | Does not authenticate or test DC site selection |
| Kerberos discovery | DNS SRV lookup for _kerberos._tcp.DOMAIN | Does not obtain a Kerberos ticket |
| LDAP TCP | TCP port 389 accepts a connection on configured DC | Does not perform LDAP bind; does not imply LDAPS/TLS |
| Kerberos TCP | TCP port 88 accepts a connection on configured DC | Does not perform Kerberos authentication |
| Local NTP | timedatectl reports NTPSynchronized | Does not measure client-to-controller time skew |

Queries target the **server-configured realm and controller** only; there is no user-supplied hostname, IP or port parameter. Default per-probe timeout 1.5 seconds; upper bound 3 seconds.

- basic_checks_passed: All five limited preflight probes passed.
- attention: One or more probes failed.
- incomplete: One or more probes are unknown and none failed.
- simulated: Demo mode; no probes were run.

Each request produces a fresh snapshot. This is not historical monitoring and will not generate alerts.

## Run on a trusted test network

Use the same backend setup described in the repository developer guide, with DPN_DS_MODE=samba, DPN_DS_REALM set to your lab domain and DPN_DS_CONTROLLER set to your lab DC's FQDN.

Your backend machine must use an **AD-aware DNS resolver**. The host's ordinary DNS resolver is queried, so a public DNS resolver will typically fail for private AD zones.

Operator-side checks for comparison:

~~~bash
dig SRV _ldap._tcp.dc._msdcs.corp.example.com
dig SRV _kerberos._tcp.corp.example.com
timedatectl show -p NTPSynchronized
~~~

Never put service credentials in CLI arguments, GitHub issues, screenshots or frontend source.

See the Ubuntu Samba AD DC provisioning guide: https://ubuntu.com/server/docs/how-to/samba/provision-samba-ad-controller/

Still required for full production readiness: LDAP auth/TLS validation, Kerberos ticket test, replication verification, DC time-offset validation, DNS consistency and hardened operator authentication.
