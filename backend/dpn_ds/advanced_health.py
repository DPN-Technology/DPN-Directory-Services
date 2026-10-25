"""Opt-in, authenticated protocol checks and bounded local DRS replication report.

No directory write APIs; LDAP is read_only and TLS verification is mandatory.
Kerberos uses a dedicated, read-only principal's keytab and disposable ticket cache.
"""

from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import tempfile
from datetime import UTC, datetime

import ldap3

from dpn_ds.config import Settings
from dpn_ds.secure_files import SecretConfigurationError, read_secret_file, verify_keytab_file

PROBE_TIMEOUT_SECONDS = 5


def _result(code: str, title: str, status: str, detail: str) -> dict[str, str]:
    return {"code": code, "title": title, "status": status, "detail": detail}


class AdvancedHealth:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def ldaps_bind(self) -> dict[str, str]:
        s = self.settings
        title = "Authenticated LDAPS bind"
        if not s.ldap_bind_user and not s.ldap_password_file:
            return _result("ldaps_bind", title, "not_configured", "Read-only LDAP probe disabled")
        if not s.ldap_bind_user or not s.ldap_password_file:
            return _result("ldaps_bind", title, "unknown", "LDAP credential settings incomplete")
        try:
            password = read_secret_file(s.ldap_password_file)
        except SecretConfigurationError:
            return _result(
                "ldaps_bind", title, "unknown", "LDAP secret file is unavailable or unsafe"
            )
        conn = None
        try:
            tls = ldap3.Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS_CLIENT,
                ca_certs_file=s.ldap_ca_file or None,
            )
            server = ldap3.Server(
                s.controller, port=636, use_ssl=True, tls=tls,
                connect_timeout=PROBE_TIMEOUT_SECONDS, get_info=ldap3.NONE,
            )
            conn = ldap3.Connection(
                server, user=s.ldap_bind_user, password=password,
                authentication=ldap3.SIMPLE, auto_bind=False,
                auto_referrals=False, read_only=True,
                receive_timeout=PROBE_TIMEOUT_SECONDS, raise_exceptions=False,
            )
            bound = conn.bind()
            return _result(
                "ldaps_bind", title, "pass" if bound else "fail",
                "Read-only bind succeeded over certificate-validated TLS"
                if bound else "Bind rejected or TLS handshake unsuccessful",
            )
        except Exception:
            # The library can raise SSL, socket, or LDAP exceptions. Never expose
            # exception messages because they can include server/identity metadata.
            return _result("ldaps_bind", title, "fail", "LDAPS bind or TLS validation failed")
        finally:
            password = ""
            if conn is not None:
                try:
                    conn.unbind()
                except Exception:
                    pass

    def kerberos_keytab(self) -> dict[str, str]:
        s = self.settings
        title = "Kerberos keytab authentication"
        if not s.krb_principal and not s.krb_keytab_file:
            return _result(
                "krb_keytab", title, "not_configured", "Keytab principal probe disabled"
            )
        if not s.krb_principal or not s.krb_keytab_file:
            return _result(
                "krb_keytab", title, "unknown", "Kerberos principal settings incomplete"
            )
        try:
            verify_keytab_file(s.krb_keytab_file)
        except SecretConfigurationError:
            return _result(
                "krb_keytab", title, "unknown", "Keytab permissions or location are invalid"
            )
        executable = shutil.which("kinit")
        if not executable:
            return _result("krb_keytab", title, "unknown", "kinit is not installed")
        try:
            with tempfile.TemporaryDirectory(prefix="dpn-krb-") as temporary:
                env = {**os.environ}
                env.pop("KRB5_TRACE", None)
                env["KRB5CCNAME"] = "FILE:" + os.path.join(temporary, "ticket")
                env["LC_ALL"] = "C"
                response = subprocess.run(
                    [executable, "-k", "-t", s.krb_keytab_file, s.krb_principal],
                    env=env, check=False, capture_output=True, text=True,
                    timeout=PROBE_TIMEOUT_SECONDS,
                )
            if response.returncode != 0:
                return _result(
                    "krb_keytab", title, "fail", "KDC did not issue a ticket using keytab"
                )
            return _result(
                "krb_keytab", title, "pass", "KDC issued a TGT into a disposable cache"
            )
        except (OSError, subprocess.TimeoutExpired):
            return _result(
                "krb_keytab", title, "unknown", "Kerberos ticket probe unavailable or timed out"
            )

    def replication(self) -> dict[str, str]:
        title = "Inbound DRS replication"
        if not self.settings.enable_drs:
            return _result(
                "drs_inbound", title, "not_configured", "Local Samba DRS probe disabled"
            )
        executable = shutil.which("samba-tool")
        if not executable:
            return _result("drs_inbound", title, "unknown", "samba-tool unavailable")
        try:
            process = subprocess.run(
                [executable, "drs", "showrepl", "--json"],
                check=False, capture_output=True, text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
            )
            if process.returncode:
                return _result(
                    "drs_inbound", title, "unknown", "Replication metadata inaccessible"
                )
            if len(process.stdout) > 262144:
                return _result("drs_inbound", title, "unknown", "DRS output too large")
            content = json.loads(process.stdout)
            if not isinstance(content, dict) or not isinstance(content.get("repsFrom"), list):
                return _result("drs_inbound", title, "unknown", "Unsupported DRS JSON structure")
            neighbors = content["repsFrom"]
            if not neighbors:
                return _result(
                    "drs_inbound", title, "unknown",
                    "No inbound partners reported (possible single-DC topology)"
                )
            for neighbor in neighbors:
                if not isinstance(neighbor, dict):
                    return _result("drs_inbound", title, "unknown", "Unexpected partner entry")
                failures = neighbor.get("consecutive failures")
                state = neighbor.get("last attempt state")
                if not isinstance(failures, int) or not isinstance(state, list) or not state:
                    return _result(
                        "drs_inbound", title, "unknown", "Partner result fields incomplete"
                    )
                if not isinstance(state[0], int):
                    return _result("drs_inbound", title, "unknown", "Invalid partner result")
            failing = sum(
                item["consecutive failures"] > 0 or item["last attempt state"][0] != 0
                for item in neighbors
            )
            if failing:
                return _result(
                    "drs_inbound", title, "fail",
                    f"{failing} of {len(neighbors)} inbound partner entries report failure"
                )
            return _result(
                "drs_inbound", title, "pass",
                f"{len(neighbors)} inbound partner entries report last-attempt success"
            )
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return _result(
                "drs_inbound", title, "unknown", "Replication report unavailable"
            )

    def snapshot(self) -> dict:
        if self.settings.mode == "demo":
            checks = [
                _result("ldaps_bind", "Authenticated LDAPS bind", "simulated", "No bind executed"),
                _result(
                    "krb_keytab", "Kerberos keytab authentication", "simulated", "No KDC contacted"
                ),
                _result("drs_inbound", "Inbound DRS replication", "simulated", "No DRS query run"),
            ]
        else:
            checks = [self.ldaps_bind(), self.kerberos_keytab(), self.replication()]
        states = {item["status"] for item in checks}
        summary = (
            "simulated" if self.settings.mode == "demo"
            else "attention" if "fail" in states
            else "incomplete" if "unknown" in states or "not_configured" in states
            else "authenticated_checks_passed"
        )
        return {
            "mode": self.settings.mode,
            "checked_at": datetime.now(UTC).isoformat(),
            "summary": summary,
            "checks": checks,
            "disclaimer": (
                "LDAP bind and TGT issuance prove only configured account authentication. "
                "DRS checks only last-attempt inbound metadata; not cross-DC convergence, "
                "staleness, SYSVOL health or authorization policy."
            ),
        }
