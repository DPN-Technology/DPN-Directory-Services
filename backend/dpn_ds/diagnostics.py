"""Bounded, read-only AD discovery and network reachability preflight.

Results are not proof of successful authentication, healthy AD, or replication.
All target hostnames come from deployment configuration, never an HTTP request.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from datetime import UTC, datetime

import dns.exception
import dns.resolver


class DomainDiagnostics:
    def __init__(self, realm: str, controller: str, mode: str, timeout: float = 1.5) -> None:
        self.realm = realm
        self.controller = controller
        self.mode = mode
        self.timeout = min(max(timeout, 0.25), 3.0)

    @staticmethod
    def _check(code: str, title: str, status: str, detail: str, target: str) -> dict[str, str]:
        return {"code": code, "title": title, "status": status, "detail": detail, "target": target}

    def _dns(self, code: str, title: str, query: str) -> dict[str, str]:
        try:
            answer = dns.resolver.resolve(query, "SRV", lifetime=self.timeout)
            count = len(list(answer))
        except (dns.exception.DNSException, OSError):
            return self._check(code, title, "fail", "SRV lookup failed via host DNS", query)
        if not count:
            return self._check(code, title, "fail", "No SRV records returned", query)
        return self._check(code, title, "pass", f"{count} SRV record(s) found", query)

    def _port(self, code: str, title: str, port: int) -> dict[str, str]:
        target = f"{self.controller}:{port}"
        try:
            with socket.create_connection((self.controller, port), timeout=self.timeout):
                pass
        except OSError:
            return self._check(code, title, "fail", "TCP connection not established", target)
        return self._check(
            code, title, "pass", "TCP reachable; authentication untested", target
        )

    def _time(self) -> dict[str, str]:
        target = "local timedatectl"
        executable = shutil.which("timedatectl")
        if not executable:
            return self._check(
                "ntp_local", "Local clock synchronization", "unknown",
                "timedatectl unavailable", target
            )
        try:
            result = subprocess.run(
                [executable, "show", "-p", "NTPSynchronized", "--value"],
                check=False, capture_output=True, text=True, timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return self._check(
                "ntp_local", "Local clock synchronization", "unknown",
                "Time synchronization query failed", target
            )
        if result.returncode != 0:
            return self._check(
                "ntp_local", "Local clock synchronization", "unknown",
                "Clock status unavailable", target
            )
        state = result.stdout.strip().lower()
        if state == "yes":
            return self._check(
                "ntp_local", "Local clock synchronization", "pass",
                "Host synchronized; DC time offset unmeasured", target
            )
        if state == "no":
            return self._check(
                "ntp_local", "Local clock synchronization", "fail",
                "Host reports unsynchronized clock", target
            )
        return self._check(
            "ntp_local", "Local clock synchronization", "unknown",
            "Unrecognized clock status", target
        )

    def snapshot(self) -> dict:
        targets = (
            ("dns_ldap", "AD controller discovery", f"_ldap._tcp.dc._msdcs.{self.realm}"),
            ("dns_kerberos", "Kerberos service discovery", f"_kerberos._tcp.{self.realm}"),
            ("tcp_ldap", "LDAP TCP reachability", f"{self.controller}:389"),
            ("tcp_kerberos", "Kerberos TCP reachability", f"{self.controller}:88"),
            ("ntp_local", "Local clock synchronization", "local timedatectl"),
        )
        if self.mode == "demo":
            checks = [
                self._check(code, title, "simulated", "Demo data; no probe executed", target)
                for code, title, target in targets
            ]
            summary = "simulated"
        else:
            checks = [
                self._dns(targets[0][0], targets[0][1], targets[0][2]),
                self._dns(targets[1][0], targets[1][1], targets[1][2]),
                self._port("tcp_ldap", "LDAP TCP reachability", 389),
                self._port("tcp_kerberos", "Kerberos TCP reachability", 88),
                self._time(),
            ]
            statuses = {item["status"] for item in checks}
            summary = (
                "attention" if "fail" in statuses
                else "incomplete" if "unknown" in statuses
                else "basic_checks_passed"
            )
        return {
            "mode": self.mode,
            "realm": self.realm,
            "controller": self.controller,
            "checked_at": datetime.now(UTC).isoformat(),
            "summary": summary,
            "checks": checks,
            "disclaimer": (
                "Connectivity and local configuration only; this does not prove "
                "Kerberos ticket issuance, LDAP bind success, or AD replication."
            ),
        }
