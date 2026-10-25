"""Directory adapters. The Samba adapter has NO write-capable code paths."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Protocol


class DirectoryUnavailable(RuntimeError):
    """Controlled error type; never carry command stderr or secrets to API clients."""


class Directory(Protocol):
    def users(self) -> list[dict[str, str]]: ...
    def groups(self) -> list[dict[str, str]]: ...
    def devices(self) -> list[dict[str, str]]: ...
    def controller_status(self) -> str: ...


class DemoDirectory:
    """Explicitly fake data. Only used when DPN_DS_MODE=demo."""

    def users(self) -> list[dict[str, str]]:
        return [{"name": name, "kind": "user"} for name in (
            "Administrator", "a.morgan", "b.chen", "c.rivera", "helpdesk"
        )]

    def groups(self) -> list[dict[str, str]]:
        return [{"name": name, "kind": "group"} for name in (
            "Domain Admins", "Domain Users", "DPN IT", "DPN Engineering"
        )]

    def devices(self) -> list[dict[str, str]]:
        return [{"name": name, "kind": "device"} for name in (
            "DPN-DC01", "DPN-LNX-01", "DPN-LNX-02", "DPN-WKS-04"
        )]

    def controller_status(self) -> str:
        return "simulated"


class SambaDirectory:
    """Read Samba AD DC metadata through a strictly fixed command allowlist.

    This operates against the local machine. Run the service only with an
    appropriate, separately configured read-authorized identity; never add
    arbitrary command execution or pass user input to subprocess arguments.
    """

    _COMMANDS = {
        "users": ("user", "list"),
        "groups": ("group", "list"),
        "devices": ("computer", "list"),
    }

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def _query(self, resource: str) -> list[dict[str, str]]:
        if resource not in self._COMMANDS:
            raise DirectoryUnavailable("Unsupported directory query")
        executable = shutil.which("samba-tool")
        if not executable:
            raise DirectoryUnavailable("Samba domain tools are unavailable")
        try:
            result = subprocess.run(
                [executable, *self._COMMANDS[resource]],
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise DirectoryUnavailable("Directory lookup failed") from exc
        # A stable sort makes the UI deterministic. No subprocess stderr is returned.
        names = sorted(
            {line.strip() for line in result.stdout.splitlines() if line.strip()},
            key=str.casefold,
        )
        kind = {"users": "user", "groups": "group", "devices": "device"}[resource]
        return [{"name": name, "kind": kind} for name in names]

    def users(self) -> list[dict[str, str]]:
        return self._query("users")

    def groups(self) -> list[dict[str, str]]:
        return self._query("groups")

    def devices(self) -> list[dict[str, str]]:
        return self._query("devices")

    def controller_status(self) -> str:
        systemctl = shutil.which("systemctl")
        if not systemctl:
            return "unknown"
        try:
            result = subprocess.run(
                [systemctl, "is-active", "--quiet", "samba-ad-dc"],
                capture_output=True,
                check=False,
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        return "online" if result.returncode == 0 else "degraded"
