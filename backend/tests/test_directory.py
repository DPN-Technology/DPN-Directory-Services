import subprocess
from unittest.mock import patch

import pytest

from dpn_ds.directory import DirectoryUnavailable, SambaDirectory


def test_list_users_uses_only_allowlisted_arguments():
    directory = SambaDirectory()
    mocked = subprocess.CompletedProcess(
        args=["/usr/bin/samba-tool", "user", "list"],
        returncode=0,
        stdout="zeta\nalpha\nalpha\n\n",
        stderr="",
    )
    with patch("dpn_ds.directory.shutil.which", return_value="/usr/bin/samba-tool"):
        with patch("dpn_ds.directory.subprocess.run", return_value=mocked) as run:
            actual = directory.users()
    assert actual == [
        {"name": "alpha", "kind": "user"},
        {"name": "zeta", "kind": "user"},
    ]
    args, kwargs = run.call_args
    assert args[0] == ["/usr/bin/samba-tool", "user", "list"]
    assert "shell" not in kwargs
    assert kwargs["timeout"] == 10.0


def test_samba_error_is_sanitized():
    directory = SambaDirectory()
    error = subprocess.CalledProcessError(1, "samba-tool", stderr="SECRET")
    with patch("dpn_ds.directory.shutil.which", return_value="/usr/bin/samba-tool"):
        with patch("dpn_ds.directory.subprocess.run", side_effect=error):
            with pytest.raises(DirectoryUnavailable, match="Directory lookup failed") as exc:
                directory.users()
    assert "SECRET" not in str(exc.value)


def test_controller_status():
    directory = SambaDirectory()
    with patch("dpn_ds.directory.shutil.which", return_value="/usr/bin/systemctl"):
        with patch("dpn_ds.directory.subprocess.run") as run:
            run.return_value.returncode = 0
            assert directory.controller_status() == "online"
            run.return_value.returncode = 3
            assert directory.controller_status() == "degraded"
