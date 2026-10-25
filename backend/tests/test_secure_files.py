from pathlib import Path

import pytest

from dpn_ds.secure_files import (
    SecretConfigurationError,
    read_secret_file,
    verify_keytab_file,
)


def test_restricted_token_file(tmp_path: Path):
    path = tmp_path / "token"
    path.write_text("value with spaces\n")
    path.chmod(0o600)
    assert read_secret_file(str(path)) == "value with spaces"


def test_reject_group_world_readability_and_symlink(tmp_path: Path):
    path = tmp_path / "secret"
    path.write_text("do-not-leak")
    path.chmod(0o644)
    with pytest.raises(SecretConfigurationError):
        read_secret_file(str(path))
    path.chmod(0o600)
    link = tmp_path / "alias"
    link.symlink_to(path)
    with pytest.raises(SecretConfigurationError):
        read_secret_file(str(link))


def test_reject_oversize_and_nul(tmp_path: Path):
    path = tmp_path / "secret"
    path.write_bytes(b"x" * 32)
    path.chmod(0o600)
    with pytest.raises(SecretConfigurationError):
        read_secret_file(str(path), max_bytes=8)
    path.write_bytes(b"x\x00y")
    with pytest.raises(SecretConfigurationError):
        read_secret_file(str(path))


def test_keytab_permissions(tmp_path: Path):
    path = tmp_path / "monitor.keytab"
    path.write_bytes(b"fixture-only")
    path.chmod(0o600)
    verify_keytab_file(str(path))
    path.chmod(0o640)
    with pytest.raises(SecretConfigurationError):
        verify_keytab_file(str(path))
