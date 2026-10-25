"""Read deployment-managed secrets with strict file permissions and no symlink following."""

from __future__ import annotations

import os
import stat


class SecretConfigurationError(ValueError):
    """Deliberately excludes paths or contents from error messages."""


def read_secret_file(path: str, *, max_bytes: int = 8192) -> str:
    if not os.path.isabs(path):
        raise SecretConfigurationError("Secret file must be an absolute path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SecretConfigurationError("Secret file cannot be opened") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecretConfigurationError("Secret source must be a regular file")
        if metadata.st_mode & 0o077:
            raise SecretConfigurationError("Secret file permissions are too permissive")
        if metadata.st_uid not in (os.geteuid(), 0):
            raise SecretConfigurationError("Secret file owner is not trusted")
        if metadata.st_size > max_bytes:
            raise SecretConfigurationError("Secret file exceeds maximum size")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise SecretConfigurationError("Secret file exceeds maximum size")
        value = payload.decode("utf-8").rstrip("\r\n")
        if not value or "\x00" in value:
            raise SecretConfigurationError("Secret file content is invalid")
        return value
    except UnicodeError as exc:
        raise SecretConfigurationError("Secret file encoding is invalid") from exc
    finally:
        os.close(descriptor)


def verify_keytab_file(path: str) -> None:
    """Keytabs are credentials; validate file metadata, never open/read their bytes."""
    if not os.path.isabs(path):
        raise SecretConfigurationError("Keytab must have an absolute path")
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SecretConfigurationError("Keytab is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SecretConfigurationError("Keytab must be a regular file, not a link")
    if metadata.st_mode & 0o077 or metadata.st_uid not in (0, os.geteuid()):
        raise SecretConfigurationError("Keytab ownership or permissions are unsafe")
    if metadata.st_size <= 0 or metadata.st_size > 65536:
        raise SecretConfigurationError("Keytab size is invalid")
    if not os.access(path, os.R_OK):
        raise SecretConfigurationError("Keytab is not readable by service identity")
