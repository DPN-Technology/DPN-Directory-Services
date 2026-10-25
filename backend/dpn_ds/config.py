"""Environment-only service configuration; no secrets baked into source control."""

import os
from dataclasses import dataclass


def _valid_hostname(value: str) -> bool:
    """Reject empty/unsafe domain host values, URLs, and shell metacharacters."""
    if not value or len(value) > 253:
        return False
    return all(
        1 <= len(label) <= 63
        and label[0].isascii() and label[0].isalnum()
        and label[-1].isascii() and label[-1].isalnum()
        and all(char.isascii() and (char.isalnum() or char == "-") for char in label)
        for label in value.split(".")
    )


@dataclass(frozen=True)
class Settings:
    api_token: str
    mode: str = "samba"
    realm: str = "corp.example.com"
    controller: str = "localhost"
    cors_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in ("demo", "samba"):
            raise ValueError("DPN_DS_MODE must be 'demo' or 'samba'")
        if not _valid_hostname(self.realm) or "." not in self.realm:
            raise ValueError("DPN_DS_REALM must be a valid DNS domain")
        if not _valid_hostname(self.controller):
            raise ValueError("DPN_DS_CONTROLLER must be a valid host or IP address")
        if self.cors_origins and any(
            not origin.startswith(("http://", "https://")) for origin in self.cors_origins
        ):
            raise ValueError("DPN_DS_CORS_ORIGINS must contain complete origins")

    @classmethod
    def from_env(cls) -> "Settings":
        origins = tuple(
            origin.strip()
            for origin in os.getenv("DPN_DS_CORS_ORIGINS", "").split(",")
            if origin.strip()
        )
        return cls(
            api_token=os.getenv("DPN_DS_API_TOKEN", ""),
            mode=os.getenv("DPN_DS_MODE", "samba").lower(),
            realm=os.getenv("DPN_DS_REALM", "corp.example.com"),
            controller=os.getenv("DPN_DS_CONTROLLER", "localhost"),
            cors_origins=origins,
        )
