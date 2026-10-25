"""Environment-only service configuration; no secrets baked into source control."""

import os
from dataclasses import dataclass

from dpn_ds.secure_files import read_secret_file


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
    ldap_bind_user: str = ""
    ldap_password_file: str = ""
    ldap_ca_file: str = ""
    krb_principal: str = ""
    krb_keytab_file: str = ""
    enable_drs: bool = False

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
            api_token=(
                read_secret_file(os.environ["DPN_DS_API_TOKEN_FILE"])
                if os.getenv("DPN_DS_API_TOKEN_FILE")
                else os.getenv("DPN_DS_API_TOKEN", "")
            ),
            mode=os.getenv("DPN_DS_MODE", "samba").lower(),
            realm=os.getenv("DPN_DS_REALM", "corp.example.com"),
            controller=os.getenv("DPN_DS_CONTROLLER", "localhost"),
            cors_origins=origins,
            ldap_bind_user=os.getenv("DPN_DS_LDAP_BIND_USER", ""),
            ldap_password_file=os.getenv("DPN_DS_LDAP_PASSWORD_FILE", ""),
            ldap_ca_file=os.getenv("DPN_DS_LDAP_CA_FILE", ""),
            krb_principal=os.getenv("DPN_DS_KRB_PRINCIPAL", ""),
            krb_keytab_file=os.getenv("DPN_DS_KRB_KEYTAB_FILE", ""),
            enable_drs=os.getenv("DPN_DS_ENABLE_DRS", "").lower() in ("1", "true", "yes"),
        )
