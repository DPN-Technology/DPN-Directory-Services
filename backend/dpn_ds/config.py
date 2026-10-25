"""Environment-only service configuration; no secrets baked into source control."""

from dataclasses import dataclass
import os


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
        if self.cors_origins and any(not x.startswith(("http://", "https://")) for x in self.cors_origins):
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
