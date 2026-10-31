from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    vault_addr: str
    ca_file: Path
    identity_dir: Path
    db_host: str
    db_port: int
    db_name: str
    db_ca_file: Path

    @classmethod
    def from_env(cls) -> "Settings":
        vault_addr = os.getenv("VAULT_ADDR", "https://vault:8200").rstrip("/")
        if not vault_addr.startswith("https://"):
            raise ValueError("Vault requires an HTTPS address")
        return cls(
            vault_addr=vault_addr,
            ca_file=Path(os.getenv("VAULT_CACERT", "/run/certs/ca.crt")),
            identity_dir=Path(os.getenv("VAULT_IDENTITY_DIR", "/run/identity")),
            db_host=os.getenv("DB_HOST", "postgres"),
            db_port=int(os.getenv("DB_PORT", "5432")),
            db_name=os.getenv("DB_NAME", "coursework"),
            db_ca_file=Path(os.getenv("DB_SSLROOTCERT", "/run/certs/ca.crt")),
        )
