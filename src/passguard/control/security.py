from dataclasses import dataclass
import hashlib
import hmac
import os
import secrets

from pwdlib import PasswordHash


PASSWORDS = PasswordHash.recommended()
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
COOKIE_NAME = "passguard_session"
COOKIE_PATH = "/api/control"


def hash_password(password: str) -> str:
    return PASSWORDS.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return PASSWORDS.verify(password, encoded)
    except Exception:
        # A malformed stored hash fails closed and never enters a traceback.
        return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def valid_csrf(provided: str | None, expected: str) -> bool:
    return bool(provided) and hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


@dataclass(frozen=True)
class SecuritySettings:
    session_seconds: int = 8 * 60 * 60
    cookie_secure: bool = False
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:8000", "http://localhost:8000")

    @classmethod
    def from_env(cls):
        origins = tuple(x.strip() for x in os.getenv(
            "CONTROL_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000"
        ).split(",") if x.strip())
        ttl = int(os.getenv("CONTROL_SESSION_SECONDS", "28800"))
        if not 60 <= ttl <= 86400 or not origins or any(x == "*" for x in origins):
            raise ValueError("Invalid control security configuration")
        return cls(ttl, os.getenv("COOKIE_SECURE", "false").lower() == "true", origins)
