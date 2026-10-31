from dataclasses import dataclass, field
from pathlib import Path
import ssl
import threading
import time
from typing import Any

import httpx
from pydantic import SecretStr


class VaultError(Exception):
    """Errors deliberately omit Vault response bodies and credentials."""


class VaultDenied(VaultError):
    pass


class VaultUnavailable(VaultError):
    pass


@dataclass(frozen=True)
class DatabaseCredentials:
    username: str
    password: SecretStr = field(repr=False)


class VaultClient:
    def __init__(
        self,
        addr: str,
        ca_file: Path,
        identity_dir: Path,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not addr.startswith("https://"):
            raise ValueError("Vault requires HTTPS")
        context = ssl.create_default_context(cafile=str(ca_file))
        self._http = httpx.Client(
            base_url=addr,
            verify=context,
            timeout=5,
            trust_env=False,
            transport=transport,
        )
        self._identity_dir = identity_dir
        self._token = SecretStr("")
        self._expires_at = 0.0
        self._lock = threading.RLock()

    def _login(self) -> None:
        try:
            role_id = (self._identity_dir / "role_id").read_text().strip()
            secret_id = (self._identity_dir / "secret_id").read_text().strip()
            if not role_id or not secret_id:
                raise ValueError("Empty identity")
            response = self._http.post(
                "/v1/auth/approle/login",
                json={"role_id": role_id, "secret_id": secret_id},
            )
        except (OSError, ValueError, httpx.HTTPError):
            raise VaultUnavailable("Vault authentication is unavailable") from None
        if response.status_code in (400, 403):
            raise VaultDenied("Vault identity was rejected")
        if response.status_code != 200:
            raise VaultUnavailable("Vault authentication is unavailable")
        try:
            auth = response.json()["auth"]
            token = auth["client_token"]
            ttl = int(auth["lease_duration"])
            if not isinstance(token, str) or not token or ttl <= 0:
                raise ValueError("Invalid authentication response")
            self._token = SecretStr(token)
            self._expires_at = time.monotonic() + max(0, ttl - 5)
        except (KeyError, TypeError, ValueError):
            raise VaultUnavailable("Vault authentication response is invalid") from None

    def request(self, method: str, path: str) -> dict[str, Any]:
        with self._lock:
            for attempt in range(2):
                if time.monotonic() >= self._expires_at:
                    self._login()
                try:
                    response = self._http.request(
                        method,
                        f"/v1/{path}",
                        headers={"X-Vault-Token": self._token.get_secret_value()},
                    )
                except httpx.HTTPError:
                    raise VaultUnavailable("Vault is unavailable") from None
                if response.status_code == 403:
                    self._expires_at = 0.0
                    if attempt == 0:
                        continue
                    raise VaultDenied("Vault policy denied the operation")
                if response.status_code not in (200, 204):
                    raise VaultUnavailable("Vault operation failed")
                if response.status_code == 204:
                    return {}
                try:
                    payload = response.json()
                    if not isinstance(payload, dict):
                        raise ValueError("Invalid response")
                    return payload
                except ValueError:
                    raise VaultUnavailable("Vault response is invalid") from None
        raise VaultUnavailable("Vault operation failed")

    def database_credentials(self) -> DatabaseCredentials:
        payload = self.request("GET", "database/static-creds/demo-db")
        try:
            username = payload["data"]["username"]
            password = payload["data"]["password"]
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError("Invalid credentials")
            if not username or not password:
                raise ValueError("Empty credentials")
            return DatabaseCredentials(username, SecretStr(password))
        except (KeyError, TypeError, ValueError):
            raise VaultUnavailable("Vault credentials response is invalid") from None

    def rotate_database_password(self) -> None:
        self.request("POST", "database/rotate-role/demo-db")

    def close(self) -> None:
        self._http.close()
