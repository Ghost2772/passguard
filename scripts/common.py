import json
import os
from pathlib import Path
import ssl
import time
from typing import Any

import httpx


def state_dir() -> Path:
    return Path(os.getenv("STATE_DIR", ".local"))


def write_private(path: Path, content: str | bytes, *, uid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode() if isinstance(content, str) else content
    # Atomic replacement protects the recovery record from partial writes.
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    if uid is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(temporary, uid, uid)
    temporary.replace(path)


def vault_http() -> httpx.Client:
    return httpx.Client(
        base_url=os.getenv("VAULT_ADDR", "https://vault:8200"),
        verify=ssl.create_default_context(
            cafile=os.getenv("VAULT_CACERT", str(state_dir() / "pki/ca.crt"))
        ),
        timeout=10,
        trust_env=False,
    )


def wait_for_vault(client: httpx.Client, *, attempts: int = 45) -> None:
    for _ in range(attempts):
        try:
            response = client.get("/v1/sys/seal-status")
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError("Vault не отвечает по HTTPS. Проверь docker compose logs vault.")


def api(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    headers = {"X-Vault-Token": token} if token else {}
    try:
        response = client.request(method, f"/v1/{path}", headers=headers, json=payload)
    except httpx.HTTPError:
        raise RuntimeError("Ошибка соединения с Vault") from None
    if response.status_code not in (200, 204):
        # Do not print raw errors: they may contain credentials or SQL.
        raise RuntimeError(f"Vault: операция {method} {path} завершилась HTTP {response.status_code}")
    return response.json() if response.content else {}


def load_recovery() -> dict[str, Any]:
    path = state_dir() / "operator/vault-init.json"
    if not path.is_file():
        raise RuntimeError("Не найдена .local/operator/vault-init.json. Нужна запись восстановления именно этой установки Vault; повторная инициализация ключ не восстановит.")
    return json.loads(path.read_text())


def wait_for_active_vault(client: httpx.Client, *, attempts: int = 45) -> None:
    # Raft leader election and post-unseal setup continue after /sys/unseal
    # returns sealed=false. Only health=200 confirms an active server.
    for attempt in range(attempts):
        try:
            if client.get("/v1/sys/health").status_code == 200:
                return
        except httpx.HTTPError:
            pass
        if attempt + 1 < attempts:
            time.sleep(1)
    raise RuntimeError("Vault разблокирован, но ещё не готов к операциям. Повтори команду позже.")


def unseal(client: httpx.Client, recovery: dict[str, Any]) -> None:
    status = api(client, "GET", "sys/seal-status")
    if status["sealed"]:
        result = api(client, "POST", "sys/unseal", payload={"key": recovery["keys_base64"][0]})
        if result["sealed"]:
            raise RuntimeError("Не удалось разблокировать Vault")
    wait_for_active_vault(client)
