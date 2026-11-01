"""Local-only Vault maintenance; no recovery material reaches the HTTP API."""

import base64
from contextlib import contextmanager

from scripts.common import api


def response_data(payload: dict) -> dict:
    return payload["data"] if isinstance(payload.get("data"), dict) else payload


def decode_root(encoded: str, otp: str) -> str:
    try:
        encrypted = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
        key = otp.encode("ascii")
        if not key or len(encrypted) != len(key):
            raise ValueError("Invalid OTP length")
        token = bytes(a ^ b for a, b in zip(encrypted, key, strict=True)).decode("ascii")
        if len(token) < 20:
            raise ValueError("Invalid token")
        return token
    except (ValueError, UnicodeError):
        raise RuntimeError("Не удалось декодировать временный токен Vault") from None


@contextmanager
def temporary_root(client, recovery: dict):
    progress = response_data(api(client, "GET", "sys/generate-root/attempt"))
    if progress.get("started"):
        raise RuntimeError("В Vault уже выполняется другая операция generate-root")
    attempt = response_data(api(client, "POST", "sys/generate-root/attempt", payload={}))
    nonce = attempt["nonce"]
    token = None
    try:
        if attempt.get("required") != 1 or not recovery.get("keys_base64"):
            raise RuntimeError("Автоматическое обновление рассчитано на учебный Vault с порогом 1")
        completed = response_data(api(client, "POST", "sys/generate-root/update", payload={
            "nonce": nonce, "key": recovery["keys_base64"][0],
        }))
        if not completed.get("complete"):
            raise RuntimeError("Не завершена выдача временного токена Vault")
        token = decode_root(completed["encoded_token"], attempt["otp"])
        yield token
    finally:
        # Never persist or print the token. Revocation is attempted even when
        # the setup operation fails. A failed revocation is a visible error.
        if token:
            api(client, "POST", "auth/token/revoke-self", token=token)
        current = response_data(api(client, "GET", "sys/generate-root/attempt"))
        if current.get("started") and current.get("nonce") == nonce:
            api(client, "DELETE", "sys/generate-root/attempt")
