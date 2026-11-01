import base64
import json

import httpx
import pytest

from passguard.control.models import CreateUserRequest
from passguard.control.security import hash_password, token_digest, valid_csrf, verify_password
from scripts.maintenance import decode_root, temporary_root


def test_passwords_use_salted_argon2id_and_wrong_passwords_fail():
    first, second = hash_password("unit-password-example"), hash_password("unit-password-example")
    assert first.startswith("$argon2id$") and first != second
    assert verify_password("unit-password-example", first)
    assert not verify_password("unit-wrong-password", first)
    assert not verify_password("unit-password-example", "invalid-hash")


def test_session_digests_and_csrf_validation():
    assert token_digest("unit-session") != "unit-session"
    assert len(token_digest("unit-session")) == 64
    assert valid_csrf("unit-csrf", "unit-csrf")
    assert not valid_csrf(None, "unit-csrf")
    assert not valid_csrf("неверный", "unit-csrf")


def test_password_models_do_not_reveal_values_in_representations():
    model = CreateUserRequest(username="UNIT_USER", password="unit-private-password", role="operator")
    assert model.username == "unit_user"
    assert "unit-private-password" not in repr(model)


def test_root_decoding_uses_vault_base62_otp_xor_protocol():
    token = "unit-root-token-for-maintenance"
    otp = "a" * len(token)
    encoded = base64.b64encode(bytes(a ^ b for a, b in zip(token.encode(), otp.encode(), strict=True))).decode().rstrip("=")
    assert decode_root(encoded, otp) == token
    with pytest.raises(RuntimeError):
        decode_root(encoded, "bad-length")


def test_maintenance_token_is_revoked_even_when_provisioning_fails():
    token = "unit-root-token-for-maintenance"
    otp = "a" * len(token)
    encoded = base64.b64encode(bytes(a ^ b for a, b in zip(token.encode(), otp.encode(), strict=True))).decode()
    calls = []
    reads = 0

    def handler(request):
        nonlocal reads
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/attempt") and request.method == "GET":
            reads += 1
            return httpx.Response(200, json={"started": False})
        if request.url.path.endswith("/attempt"):
            return httpx.Response(200, json={"nonce": "unit-nonce", "required": 1, "otp": otp})
        if request.url.path.endswith("/update"):
            assert json.loads(request.content)["key"] == "unit-recovery"
            return httpx.Response(200, json={"complete": True, "encoded_token": encoded})
        assert request.headers["X-Vault-Token"] == token
        return httpx.Response(204)

    with httpx.Client(base_url="https://vault:8200", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError):
            with temporary_root(client, {"keys_base64": ["unit-recovery"]}):
                raise ValueError("unit-setup-error")
    assert ("POST", "/v1/auth/token/revoke-self") in calls


def test_other_operators_root_generation_is_not_cancelled():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"started": True, "nonce": "other-operation"})
    with httpx.Client(base_url="https://vault:8200", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError):
            with temporary_root(client, {"keys_base64": ["unit-recovery"]}):
                pass
    assert len(requests) == 1
