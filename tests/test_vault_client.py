import httpx
import pytest

from passguard.vault_client import VaultClient, VaultDenied, VaultUnavailable


def client(settings, handler):
    return VaultClient(
        settings.vault_addr,
        settings.ca_file,
        settings.identity_dir,
        transport=httpx.MockTransport(handler),
    )


def login_response(token="unit-token"):
    return httpx.Response(200, json={"auth": {"client_token": token, "lease_duration": 300}})


def test_authentication_is_cached_and_credential_repr_is_safe(settings):
    logins = []

    def handler(request):
        if request.url.path.endswith("/login"):
            logins.append(request)
            return login_response()
        assert request.headers["X-Vault-Token"] == "unit-token"
        return httpx.Response(200, json={"data": {"username": "demo_reader", "password": "unit-value-never-log"}})

    vault = client(settings, handler)
    try:
        first = vault.database_credentials()
        second = vault.database_credentials()
        assert len(logins) == 1
        assert first.password.get_secret_value() == second.password.get_secret_value()
        assert "unit-value-never-log" not in repr(first)
    finally:
        vault.close()


def test_revoked_token_triggers_one_reauthentication(settings):
    logins = 0
    reads = 0

    def handler(request):
        nonlocal logins, reads
        if request.url.path.endswith("/login"):
            logins += 1
            return login_response(f"token-{logins}")
        reads += 1
        if reads == 1:
            return httpx.Response(403, json={"errors": ["permission denied"]})
        assert request.headers["X-Vault-Token"] == "token-2"
        return httpx.Response(200, json={"data": {"username": "demo_reader", "password": "unit-replacement"}})

    vault = client(settings, handler)
    try:
        vault.database_credentials()
        assert logins == 2
        assert reads == 2
    finally:
        vault.close()


def test_expired_token_is_refreshed(settings):
    logins = 0

    def handler(request):
        nonlocal logins
        if request.url.path.endswith("/login"):
            logins += 1
            return login_response()
        return httpx.Response(200, json={"data": {"username": "demo_reader", "password": "unit-current"}})

    vault = client(settings, handler)
    try:
        vault.database_credentials()
        vault._expires_at = 0
        vault.database_credentials()
        assert logins == 2
    finally:
        vault.close()


def test_forbidden_rotation_stops_after_one_retry_and_hides_response(settings):
    attempts = []

    def handler(request):
        if request.url.path.endswith("/login"):
            return login_response()
        attempts.append(request)
        return httpx.Response(403, text="unit-value-must-stay-hidden")

    vault = client(settings, handler)
    try:
        with pytest.raises(VaultDenied) as error:
            vault.rotate_database_password()
        assert len(attempts) == 2
        assert "unit-value-must-stay-hidden" not in str(error.value)
    finally:
        vault.close()


@pytest.mark.parametrize("response", [
    httpx.Response(500, text="unit-sensitive-error"),
    httpx.Response(200, text="unit-sensitive-invalid-json"),
    httpx.Response(200, json={"data": {"password": "unit-sensitive-incomplete"}}),
])
def test_bad_credential_response_is_sanitized(settings, response):
    def handler(request):
        return login_response() if request.url.path.endswith("/login") else response

    vault = client(settings, handler)
    try:
        with pytest.raises(VaultUnavailable) as error:
            vault.database_credentials()
        assert "unit-sensitive" not in str(error.value)
    finally:
        vault.close()


def test_transport_errors_are_sanitized(settings):
    def handler(request):
        raise httpx.ConnectError("unit-sensitive-network-error")

    vault = client(settings, handler)
    try:
        with pytest.raises(VaultUnavailable) as error:
            vault.database_credentials()
        assert "unit-sensitive" not in str(error.value)
    finally:
        vault.close()


def test_plain_http_is_rejected(settings):
    with pytest.raises(ValueError, match="HTTPS"):
        VaultClient("http://vault:8200", settings.ca_file, settings.identity_dir)
