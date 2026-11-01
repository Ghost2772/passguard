from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from passguard.control.app import create_app
from passguard.control.repository import ControlError, Identity, LoginResult
from passguard.control.security import COOKIE_NAME, COOKIE_PATH, SecuritySettings
from passguard.vault_client import VaultUnavailable


PREFIX = COOKIE_PATH
TOKEN = "unit-session-identifier-never-return"
CSRF = "unit-csrf-token"


def make_client(role="admin"):
    user = {"id": uuid4(), "username": "unit_user", "role": role, "active": True,
            "created_at": datetime.now(timezone.utc), "password_hash": "unit-private-hash"}
    identity = Identity(user, CSRF, "unit-session-digest")
    repo, vault = Mock(), Mock()
    repo.authenticate.side_effect = lambda token: identity if token == TOKEN else None
    repo.login.return_value = LoginResult(user, TOKEN, CSRF)
    repo.users.return_value = [user]
    repo.create_user.return_value = user
    repo.update_user.return_value = user
    repo.audit_events.return_value = []
    vault.database_role.return_value = {"id": "demo-db", "type": "database-password"}
    app = create_app(repo, vault, SecuritySettings(), probe=lambda: True)
    client = TestClient(app, base_url="http://127.0.0.1:8000")
    client.cookies.set(COOKIE_NAME, TOKEN, path=COOKIE_PATH)
    return client, repo, vault


@pytest.mark.parametrize("role,path,expected", [
    ("admin", "/users", 200), ("operator", "/users", 403), ("auditor", "/users", 403),
    ("admin", "/audit", 200), ("operator", "/audit", 403), ("auditor", "/audit", 200),
    ("operator", "/secrets", 200), ("auditor", "/secrets", 200),
])
def test_read_permissions(role, path, expected):
    client, _, _ = make_client(role)
    with client:
        response = client.get(PREFIX + path)
        assert response.status_code == expected
        assert "unit-private-hash" not in response.text


@pytest.mark.parametrize("role,expected", [("admin", 200), ("operator", 200), ("auditor", 403)])
def test_only_operators_and_admins_can_start_a_service_check(role, expected):
    client, repo, _ = make_client(role)
    with client:
        response = client.post(PREFIX + "/checks/demo", headers={"X-CSRF-Token": CSRF})
        assert response.status_code == expected
        if expected == 200:
            assert response.json() == {"status": "ready"}


@pytest.mark.parametrize("role", ["operator", "auditor"])
def test_non_admin_cannot_rotate_even_with_a_valid_csrf_token(role):
    client, repo, vault = make_client(role)
    with client:
        response = client.post(PREFIX + "/secrets/demo-db/rotate", headers={"X-CSRF-Token": CSRF},
                               json={"idempotency_key": str(uuid4())})
        assert response.status_code == 403
        repo.begin_rotation.assert_not_called()
        vault.rotate_database_password.assert_not_called()


@pytest.mark.parametrize("provided", [None, "unit-forged-csrf"])
def test_csrf_is_required_before_state_changes(provided):
    client, repo, _ = make_client()
    with client:
        response = client.post(PREFIX + "/users", headers={"X-CSRF-Token": provided} if provided else {},
                               json={"username": "new_user", "password": "unit-password-long-enough", "role": "operator"})
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_failed"
        repo.create_user.assert_not_called()


def test_anonymous_access_is_rejected():
    client, repo, _ = make_client()
    client.cookies.clear()
    with client:
        assert client.get(PREFIX + "/users").status_code == 401


def test_login_uses_scoped_httponly_cookie_and_response_models_hide_hashes():
    client, _, _ = make_client()
    with client:
        response = client.post(PREFIX + "/auth/login", json={"username": "unit_user", "password": "unit-password"})
        assert response.status_code == 200
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie and "SameSite=strict" in cookie
        assert f"Path={COOKIE_PATH}" in cookie
        assert TOKEN not in response.text and "unit-private-hash" not in response.text
        assert response.json()["csrf_token"] == CSRF


def test_cross_origin_login_is_rejected_before_verifying_credentials():
    client, repo, _ = make_client()
    with client:
        response = client.post(PREFIX + "/auth/login", headers={"Origin": "https://untrusted.invalid"},
                               json={"username": "unit_user", "password": "unit-password"})
        assert response.status_code == 403
        repo.login.assert_not_called()


def test_validation_errors_do_not_echo_passwords_or_request_inputs():
    client, repo, _ = make_client()
    with client:
        response = client.post(PREFIX + "/users", headers={"X-CSRF-Token": CSRF},
                               json={"username": "new_user", "password": "sensitive", "role": "operator"})
        assert response.status_code == 422
        assert "sensitive" not in response.text and '"input"' not in response.text
        repo.create_user.assert_not_called()


def test_existing_operation_is_not_rotated_twice():
    client, repo, vault = make_client()
    operation_id = uuid4()
    first = {"id": operation_id, "status": "in_progress"}
    done = {"id": operation_id, "status": "succeeded"}
    repo.begin_rotation.side_effect = [(first, True), (done, False)]
    repo.finish_rotation.return_value = done
    with client:
        for _ in range(2):
            response = client.post(PREFIX + "/secrets/demo-db/rotate", headers={"X-CSRF-Token": CSRF},
                                   json={"idempotency_key": str(operation_id)})
            assert response.status_code == 200
        assert response.json()["replayed"] is True
        vault.rotate_database_password.assert_called_once_with("demo-db")


def test_uncertain_vault_result_is_not_reported_as_success():
    client, repo, vault = make_client()
    operation_id = uuid4()
    repo.begin_rotation.return_value = ({"id": operation_id, "status": "in_progress"}, True)
    vault.rotate_database_password.side_effect = VaultUnavailable("unit-sensitive-provider-message")
    repo.finish_rotation.return_value = {"id": operation_id, "status": "unknown"}
    with client:
        response = client.post(PREFIX + "/secrets/demo-db/rotate", headers={"X-CSRF-Token": CSRF},
                               json={"idempotency_key": str(operation_id)})
        assert response.status_code == 502
        assert response.json()["operation"]["status"] == "unknown"
        assert "unit-sensitive" not in response.text


def test_password_change_and_logout_clear_the_scoped_cookie():
    client, repo, _ = make_client()
    with client:
        response = client.post(PREFIX + "/auth/password", headers={"X-CSRF-Token": CSRF},
                               json={"current_password": "unit-current", "new_password": "unit-new-password-long"})
        assert response.status_code == 204
        assert "Max-Age=0" in response.headers["set-cookie"]
        repo.change_password.assert_called_once()
