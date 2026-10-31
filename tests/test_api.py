from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

from passguard.database import DatabaseUnavailable
from passguard.main import create_app
from passguard.vault_client import VaultUnavailable


def test_application_returns_only_documents():
    repository = Mock()
    repository.list_documents.return_value = [{"id": 1, "title": "Учебный документ"}]
    with TestClient(create_app(repository)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").json() == {"status": "ready"}
        response = client.get("/api/documents")
        assert response.json() == {"items": [{"id": 1, "title": "Учебный документ"}]}
        assert "password" not in response.text


@pytest.mark.parametrize("error", [VaultUnavailable("unit-private-value"), DatabaseUnavailable("unit-private-value")])
def test_dependency_failure_returns_a_sanitized_503(error):
    repository = Mock()
    repository.list_documents.side_effect = error
    with TestClient(create_app(repository)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
        response = client.get("/api/documents")
        assert response.status_code == 503
        assert "unit-private-value" not in response.text


def test_rotation_is_not_exposed_before_user_authorization_is_implemented():
    with TestClient(create_app(Mock())) as client:
        assert client.post("/api/rotate").status_code == 404
        operations = client.get("/openapi.json").json()["paths"]
        assert all(set(operation).issubset({"get"}) for operation in operations.values())
