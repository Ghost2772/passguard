from unittest.mock import Mock

import psycopg
from pydantic import SecretStr
import pytest

from passguard import database
from passguard.database import DatabaseUnavailable, DocumentRepository, is_authentication_error
from passguard.vault_client import DatabaseCredentials


def credentials(value="unit-current"):
    return DatabaseCredentials("demo_reader", SecretStr(value))


def connection_with_documents():
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    connection.execute.return_value.fetchall.return_value = [{"id": 1, "title": "Document"}]
    return connection


def test_each_read_creates_a_new_connection_with_a_current_secret(settings, monkeypatch):
    vault = Mock()
    vault.database_credentials.side_effect = [credentials("old-unit-value"), credentials("new-unit-value")]
    connector = Mock(side_effect=[connection_with_documents(), connection_with_documents()])
    monkeypatch.setattr(database, "connect", connector)
    repository = DocumentRepository(settings, vault)
    assert repository.list_documents()[0]["id"] == 1
    repository.list_documents()
    assert vault.database_credentials.call_count == 2
    assert connector.call_args_list[0].args[1].password.get_secret_value() == "old-unit-value"
    assert connector.call_args_list[1].args[1].password.get_secret_value() == "new-unit-value"


def test_rotation_between_fetch_and_connect_refreshes_once(settings, monkeypatch):
    vault = Mock()
    vault.database_credentials.side_effect = [credentials("unit-stale"), credentials("unit-fresh")]
    connector = Mock(side_effect=[psycopg.OperationalError("password authentication failed"), connection_with_documents()])
    monkeypatch.setattr(database, "connect", connector)
    assert DocumentRepository(settings, vault).list_documents()[0]["id"] == 1
    assert connector.call_count == 2


def test_invalid_password_retry_is_bounded(settings, monkeypatch):
    vault = Mock()
    vault.database_credentials.return_value = credentials()
    connector = Mock(side_effect=psycopg.OperationalError("password authentication failed"))
    monkeypatch.setattr(database, "connect", connector)
    with pytest.raises(DatabaseUnavailable):
        DocumentRepository(settings, vault).list_documents()
    assert connector.call_count == 2


def test_network_failure_is_not_treated_as_password_rotation(settings, monkeypatch):
    vault = Mock()
    vault.database_credentials.return_value = credentials()
    connector = Mock(side_effect=psycopg.OperationalError("unit-sensitive-host-error"))
    monkeypatch.setattr(database, "connect", connector)
    with pytest.raises(DatabaseUnavailable) as error:
        DocumentRepository(settings, vault).list_documents()
    assert connector.call_count == 1
    assert "unit-sensitive" not in str(error.value)
    assert not is_authentication_error(psycopg.OperationalError("connection refused"))


def test_query_errors_are_not_replayed(settings, monkeypatch):
    vault = Mock()
    vault.database_credentials.return_value = credentials()
    connection = connection_with_documents()
    connection.execute.side_effect = psycopg.errors.InsufficientPrivilege("unit-sensitive-sql")
    connector = Mock(return_value=connection)
    monkeypatch.setattr(database, "connect", connector)
    with pytest.raises(DatabaseUnavailable) as error:
        DocumentRepository(settings, vault).list_documents()
    assert connector.call_count == 1
    assert connection.execute.call_count == 1
    assert "unit-sensitive" not in str(error.value)


def test_database_connections_require_tls_and_do_not_use_a_dsn(settings, monkeypatch):
    connector = Mock()
    monkeypatch.setattr(database.psycopg, "connect", connector)
    database.connect(settings, credentials())
    assert connector.call_args.args == ()
    assert connector.call_args.kwargs["sslmode"] == "verify-full"
    assert connector.call_args.kwargs["options"] == "-c default_transaction_read_only=on"
