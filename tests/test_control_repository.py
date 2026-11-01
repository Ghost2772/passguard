from contextlib import contextmanager
from unittest.mock import Mock
from uuid import uuid4

import pytest

from passguard.control.repository import ControlError, ControlRepository, Identity


def repository_with_connection(connection):
    repository = ControlRepository(None, None)
    @contextmanager
    def opened():
        yield connection
    repository.connection = opened
    return repository


def test_rate_limit_rejects_before_password_verification_and_commits_audit(monkeypatch):
    connection = Mock()
    connection.execute.return_value.fetchone.return_value = {"failures": 10}
    password_check = Mock()
    monkeypatch.setattr("passguard.control.repository.verify_password", password_check)
    repository = repository_with_connection(connection)
    with pytest.raises(ControlError) as error:
        repository.login("unit_user", "unit-private-password", "127.0.0.1", 300)
    assert error.value.status == 429
    password_check.assert_not_called()
    audit_calls = [call for call in connection.execute.call_args_list if "INSERT INTO control.audit" in call.args[0]]
    assert len(audit_calls) == 1
    assert audit_calls[0].args[1][3] == "auth.rate_limited"


def test_last_active_admin_cannot_be_deactivated():
    user_id = uuid4()
    target = {"id": user_id, "username": "unit_admin", "role": "admin", "active": True}
    connection = Mock()
    connection.execute.return_value.fetchone.side_effect = [target, {"n": 1}]
    repository = repository_with_connection(connection)
    with pytest.raises(ControlError) as error:
        repository.update_user(Identity(target, "unit-csrf", "unit-digest"), user_id, None, False)
    assert error.value.code == "last_admin"
    statements = [call.args[0] for call in connection.execute.call_args_list]
    assert not any(statement.startswith("UPDATE control.users") for statement in statements)
    assert any("pg_advisory_xact_lock" in statement for statement in statements)


def test_missing_or_oversized_session_cookie_does_not_query_database():
    repository = ControlRepository(None, None)
    repository.connection = Mock(side_effect=AssertionError("Unexpected database access"))
    assert repository.authenticate(None) is None
    assert repository.authenticate("x" * 201) is None
    repository.connection.assert_not_called()
