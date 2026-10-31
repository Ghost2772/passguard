import json
from unittest.mock import Mock

import httpx
import pytest

from scripts.bootstrap import finalize_root_revocation
from scripts import verify_rotation
from passguard.vault_client import VaultUnavailable


@pytest.mark.parametrize("status", [204, 403])
def test_root_token_is_removed_even_if_previous_revocation_response_was_lost(tmp_path, status):
    record = {"bootstrap_complete": True, "root_token": "unit-initial-token", "keys_base64": ["unit-recovery"]}
    path = tmp_path / "recovery.json"
    client = Mock()
    client.post.return_value = httpx.Response(status)
    finalize_root_revocation(client, record, path)
    persisted = json.loads(path.read_text())
    assert "root_token" not in persisted
    assert persisted["root_token_revoked"] is True


def test_failed_revocation_preserves_the_token_for_a_safe_retry(tmp_path):
    record = {"bootstrap_complete": True, "root_token": "unit-initial-token"}
    client = Mock()
    client.post.return_value = httpx.Response(500, text="unit-sensitive-details")
    with pytest.raises(RuntimeError) as error:
        finalize_root_revocation(client, record, tmp_path / "recovery.json")
    assert record["root_token"] == "unit-initial-token"
    assert "unit-sensitive" not in str(error.value)


def test_failed_rotation_verification_replaces_an_old_success_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("REPORT_DIR", str(tmp_path))
    path = tmp_path / "rotation.json"
    path.write_text('{"status": "passed"}')
    monkeypatch.setattr(verify_rotation, "verify", Mock(side_effect=ValueError("unit-sensitive-response")))
    with pytest.raises(SystemExit) as error:
        verify_rotation.main()
    assert error.value.code == 1
    report = json.loads(path.read_text())
    assert report["status"] == "failed"
    assert "unit-sensitive-response" not in path.read_text()
    assert "unit-sensitive-response" not in capsys.readouterr().err
