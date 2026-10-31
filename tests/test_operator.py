import json
from unittest.mock import Mock

import httpx
import pytest

from scripts.bootstrap import finalize_root_revocation
from scripts import verify_rotation
from scripts.common import unseal, wait_for_active_vault
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


def test_unseal_waits_for_raft_to_be_active(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("scripts.common.time.sleep", sleep)
    paths = []
    statuses = iter([429, 200])

    def handler(request):
        paths.append(request.url.path)
        if request.url.path.endswith("seal-status"):
            return httpx.Response(200, json={"sealed": True})
        if request.url.path.endswith("/unseal"):
            return httpx.Response(200, json={"sealed": False})
        return httpx.Response(next(statuses), json={"sealed": False})

    with httpx.Client(base_url="https://vault:8200", transport=httpx.MockTransport(handler)) as client:
        unseal(client, {"keys_base64": ["unit-recovery"]})
    assert paths == ["/v1/sys/seal-status", "/v1/sys/unseal", "/v1/sys/health", "/v1/sys/health"]
    sleep.assert_called_once_with(1)


def test_already_unsealed_server_still_requires_an_active_health_check(monkeypatch):
    monkeypatch.setattr("scripts.common.time.sleep", Mock())
    paths = []

    def handler(request):
        assert request.method == "GET"
        paths.append(request.url.path)
        return httpx.Response(200, json={"sealed": False})

    with httpx.Client(base_url="https://vault:8200", transport=httpx.MockTransport(handler)) as client:
        unseal(client, {"keys_base64": ["unit-recovery"]})
    assert paths == ["/v1/sys/seal-status", "/v1/sys/health"]


def test_active_vault_wait_is_bounded_and_does_not_expose_response_bodies(monkeypatch):
    monkeypatch.setattr("scripts.common.time.sleep", Mock())
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503, text="unit-sensitive-health-response")

    with httpx.Client(base_url="https://vault:8200", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError) as error:
            wait_for_active_vault(client, attempts=2)
    assert len(calls) == 2
    assert "unit-sensitive" not in str(error.value)
