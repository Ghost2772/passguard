from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient
import httpx
import pytest

from passguard.control.app import create_app
from passguard.control.repository import Identity
from passguard.control.security import COOKIE_NAME, COOKIE_PATH, SecuritySettings
from passguard.scanner.client import ScannerClient
from passguard.scanner.errors import ScanError, failure
from passguard.scanner.models import MAX_UPLOAD_BYTES, ScanResult


def make_client(role="operator"):
    user = {"id": uuid4(), "username": "scan_tester", "role": role, "active": True, "created_at": datetime.now(timezone.utc)}
    identity = Identity(user, "unit-scan-csrf", "unit-scan-digest")
    repo, scanner = Mock(), Mock()
    repo.authenticate.side_effect = lambda token: identity if token == "unit-scan-session" else None
    result = ScanResult(files_scanned=1, bytes_scanned=10, findings=[], skipped_files=[])
    scanner.scan.return_value = result
    repo.save_scan.return_value = {"id": str(uuid4()), "actor_id": user["id"], "created_at": datetime.now(timezone.utc),
                                   "findings_count": 0, "result": result.model_dump()}
    app = create_app(repo, Mock(), SecuritySettings(), scanner=scanner)
    client = TestClient(app, base_url="http://127.0.0.1:8000")
    client.cookies.set(COOKIE_NAME, "unit-scan-session", path=COOKIE_PATH)
    return client, repo, scanner


@pytest.mark.parametrize("role,expected", [("admin", 201), ("operator", 201), ("auditor", 403)])
def test_scan_role_permissions(role, expected):
    client, repo, scanner = make_client(role)
    with client:
        response = client.post(COOKIE_PATH + "/scans", content=b"opaque-archive-content",
                               headers={"X-CSRF-Token": "unit-scan-csrf", "Content-Type": "application/zip"})
    assert response.status_code == expected
    if expected == 403:
        scanner.scan.assert_not_called()
        repo.save_scan.assert_not_called()


def test_scan_authentication_and_csrf_happen_before_body_processing():
    client, repo, scanner = make_client()
    with client:
        # Invalid Content-Type and oversized length must not bypass auth.
        headers = {"Content-Length": str(MAX_UPLOAD_BYTES + 1)}
        assert client.post(COOKIE_PATH + "/scans", content=b"", headers=headers).status_code == 403
        client.cookies.clear()
        assert client.post(COOKIE_PATH + "/scans", content=b"", headers=headers).status_code == 401
    scanner.scan.assert_not_called()
    repo.save_scan.assert_not_called()


@pytest.mark.parametrize("headers,expected", [
    ({"Content-Type": "text/plain"}, 415),
    ({"Content-Type": "application/zip", "Content-Length": str(MAX_UPLOAD_BYTES + 1)}, 413),
])
def test_upload_limits_are_checked_before_forwarding(headers, expected):
    client, repo, scanner = make_client()
    with client:
        response = client.post(COOKIE_PATH + "/scans", content=b"private-source-text",
                               headers={**headers, "X-CSRF-Token": "unit-scan-csrf"})
    assert response.status_code == expected
    assert "private-source-text" not in response.text
    scanner.scan.assert_not_called()
    repo.save_scan.assert_not_called()


def test_streamed_upload_cannot_bypass_limit_by_omitting_content_length():
    client, repo, scanner = make_client()
    with client:
        response = client.post(COOKIE_PATH + "/scans", content=iter([b"x" * 1024 * 1024] * 6),
                               headers={"Content-Type": "application/zip", "X-CSRF-Token": "unit-scan-csrf"})
    assert response.status_code == 413
    scanner.scan.assert_not_called()


def test_failed_scan_has_audit_code_and_does_not_save_a_report():
    client, repo, scanner = make_client()
    scanner.scan.side_effect = failure("scanner_timeout")
    with client:
        response = client.post(COOKIE_PATH + "/scans", content=b"private-source-text",
                               headers={"Content-Type": "application/zip", "X-CSRF-Token": "unit-scan-csrf"})
    assert response.status_code == 503
    assert "private-source-text" not in response.text
    repo.save_scan.assert_not_called()
    assert repo.audit.call_args.args[-1] == {"code": "scanner_timeout"}


def test_unexpected_secret_field_from_scanner_is_not_forwarded_or_persisted():
    client = ScannerClient()
    data = ScanResult(files_scanned=1, bytes_scanned=10, findings=[], skipped_files=[]).model_dump()
    data["Secret"] = "synthetic-sensitive-value"
    client.http.close()
    client.http = httpx.Client(base_url="http://scanner:8002", transport=httpx.MockTransport(lambda _: httpx.Response(200, json=data)))
    try:
        with pytest.raises(ScanError) as error:
            client.scan(b"opaque")
        assert error.value.code == "scanner_unavailable"
        assert "synthetic-sensitive-value" not in str(error.value)
    finally:
        client.close()
