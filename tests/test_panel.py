from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

from passguard.control.app import create_app


@pytest.fixture
def panel_client(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text('<!doctype html><html lang="ru"><title>PassGuard</title></html>')
    (tmp_path / "assets/app.js").write_text("/* public panel bundle */")
    (tmp_path / "favicon.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
    (tmp_path / "private.txt").write_text("synthetic-file-outside-assets")
    repo = Mock()
    repo.authenticate.return_value = None
    with TestClient(create_app(repo, Mock(), panel_dir=tmp_path)) as client:
        yield client


def test_panel_and_assets_are_served_with_strict_same_origin_policy(panel_client):
    response = panel_client.get("/")
    assert response.status_code == 200 and "PassGuard" in response.text
    assert "text/html" in response.headers["content-type"]
    policy = response.headers["content-security-policy"]
    assert "script-src 'self'" in policy and "'unsafe-inline'" not in policy
    assert "connect-src 'self'" in policy and "frame-ancestors 'none'" in policy
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-cache"
    assert panel_client.get("/assets/app.js").status_code == 200
    assert panel_client.get("/favicon.svg").status_code == 200


def test_static_panel_does_not_replace_api_authentication_or_unknown_routes(panel_client):
    assert panel_client.get("/api/control/scans").status_code == 401
    response = panel_client.get("/api/control/not-a-route")
    assert response.status_code == 404 and response.headers["content-type"].startswith("application/json")
    assert panel_client.get("/not-a-route").status_code == 404


def test_assets_cannot_expose_other_files_or_parent_directories(panel_client):
    for path in ("/private.txt", "/assets/%2e%2e/private.txt", "/assets/../../private.txt"):
        response = panel_client.get(path)
        assert response.status_code == 404
        assert "synthetic-file-outside-assets" not in response.text


def test_missing_build_is_not_a_successful_empty_panel(tmp_path):
    with TestClient(create_app(Mock(), Mock(), panel_dir=tmp_path)) as client:
        assert client.get("/").status_code == 503
