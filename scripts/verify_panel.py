"""Check the installed panel and API without printing credentials."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

import httpx

from scripts.common import state_dir
from scripts.verify_control import expect, login
from scripts.verify_rotation import require
from passguard.control.security import COOKIE_PATH


def verify():
    checks = {}
    base_url = os.getenv("CONTROL_URL", "http://control:8000")
    initial = json.loads((state_dir() / "operator/control-admin.json").read_text())
    with httpx.Client(base_url=base_url, timeout=20, trust_env=False) as client:
        response = client.get("/")
        require(response.status_code == 200 and '<html lang="ru">' in response.text and "PassGuard" in response.text, "Панель не отвечает")
        assets = re.findall(r'(?:src|href)="(/assets/[^"<>]+)"', response.text)
        require(assets and any(p.endswith(".js") for p in assets) and any(p.endswith(".css") for p in assets), "Не найдены ресурсы панели")
        for asset in assets:
            require(client.get(asset).status_code == 200, "Ресурс панели недоступен")
        checks["panel_and_bundled_assets_served"] = True
        policy = response.headers.get("content-security-policy", "")
        require("script-src 'self'" in policy and "connect-src 'self'" in policy and "'unsafe-inline'" not in policy, "Не задана политика безопасности панели")
        require(response.headers.get("x-frame-options") == "DENY", "Панель допускает встраивание во фрейм")
        checks["same_origin_content_security_policy"] = True
        unknown = client.get(COOKIE_PATH + "/not-a-route")
        require(unknown.status_code == 404 and "application/json" in unknown.headers.get("content-type", ""), "Неизвестный API-маршрут заменён страницей панели")
        expect(client.get(COOKIE_PATH + "/scans"), 401, "API требует вход")
        checks["api_routes_and_authentication_preserved"] = True
        _, headers = login(client, initial["username"], initial["password"])
        try:
            secrets = expect(client.get(COOKIE_PATH + "/secrets"), 200, "метаданные секрета")
            require(all(set(item) == {"id", "type", "username", "rotation_period_seconds"} for item in secrets["items"]), "Метаданные содержат лишние поля")
            checks["httponly_session_and_metadata_only_secrets"] = True
        finally:
            expect(client.post(COOKIE_PATH + "/auth/logout", headers=headers), 204, "выход после проверки панели")
    return {"status": "passed", "checked_at": datetime.now(timezone.utc).isoformat(), "checks": checks}


def main():
    try:
        report = verify()
    except (RuntimeError, OSError, ValueError, KeyError, httpx.HTTPError) as error:
        reason = str(error) if isinstance(error, RuntimeError) else "Не пройдена проверка панели; чувствительные подробности скрыты"
        report = {"status": "failed", "checked_at": datetime.now(timezone.utc).isoformat(), "reason": reason}
    directory = Path(os.getenv("REPORT_DIR", "reports"))
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "panel.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
