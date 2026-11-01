"""Live control API checks. Test accounts are disabled afterwards."""

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import time
from uuid import uuid4

import httpx
import psycopg
from pydantic import SecretStr

from scripts.common import state_dir
from scripts.verify_rotation import require
from passguard.config import Settings
from passguard.database import connect, is_authentication_error
from passguard.vault_client import DatabaseCredentials, VaultClient, VaultDenied, VaultError
from passguard.control.security import COOKIE_NAME, COOKIE_PATH, token_digest


PREFIX = COOKIE_PATH


def expect(response: httpx.Response, status: int, label: str):
    require(response.status_code == status, f"Не пройдена проверка: {label}")
    return response.json() if response.content else {}


def login(client: httpx.Client, username: str, password: str):
    response = client.post(PREFIX + "/auth/login", json={"username": username, "password": password})
    result = expect(response, 200, "вход пользователя")
    require("HttpOnly" in response.headers.get("set-cookie", ""), "Сессионная cookie не имеет HttpOnly")
    return result, {"X-CSRF-Token": result["csrf_token"]}


def verify(check_last_admin=False):
    settings = Settings.from_env()
    base_url = os.getenv("CONTROL_URL", "http://control:8000")
    initial = json.loads((state_dir() / "operator/control-admin.json").read_text())
    checks = {}
    reader = VaultClient(settings.vault_addr, settings.ca_file, state_dir() / "identities/demo")
    control_identity = VaultClient(settings.vault_addr, settings.ca_file, state_dir() / "identities/control")
    created = []
    passwords = [initial["password"]]
    with httpx.Client(base_url=base_url, timeout=15, trust_env=False) as admin, \
         httpx.Client(base_url=base_url, timeout=15, trust_env=False) as operator, \
         httpx.Client(base_url=base_url, timeout=15, trust_env=False) as auditor:
        admin_headers = None
        try:
            for _ in range(30):
                try:
                    if admin.get("/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError("Управляющий API не готов")
            expect(admin.get(PREFIX + "/users"), 401, "отказ анонимному пользователю")
            expect(admin.post(PREFIX + "/auth/login", json={"username": initial["username"], "password": "unit-invalid-check-password"}), 401, "отказ неверному паролю")
            admin_info, admin_headers = login(admin, initial["username"], initial["password"])
            checks["authentication_and_httponly_session"] = True

            fixtures = {}
            for role in ("operator", "auditor"):
                username = "verify_" + role + "_" + uuid4().hex[:10]
                password = secrets.token_urlsafe(24)
                passwords.append(password)
                payload = {"username": username, "password": password, "role": role}
                if role == "operator":
                    expect(admin.post(PREFIX + "/users", json=payload), 403, "отказ без CSRF")
                user = expect(admin.post(PREFIX + "/users", headers=admin_headers, json=payload), 201, "создание пользователя")
                require("password_hash" not in user and "password" not in user, "API раскрыл пароль или хеш")
                created.append(user["id"])
                fixtures[role] = (user, password)
            checks["csrf_required_for_writes"] = True
            operator_info, operator_headers = login(operator, fixtures["operator"][0]["username"], fixtures["operator"][1])
            _, auditor_headers = login(auditor, fixtures["auditor"][0]["username"], fixtures["auditor"][1])
            expect(operator.get(PREFIX + "/users"), 403, "оператор не управляет пользователями")
            expect(operator.get(PREFIX + "/audit"), 403, "оператор не читает журнал")
            expect(auditor.get(PREFIX + "/audit"), 200, "аудитор читает журнал")
            expect(auditor.post(PREFIX + "/checks/demo", headers=auditor_headers), 403, "аудитор не запускает проверки")
            expect(operator.post(PREFIX + "/checks/demo", headers=operator_headers), 200, "оператор проверяет сервис")
            for client, headers in ((operator, operator_headers), (auditor, auditor_headers)):
                expect(client.post(PREFIX + "/secrets/demo-db/rotate", headers=headers,
                                   json={"idempotency_key": str(uuid4())}), 403, "ротация разрешена только администратору")
            checks["role_permissions_enforced"] = True

            catalog = expect(admin.get(PREFIX + "/secrets"), 200, "метаданные секрета")
            require("password" not in catalog["items"][0], "Метаданные содержат значение пароля")
            try:
                control_identity.database_credentials("demo-db")
            except VaultDenied:
                pass
            else:
                raise RuntimeError("Управляющий API ошибочно может читать пароль потребителя")
            checks["control_identity_cannot_read_demo_password"] = True

            old = reader.database_credentials()
            operation_id = str(uuid4())
            payload = {"idempotency_key": operation_id, "reason": "manual_test"}
            first = expect(admin.post(PREFIX + "/secrets/demo-db/rotate", headers=admin_headers, json=payload), 200, "ротация через API")
            require(first["operation"]["status"] == "succeeded", "Ротация через API не завершена")
            current = reader.database_credentials()
            require(old.password.get_secret_value() != current.password.get_secret_value(), "Пароль БД не изменился")
            try:
                with connect(settings, old) as connection:
                    connection.execute("SELECT 1")
            except psycopg.Error as error:
                require(is_authentication_error(error), "Проверка старого пароля завершилась иной ошибкой")
            else:
                raise RuntimeError("Старый пароль принят после API-ротации")
            with connect(settings, current) as connection:
                connection.execute("SELECT 1")
            again = expect(admin.post(PREFIX + "/secrets/demo-db/rotate", headers=admin_headers, json=payload), 200, "повтор запроса с тем же ключом")
            require(again["replayed"] is True, "Не сработала идемпотентность")
            require(reader.database_credentials().password.get_secret_value() == current.password.get_secret_value(), "Повторный запрос снова поменял пароль")
            checks["api_rotation_is_real_and_idempotent"] = True

            if check_last_admin:
                # Only enable for a disposable CI installation. This request
                # is deliberately omitted from ordinary user-side checks.
                active_admins = [u for u in expect(admin.get(PREFIX + "/users?limit=100"), 200, "список пользователей")["items"] if u["role"] == "admin" and u["active"]]
                require(len(active_admins) == 1, "Проверка последнего администратора требует пустого тестового стенда")
                expect(admin.patch(PREFIX + "/users/" + str(admin_info["user"]["id"]), headers=admin_headers, json={"active": False}), 409, "защита последнего администратора")
                checks["last_administrator_is_protected"] = True

            new_password = secrets.token_urlsafe(24)
            passwords.append(new_password)
            expect(operator.post(PREFIX + "/auth/password", headers=operator_headers, json={
                "current_password": fixtures["operator"][1], "new_password": new_password,
            }), 204, "смена пароля пользователя")
            expect(operator.get(PREFIX + "/auth/me"), 401, "отзыв сессии после смены пароля")
            expect(operator.post(PREFIX + "/auth/login", json={"username": operator_info["user"]["username"], "password": fixtures["operator"][1]}), 401, "отказ старому паролю пользователя")
            _, operator_headers = login(operator, operator_info["user"]["username"], new_password)
            checks["user_password_change_revokes_sessions"] = True

            # Expire only the dedicated test account's current session.
            bootstrap = DatabaseCredentials("postgres", SecretStr((state_dir() / "bootstrap/postgres_password").read_text().strip()))
            control_settings = replace(settings, db_name="passguard_control")
            with connect(control_settings, bootstrap, readonly=False) as connection:
                connection.execute("UPDATE control.sessions SET expires_at=now()-interval '1 second' WHERE token_hash=%s",
                                   (token_digest(operator.cookies.get(COOKIE_NAME)),))
            expect(operator.get(PREFIX + "/auth/me"), 401, "истечение сессии")
            _, operator_headers = login(operator, operator_info["user"]["username"], new_password)
            expect(admin.patch(PREFIX + "/users/" + fixtures["operator"][0]["id"], headers=admin_headers, json={"active": False}), 200, "блокировка тестового пользователя")
            expect(operator.get(PREFIX + "/auth/me"), 401, "отзыв сессии заблокированного пользователя")
            checks["expired_and_disabled_sessions_rejected"] = True

            events = expect(auditor.get(PREFIX + "/audit?limit=100"), 200, "чтение журнала")
            serialized = json.dumps(events)
            require(all(value not in serialized for value in passwords), "Журнал содержит пароль")
            require(any(e["action"] == "secrets.rotate" and e["outcome"] == "success" for e in events["items"]), "Нет аудита ротации")
            require(any(e["outcome"] == "denied" for e in events["items"]), "Нет аудита отказов")
            credentials = control_identity.database_credentials("control-db")
            with connect(control_settings, credentials, readonly=False) as connection:
                try:
                    connection.execute("UPDATE control.audit SET action='permission_test' WHERE false")
                except psycopg.errors.InsufficientPrivilege:
                    connection.rollback()
                else:
                    connection.rollback()
                    raise RuntimeError("У сервиса ошибочно есть право изменять журнал")
            checks["audit_records_actions_and_is_append_only_for_service"] = True

            old_cookie = auditor.cookies.get(COOKIE_NAME)
            expect(auditor.post(PREFIX + "/auth/logout", headers=auditor_headers), 204, "выход")
            auditor.cookies.set(COOKIE_NAME, old_cookie, path=COOKIE_PATH)
            expect(auditor.get(PREFIX + "/auth/me"), 401, "повторное использование завершённой сессии")
            checks["logout_revokes_session_server_side"] = True
            return {"status": "passed", "checked_at": datetime.now(timezone.utc).isoformat(), "checks": checks}
        finally:
            # Deactivate only accounts created by this verification run.
            if admin_headers:
                for user_id in created:
                    try:
                        admin.patch(PREFIX + "/users/" + user_id, headers=admin_headers, json={"active": False})
                    except httpx.HTTPError:
                        pass
            reader.close()
            control_identity.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-last-admin", action="store_true", help="Only for a disposable CI installation")
    args = parser.parse_args()
    try:
        report = verify(args.check_last_admin)
    except (RuntimeError, ValueError, OSError, KeyError, VaultError, psycopg.Error, httpx.HTTPError) as error:
        reason = str(error) if isinstance(error, RuntimeError) else "Не пройдена проверка управляющего API; чувствительные подробности скрыты"
        report = {"status": "failed", "checked_at": datetime.now(timezone.utc).isoformat(),
                  "reason": reason}
    directory = Path(os.getenv("REPORT_DIR", "reports"))
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "control.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
