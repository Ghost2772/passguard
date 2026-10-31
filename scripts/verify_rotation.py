"""Exercise live services, never emit password values, and save a safe report."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

import httpx
import psycopg

from scripts.common import state_dir
from passguard.config import Settings
from passguard.database import connect, is_authentication_error
from passguard.vault_client import VaultClient, VaultDenied, VaultError


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def check_application(client: httpx.Client) -> int:
    for _ in range(30):
        try:
            response = client.get("/api/documents")
            if response.status_code == 200:
                items = response.json().get("items")
                require(isinstance(items, list) and len(items) >= 2, "Сервис вернул неожиданные данные")
                return len(items)
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError("Демонстрационный сервис не прошёл проверку готовности")


def verify() -> dict:
    settings = Settings.from_env()
    reader = VaultClient(settings.vault_addr, settings.ca_file, state_dir() / "identities/demo")
    rotator = VaultClient(settings.vault_addr, settings.ca_file, state_dir() / "identities/rotator")
    try:
        with httpx.Client(base_url=os.getenv("DEMO_URL", "http://demo:8001"), timeout=15, trust_env=False) as app:
            count = check_application(app)
            old = reader.database_credentials()
            with connect(settings, old) as connection:
                connection.execute("SELECT 1")

            try:
                reader.rotate_database_password()
            except VaultDenied:
                pass
            else:
                raise RuntimeError("Приложение ошибочно имеет право менять пароль")

            try:
                rotator.database_credentials()
            except VaultDenied:
                pass
            else:
                raise RuntimeError("Оператор ротации ошибочно имеет право читать пароль")

            # readonly=False deliberately removes the client-side read-only
            # setting: this proves actual PostgreSQL role restrictions.
            with connect(settings, old, readonly=False) as connection:
                try:
                    connection.execute("INSERT INTO demo.documents VALUES (999, 'permission test')")
                except psycopg.errors.InsufficientPrivilege:
                    connection.rollback()
                else:
                    # Always roll back an unexpectedly permitted write.
                    connection.rollback()
                    raise RuntimeError("Учебная учётная запись ошибочно имеет право записи")

            rotator.rotate_database_password()
            current = reader.database_credentials()
            require(
                old.password.get_secret_value() != current.password.get_secret_value(),
                "После ротации пароль не изменился",
            )
            try:
                with connect(settings, old) as connection:
                    connection.execute("SELECT 1")
            except psycopg.Error as error:
                require(is_authentication_error(error), "Проверка старого пароля завершилась сетевой или иной ошибкой")
            else:
                raise RuntimeError("Старый пароль по-прежнему принимается")

            with connect(settings, current) as connection:
                connection.execute("SELECT 1")
            for _ in range(5):
                response = app.get("/api/documents")
                require(response.status_code == 200, "Приложение не работает после ротации")
                require(len(response.json()["items"]) == count, "Учебные данные изменились")

            return {
                "status": "passed",
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "checks": {
                    "application_works_before": True,
                    "application_cannot_rotate": True,
                    "rotator_cannot_read_password": True,
                    "database_role_is_readonly": True,
                    "password_changed": True,
                    "old_password_rejected_on_new_connection": True,
                    "new_password_accepted_on_new_connection": True,
                    "application_works_after_without_restart": True,
                },
                "successful_requests_after_rotation": 5,
                "documents_count": count,
            }
    finally:
        reader.close()
        rotator.close()


def main() -> None:
    try:
        report = verify()
        report_dir = Path(os.getenv("REPORT_DIR", "reports"))
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "rotation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print("Проверка пройдена. Отчёт: reports/rotation.json; значения секретов не сохранялись.")
    except (RuntimeError, VaultError, psycopg.Error, httpx.HTTPError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, (RuntimeError, VaultError)) else "Сбой соединения, обработки ответа или локального файла"
        # A failed rerun must not leave an older successful report in place.
        failed = {"status": "failed", "checked_at": datetime.now(timezone.utc).isoformat(), "reason": reason}
        try:
            report_dir = Path(os.getenv("REPORT_DIR", "reports"))
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "rotation.json").write_text(json.dumps(failed, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass
        print(f"Испытание не пройдено: {reason}. Чувствительные подробности скрыты.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
