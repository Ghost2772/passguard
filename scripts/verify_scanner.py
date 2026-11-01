"""Live scanner checks with random, non-working educational credentials."""

from dataclasses import replace
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from uuid import uuid4
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import psycopg

from scripts.common import state_dir
from scripts.verify_control import expect, login
from scripts.verify_rotation import require
from passguard.config import Settings
from passguard.database import connect
from passguard.vault_client import VaultClient, VaultError
from passguard.control.security import COOKIE_PATH
from passguard.scanner.models import MAX_FILE_BYTES


def make_zip(items):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in items:
            archive.writestr(path, content)
    return data.getvalue()


def verify():
    settings = Settings.from_env()
    initial = json.loads((state_dir() / "operator/control-admin.json").read_text())
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    password = "Educational-" + secrets.token_hex(12)
    token = "ghp_" + secrets.token_hex(18)
    forbidden_values = [password, token, private_key, private_key.splitlines()[1]]
    source = make_zip([
        ("src/config.py", f'DATABASE_PASSWORD = "{password}"  # gitleaks:allow\nAPI_TOKEN = "{token}"\n'),
        ("src/test-key.pem", private_key),
        (".gitleaks.toml", "invalid user-supplied TOML must not be read"),
        (".gitleaksignore", "file_0001.py:passguard-hardcoded-password:1\n"),
        ("picture.bin", b"\x00\xff\x00"),
    ])
    checks, created, scan_ids = {}, [], []
    base_url = os.getenv("CONTROL_URL", "http://control:8000")
    identity = VaultClient(settings.vault_addr, settings.ca_file, state_dir() / "identities/control")
    with httpx.Client(base_url=base_url, timeout=50, trust_env=False) as admin, \
         httpx.Client(base_url=base_url, timeout=50, trust_env=False) as operator, \
         httpx.Client(base_url=base_url, timeout=50, trust_env=False) as auditor:
        admin_headers = None
        try:
            expect(admin.post(COOKIE_PATH + "/scans", content=source, headers={"Content-Type": "application/zip"}), 401, "аноним не сканирует")
            _, admin_headers = login(admin, initial["username"], initial["password"])
            role_headers = {}
            for role, client in (("operator", operator), ("auditor", auditor)):
                username, user_password = "verify_scan_" + uuid4().hex[:12], secrets.token_urlsafe(24)
                user = expect(admin.post(COOKIE_PATH + "/users", headers=admin_headers,
                                         json={"username": username, "password": user_password, "role": role}), 201, "учётная запись проверки")
                created.append(user["id"])
                _, role_headers[role] = login(client, username, user_password)
            headers = {**role_headers["operator"], "Content-Type": "application/zip"}
            expect(operator.post(COOKIE_PATH + "/scans", content=source, headers={"Content-Type": "application/zip"}), 403, "CSRF для сканирования")
            expect(auditor.post(COOKIE_PATH + "/scans", content=source,
                                headers={**role_headers["auditor"], "Content-Type": "application/zip"}), 403, "аудитор не запускает сканирование")
            checks["authentication_csrf_and_scan_permissions"] = True

            report = expect(operator.post(COOKIE_PATH + "/scans", content=source, headers=headers), 201, "сканирование учебных секретов")
            scan_ids.append(report["id"])
            findings = report["result"]["findings"]
            require(any(f["rule_id"] == "passguard-hardcoded-password" and f["path"] == "src/config.py" and f["line"] == 1 for f in findings), "Учебный пароль не найден")
            require(any("github" in f["rule_id"] for f in findings), "Учебный токен не найден")
            require(any(f["kind"] == "private_key" for f in findings), "Учебный закрытый ключ не найден")
            require(all(f["status"] == "suspected" for f in findings), "Находки должны требовать проверки")
            require(len(report["result"]["skipped_files"]) == 1, "Пропущенный бинарный файл не отмечен")
            checks["password_token_and_private_key_detected"] = True
            checks["uploaded_config_and_allow_comments_cannot_disable_rules"] = True
            checks["binary_files_are_explicitly_reported_as_skipped"] = True

            loaded = expect(auditor.get(COOKIE_PATH + "/scans/" + report["id"]), 200, "аудитор читает отчёт")
            require(loaded == report, "Сохранённый отчёт отличается от результата")
            listing = expect(operator.get(COOKIE_PATH + "/scans?limit=100"), 200, "список отчётов")
            require(any(item["id"] == report["id"] for item in listing["items"]), "Отчёт отсутствует в списке")
            expect(admin.get(COOKIE_PATH + "/scans/" + str(uuid4())), 404, "несуществующий отчёт")
            clean = expect(admin.post(COOKIE_PATH + "/scans", content=make_zip([("main.py", 'print("Hello, PassGuard")\n')]),
                                      headers={**admin_headers, "Content-Type": "application/zip"}), 201, "чистый проект")
            scan_ids.append(clean["id"])
            require(clean["findings_count"] == 0 and clean["result"]["findings"] == [], "Ложная находка в чистом примере")
            checks["clean_project_and_saved_report_reads"] = True

            link = zipfile.ZipInfo("linked.py")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            invalid_archives = [
                (make_zip([("../escaped.py", "x=1")]), "unsafe_archive_path"),
                (make_zip([(link, "/run/identity/secret_id")]), "invalid_archive"),
                (make_zip([("large.py", "x" * (MAX_FILE_BYTES + 1))]), "archive_limits"),
                (make_zip([(".local/operator/key", "synthetic")]), "excluded_directory"),
                (b"not a zip", "invalid_archive"),
            ]
            for archive, code in invalid_archives:
                error = expect(operator.post(COOKIE_PATH + "/scans", content=archive, headers=headers), 422, "отказ опасному архиву")
                require(error["code"] == code, "Некорректная причина отказа архиву")
            checks["path_traversal_symlinks_and_decompression_limits"] = True

            events = expect(auditor.get(COOKIE_PATH + "/audit?limit=100"), 200, "аудит сканирования")
            require(any(e["action"] == "scans.create" and e["outcome"] == "success" for e in events["items"]), "Нет аудита сканирования")
            require(any(e["action"] == "scans.create" and e["outcome"] == "failed" for e in events["items"]), "Нет аудита отказа архиву")
            serialized = json.dumps([report, loaded, listing, clean, events])
            require(all(value not in serialized for value in forbidden_values), "Секрет обнаружен в ответе или журнале")
            credentials = identity.database_credentials("control-db")
            with connect(replace(settings, db_name="passguard_control"), credentials, readonly=False) as connection:
                stored = connection.execute("SELECT result FROM control.scans WHERE id=ANY(%s::uuid[])", (scan_ids,)).fetchall()
                require(all(value not in json.dumps(stored) for value in forbidden_values), "Секрет сохранён в БД отчётов")
                for statement in ("UPDATE control.scans SET findings_count=0 WHERE false", "DELETE FROM control.scans WHERE false"):
                    try:
                        connection.execute(statement)
                    except psycopg.errors.InsufficientPrivilege:
                        connection.rollback()
                    else:
                        raise RuntimeError("Сервис может изменять отчёты сканирования")
            checks["secret_values_absent_from_api_database_and_audit"] = True
            checks["reports_are_immutable_for_service"] = True
            return {"status": "passed", "checked_at": datetime.now(timezone.utc).isoformat(),
                    "engine": "gitleaks", "engine_version": report["result"]["engine_version"],
                    "checks": checks, "findings_in_synthetic_project": len(findings)}
        finally:
            if admin_headers:
                for user_id in created:
                    try:
                        admin.patch(COOKIE_PATH + "/users/" + user_id, headers=admin_headers, json={"active": False})
                    except httpx.HTTPError:
                        pass
            identity.close()


def main():
    try:
        report = verify()
    except (RuntimeError, OSError, ValueError, KeyError, VaultError, psycopg.Error, httpx.HTTPError) as error:
        reason = str(error) if isinstance(error, RuntimeError) else "Проверка сканера не пройдена; чувствительные подробности скрыты"
        report = {"status": "failed", "checked_at": datetime.now(timezone.utc).isoformat(), "reason": reason}
    directory = Path(os.getenv("REPORT_DIR", "reports"))
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "scanner.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
