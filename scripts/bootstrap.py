"""One-time initialization. The root token is revoked after successful setup."""

import json
import os
from pathlib import Path
import secrets
import sys

import httpx
import psycopg
from psycopg import sql
from pydantic import SecretStr

from scripts.common import api, load_recovery, state_dir, unseal, vault_http, wait_for_vault, write_private
from passguard.config import Settings
from passguard.database import connect
from passguard.vault_client import DatabaseCredentials


def provision_database(settings: Settings, password: str) -> None:
    bootstrap_password = (state_dir() / "bootstrap/postgres_password").read_text().strip()
    credentials = DatabaseCredentials("postgres", SecretStr(bootstrap_password))
    with connect(settings, credentials, readonly=False) as connection:
        # This is a local operator task. Only Vault's database manager can
        # rotate demo_reader, and demo_reader has SELECT on one schema only.
        for role, attributes in [
            ("demo_reader", "NOINHERIT NOCREATEROLE"),
            ("vault_db_manager", "NOINHERIT CREATEROLE"),
        ]:
            if not connection.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                connection.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION " + attributes).format(sql.Identifier(role)))
        connection.execute(
            sql.SQL("ALTER ROLE vault_db_manager WITH PASSWORD {}").format(sql.Literal(password))
        )
        connection.execute("GRANT demo_reader TO vault_db_manager WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
        connection.execute("REVOKE ALL ON DATABASE coursework FROM PUBLIC")
        connection.execute("GRANT CONNECT ON DATABASE coursework TO demo_reader, vault_db_manager")
        connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        connection.execute("CREATE SCHEMA IF NOT EXISTS demo")
        connection.execute("REVOKE ALL ON SCHEMA demo FROM PUBLIC")
        connection.execute("CREATE TABLE IF NOT EXISTS demo.documents (id integer PRIMARY KEY, title text NOT NULL)")
        connection.execute(
            "INSERT INTO demo.documents (id, title) VALUES (%s, %s), (%s, %s) ON CONFLICT (id) DO NOTHING",
            (1, "Политика управления секретами", 2, "Порядок замены паролей"),
        )
        connection.execute("GRANT USAGE ON SCHEMA demo TO demo_reader")
        connection.execute("GRANT SELECT ON demo.documents TO demo_reader")


def create_identity(client, token: str, name: str) -> None:
    api(client, "POST", f"auth/approle/role/{name}", token=token, payload={
        "token_policies": [name],
        "token_no_default_policy": True,
        "token_ttl": "5m",
        "token_max_ttl": "15m",
        "secret_id_ttl": "0",
        "secret_id_num_uses": 0,
    })
    role_id = api(client, "GET", f"auth/approle/role/{name}/role-id", token=token)["data"]["role_id"]
    secret_id = api(client, "POST", f"auth/approle/role/{name}/secret-id", token=token)["data"]["secret_id"]
    directory = state_dir() / "identities" / name
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    owner = 10001 if name == "demo" else None
    write_private(directory / "role_id", role_id, uid=owner)
    write_private(directory / "secret_id", secret_id, uid=owner)
    if owner is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(directory, owner, owner)


def finalize_root_revocation(client, recovery: dict, recovery_path: Path) -> None:
    token = recovery.get("root_token")
    if token:
        # A lost successful response may leave the now-invalid token in the
        # local record. A root token returning 403 is already invalid.
        try:
            response = client.post("/v1/auth/token/revoke-self", headers={"X-Vault-Token": token})
        except httpx.HTTPError:
            raise RuntimeError("Не подтверждён отзыв начального токена. Повтори bootstrap.") from None
        if response.status_code not in (200, 204, 403):
            raise RuntimeError("Не подтверждён отзыв начального токена. Повтори bootstrap.")
        recovery.pop("root_token", None)
        recovery["root_token_revoked"] = True
        write_private(recovery_path, json.dumps(recovery))


def bootstrap() -> None:
    root = state_dir()
    if not (root / "prepared").is_file():
        raise RuntimeError("Сначала выполни python -m scripts.prepare в контейнере tools.")
    with vault_http() as client:
        wait_for_vault(client)
        initialized = api(client, "GET", "sys/init")["initialized"]
        recovery_path = root / "operator/vault-init.json"
        if not initialized:
            if recovery_path.exists():
                raise RuntimeError("Vault пуст, но запись восстановления уже существует. Проверь подключение томов.")
            # One key is a conscious simplification of this local coursework
            # deployment. The key never enters the application container.
            recovery = api(client, "POST", "sys/init", payload={"secret_shares": 1, "secret_threshold": 1})
            write_private(recovery_path, json.dumps(recovery))
        else:
            recovery = load_recovery()
        unseal(client, recovery)
        if recovery.get("bootstrap_complete"):
            finalize_root_revocation(client, recovery, recovery_path)
            print("Vault разблокирован; конфигурация уже существует, пароли сохранены.")
            return
        token = recovery.get("root_token")
        if not token:
            raise RuntimeError("Первоначальная настройка не завершена, а начальный токен отсутствует.")

        audits = api(client, "GET", "sys/audit", token=token)
        audits = audits.get("data", audits)
        if "file/" not in audits:
            api(client, "PUT", "sys/audit/file", token=token, payload={
                "type": "file",
                "options": {"file_path": "/vault/audit/audit.jsonl", "log_raw": "false"},
            })
        mounts = api(client, "GET", "sys/mounts", token=token)
        mounts = mounts.get("data", mounts)
        if "database/" not in mounts:
            api(client, "POST", "sys/mounts/database", token=token, payload={"type": "database"})
        auth = api(client, "GET", "sys/auth", token=token)
        auth = auth.get("data", auth)
        if "approle/" not in auth:
            api(client, "POST", "sys/auth/approle", token=token, payload={"type": "approle"})

        settings = Settings.from_env()
        manager_password = secrets.token_urlsafe(36)
        provision_database(settings, manager_password)
        api(client, "POST", "database/config/coursework", token=token, payload={
            "plugin_name": "postgresql-database-plugin",
            "allowed_roles": ["demo-db"],
            "connection_url": (
                "postgresql://{{username}}:{{password}}@postgres:5432/coursework"
                "?sslmode=verify-full&sslrootcert=/run/secrets/local_ca"
            ),
            "username": "vault_db_manager",
            "password": manager_password,
        })
        # Vault now holds the manager password, and the bootstrap copy is stale.
        api(client, "POST", "database/rotate-root/coursework", token=token)
        api(client, "POST", "database/static-roles/demo-db", token=token, payload={
            "db_name": "coursework",
            "username": "demo_reader",
            "rotation_period": "24h",
            "rotation_statements": ["ALTER ROLE \"{{name}}\" WITH PASSWORD '{{password}}';"],
        })
        for name in ("demo", "rotator"):
            policy = (Path(__file__).resolve().parents[1] / "infra/vault/policies" / f"{name}.hcl").read_text()
            api(client, "PUT", f"sys/policies/acl/{name}", token=token, payload={"policy": policy})
            create_identity(client, token, name)

        # Save a recoverable completion state before the revocation. If the
        # response is lost, the marker still allows normal subsequent unseals.
        recovery["bootstrap_complete"] = True
        write_private(recovery_path, json.dumps(recovery))
        finalize_root_revocation(client, recovery, recovery_path)
    print("Vault настроен: TLS, аудит, политики AppRole и ротация PostgreSQL.")
    print("Начальный root-токен отозван; значения секретов скрыты.")


def main() -> None:
    try:
        bootstrap()
    except (RuntimeError, OSError, ValueError, psycopg.Error) as error:
        # Database exceptions may include SQL or sensitive context.
        message = str(error) if isinstance(error, RuntimeError) else "Ошибка настройки стенда; проверь доступность сервисов и локальные файлы."
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
