"""Upgrade an existing stage-1 installation without replacing its data."""

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sys
from uuid import uuid4

import psycopg
from psycopg import sql
from pydantic import SecretStr

from scripts.bootstrap import create_identity
from scripts.common import api, load_recovery, state_dir, unseal, vault_http, wait_for_vault, write_private
from scripts.maintenance import temporary_root
from passguard.config import Settings
from passguard.database import connect
from passguard.vault_client import DatabaseCredentials
from passguard.control.security import hash_password


def setup_database(settings: Settings, manager_password: str):
    password = (state_dir() / "bootstrap/postgres_password").read_text().strip()
    administrator = DatabaseCredentials("postgres", SecretStr(password))
    with connect(settings, administrator, readonly=False) as connection:
        connection.autocommit = True
        for name, attributes in (
            ("control_api", "NOCREATEROLE"),
            ("vault_control_manager", "CREATEROLE"),
        ):
            if not connection.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (name,)).fetchone():
                connection.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOREPLICATION " + attributes).format(sql.Identifier(name)))
        connection.execute(sql.SQL("ALTER ROLE vault_control_manager WITH PASSWORD {}").format(sql.Literal(manager_password)))
        connection.execute("GRANT control_api TO vault_control_manager WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
        if not connection.execute("SELECT 1 FROM pg_database WHERE datname='passguard_control'").fetchone():
            connection.execute("CREATE DATABASE passguard_control")
        connection.execute("REVOKE ALL ON DATABASE passguard_control FROM PUBLIC")
        connection.execute("GRANT CONNECT ON DATABASE passguard_control TO control_api, vault_control_manager")

    with connect(replace(settings, db_name="passguard_control"), administrator, readonly=False) as connection:
        schema = (Path(__file__).resolve().parents[1] / "infra/postgres/control-schema.sql").read_text()
        connection.execute(schema, prepare=False)
        if connection.execute("SELECT count(*) AS n FROM control.users").fetchone()["n"] == 0:
            initial_path = state_dir() / "operator/control-admin.json"
            if initial_path.is_file():
                initial = json.loads(initial_path.read_text())
                if initial.get("username") != "admin" or not isinstance(initial.get("password"), str) or len(initial["password"]) < 15:
                    raise RuntimeError("Некорректная локальная запись первого администратора")
            else:
                initial = {"username": "admin", "password": secrets.token_urlsafe(24),
                           "created_at": datetime.now(timezone.utc).isoformat()}
                # Save before committing the first account; a retry uses the
                # same password and never resets an existing administrator.
                write_private(initial_path, json.dumps(initial))
            user_id = uuid4()
            connection.execute(
                "INSERT INTO control.users (id,username,password_hash,role) VALUES (%s,%s,%s,'admin')",
                (user_id, initial["username"], hash_password(initial["password"])),
            )
            connection.execute(
                "INSERT INTO control.audit (actor_id,actor_username,actor_role,action,outcome) "
                "VALUES (%s,'admin','admin','users.bootstrap','success')", (user_id,),
            )


def setup_control():
    recovery = load_recovery()
    if not recovery.get("bootstrap_complete"):
        raise RuntimeError("Сначала заверши первоначальный scripts.bootstrap")
    marker = state_dir() / "operator/control-setup.json"
    with vault_http() as client:
        wait_for_vault(client)
        unseal(client, recovery)
        identity = state_dir() / "identities/control"
        if marker.is_file() and all((identity / name).is_file() for name in ("role_id", "secret_id")):
            print("Управляющий API уже настроен; учётные записи и пароли сохранены.")
            return
        with temporary_root(client, recovery) as token:
            manager_password = secrets.token_urlsafe(36)
            setup_database(Settings.from_env(), manager_password)
            api(client, "POST", "database/config/control", token=token, payload={
                "plugin_name": "postgresql-database-plugin",
                "allowed_roles": ["control-db"],
                "connection_url": "postgresql://{{username}}:{{password}}@postgres:5432/passguard_control?sslmode=verify-full&sslrootcert=/run/secrets/local_ca",
                "username": "vault_control_manager", "password": manager_password,
            })
            api(client, "POST", "database/rotate-root/control", token=token)
            api(client, "POST", "database/static-roles/control-db", token=token, payload={
                "db_name": "control", "username": "control_api", "rotation_period": "24h",
                "rotation_statements": ["ALTER ROLE \"{{name}}\" WITH PASSWORD '{{password}}';"],
            })
            policy = (Path(__file__).resolve().parents[1] / "infra/vault/policies/control.hcl").read_text()
            api(client, "PUT", "sys/policies/acl/control", token=token, payload={"policy": policy})
            create_identity(client, token, "control")
        write_private(marker, json.dumps({"schema_version": 2, "completed_at": datetime.now(timezone.utc).isoformat()}))
    print("Управляющий API настроен; временный root-токен отозван.")
    print("Первый логин сохранён локально: .local/operator/control-admin.json")


def main():
    try:
        setup_control()
    except (RuntimeError, OSError, ValueError, KeyError, psycopg.Error) as error:
        message = str(error) if isinstance(error, RuntimeError) else "Не удалось настроить управляющую базу; чувствительные подробности скрыты."
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
