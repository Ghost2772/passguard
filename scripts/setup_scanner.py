"""Add the scanner table to an existing installation; no Vault root token."""

from dataclasses import replace
from pathlib import Path
import sys

import psycopg
from pydantic import SecretStr

from scripts.common import state_dir
from passguard.config import Settings
from passguard.database import connect
from passguard.vault_client import DatabaseCredentials


def migrate(connection):
    connection.execute("SELECT pg_advisory_xact_lock(7319003)")
    schema = (Path(__file__).resolve().parents[1] / "infra/postgres/scanner-schema.sql").read_text()
    connection.execute(schema, prepare=False)


def setup_scanner():
    settings = replace(Settings.from_env(), db_name="passguard_control")
    credentials = DatabaseCredentials("postgres", SecretStr((state_dir() / "bootstrap/postgres_password").read_text().strip()))
    with connect(settings, credentials, readonly=False) as connection:
        migrate(connection)
    print("Таблица отчётов сканирования готова; пользователи и секреты сохранены.")


def main():
    try:
        setup_scanner()
    except (OSError, ValueError, psycopg.Error):
        print("Не удалось подготовить сканирование. Сначала выполни scripts.setup_control; чувствительные подробности скрыты.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
