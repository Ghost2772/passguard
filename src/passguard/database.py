import psycopg
from psycopg.rows import dict_row

from passguard.config import Settings
from passguard.vault_client import DatabaseCredentials, VaultClient


class DatabaseUnavailable(Exception):
    pass


def is_authentication_error(error: psycopg.Error) -> bool:
    # libpq connection failures may omit SQLSTATE; PostgreSQL runs with C locale.
    return error.sqlstate == "28P01" or "password authentication failed" in str(error)


def connect(settings: Settings, credentials: DatabaseCredentials, *, readonly: bool = True,
            application_name: str | None = None):
    return psycopg.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=credentials.username,
        password=credentials.password.get_secret_value(),
        sslmode="verify-full",
        sslrootcert=str(settings.db_ca_file),
        connect_timeout=5,
        application_name=application_name or ("passguard-demo" if readonly else "passguard-operator"),
        options="-c default_transaction_read_only=on" if readonly else "",
        row_factory=dict_row,
    )


class DocumentRepository:
    def __init__(self, settings: Settings, vault: VaultClient) -> None:
        self._settings = settings
        self._vault = vault

    def list_documents(self) -> list[dict]:
        # Reconnect on each request. Retry only authentication during connect;
        # no business operation or transaction is replayed.
        for attempt in range(2):
            credentials = self._vault.database_credentials()
            try:
                connection = connect(self._settings, credentials)
            except psycopg.Error as error:
                if attempt == 0 and is_authentication_error(error):
                    continue
                raise DatabaseUnavailable("Database connection is unavailable") from None
            try:
                with connection:
                    return connection.execute(
                        "SELECT id, title FROM demo.documents ORDER BY id"
                    ).fetchall()
            except psycopg.Error:
                raise DatabaseUnavailable("Database query failed") from None
        raise DatabaseUnavailable("Database connection is unavailable")
