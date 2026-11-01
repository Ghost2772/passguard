from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

from passguard.config import Settings
from passguard.database import connect, DatabaseUnavailable, is_authentication_error
from passguard.vault_client import VaultClient
from passguard.control.security import DUMMY_HASH, hash_password, new_token, token_digest, verify_password
from passguard.scanner.models import ScanResult


class ControlError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        self.status, self.code, self.detail = status, code, detail
        super().__init__(detail)


def public_user(row: dict) -> dict:
    return {key: row[key] for key in ("id", "username", "role", "active", "created_at")}


@dataclass(frozen=True)
class Identity:
    user: dict
    csrf_token: str = field(repr=False)
    session_hash: str = field(repr=False)


@dataclass(frozen=True)
class LoginResult:
    user: dict
    token: str = field(repr=False)
    csrf_token: str = field(repr=False)


class ControlRepository:
    def __init__(self, settings: Settings, vault: VaultClient):
        self.settings, self.vault = settings, vault

    @contextmanager
    def connection(self):
        for attempt in range(2):
            credentials = self.vault.database_credentials("control-db")
            try:
                connection = connect(self.settings, credentials, readonly=False,
                                     application_name="passguard-control")
                break
            except psycopg.Error as error:
                if attempt == 0 and is_authentication_error(error):
                    continue
                raise DatabaseUnavailable("Control database connection is unavailable") from None
        try:
            with connection:
                yield connection
        except psycopg.errors.UniqueViolation:
            raise ControlError(409, "already_exists", "Такая запись уже существует") from None
        except psycopg.Error:
            raise DatabaseUnavailable("Control database operation failed") from None

    @staticmethod
    def _audit(connection, actor: dict | None, action: str, outcome: str, details: dict | None = None):
        actor = actor or {}
        connection.execute(
            "INSERT INTO control.audit (actor_id,actor_username,actor_role,action,outcome,details) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (actor.get("id"), actor.get("username"), actor.get("role"), action, outcome, Jsonb(details or {})),
        )

    def audit(self, actor: dict | None, action: str, outcome: str, details: dict | None = None):
        with self.connection() as connection:
            self._audit(connection, actor, action, outcome, details)

    def ready(self):
        with self.connection() as connection:
            connection.execute("SELECT id FROM control.users LIMIT 1")

    def login(self, username: str, password: str, peer: str, session_seconds: int) -> LoginResult:
        error = None
        result = None
        with self.connection() as connection:
            # Serialize attempts from one peer so concurrent requests cannot
            # bypass the database-backed rate limit.
            connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("login:" + peer,))
            connection.execute(
                "INSERT INTO control.login_failures (peer) VALUES (%s) ON CONFLICT DO NOTHING", (peer,)
            )
            connection.execute(
                "UPDATE control.login_failures SET failures=0,window_start=now() "
                "WHERE peer=%s AND window_start < now()-interval '15 minutes'", (peer,)
            )
            attempts = connection.execute(
                "SELECT failures FROM control.login_failures WHERE peer=%s FOR UPDATE", (peer,)
            ).fetchone()["failures"]
            if attempts >= 10:
                self._audit(connection, None, "auth.rate_limited", "denied")
                error = ControlError(429, "rate_limited", "Слишком много попыток входа. Повтори позже")
            else:
                user = connection.execute("SELECT * FROM control.users WHERE username=%s", (username,)).fetchone()
                valid = verify_password(password, user["password_hash"] if user else DUMMY_HASH)
                if not valid or user is None or not user["active"]:
                    connection.execute("UPDATE control.login_failures SET failures=failures+1 WHERE peer=%s", (peer,))
                    self._audit(connection, public_user(user) if user else None, "auth.login", "denied")
                    error = ControlError(401, "invalid_credentials", "Неверный логин или пароль")
                else:
                    token, csrf = new_token(), new_token()
                    connection.execute("DELETE FROM control.login_failures WHERE peer=%s", (peer,))
                    connection.execute("DELETE FROM control.sessions WHERE expires_at<=now()")
                    connection.execute(
                        "INSERT INTO control.sessions (token_hash,user_id,csrf_token,expires_at) VALUES (%s,%s,%s,%s)",
                        (token_digest(token), user["id"], csrf,
                         datetime.now(timezone.utc) + timedelta(seconds=session_seconds)),
                    )
                    result = LoginResult(public_user(user), token, csrf)
                    self._audit(connection, result.user, "auth.login", "success")
        # Raising outside the transaction keeps failed attempts and their audit.
        if error:
            raise error
        return result

    def authenticate(self, token: str | None) -> Identity | None:
        if not token or not 20 <= len(token) <= 200:
            return None
        digest = token_digest(token)
        with self.connection() as connection:
            row = connection.execute(
                "SELECT u.*,s.csrf_token FROM control.sessions s JOIN control.users u ON u.id=s.user_id "
                "WHERE s.token_hash=%s AND s.expires_at>now() AND u.active=true", (digest,)
            ).fetchone()
            return Identity(public_user(row), row["csrf_token"], digest) if row else None

    def logout(self, actor: Identity):
        with self.connection() as connection:
            connection.execute("DELETE FROM control.sessions WHERE token_hash=%s", (actor.session_hash,))
            self._audit(connection, actor.user, "auth.logout", "success")

    def change_password(self, actor: Identity, old_password: str, new_password: str):
        error = None
        with self.connection() as connection:
            row = connection.execute("SELECT password_hash FROM control.users WHERE id=%s FOR UPDATE", (actor.user["id"],)).fetchone()
            if not row or not verify_password(old_password, row["password_hash"]):
                self._audit(connection, actor.user, "auth.password_change", "denied")
                error = ControlError(400, "invalid_current_password", "Текущий пароль не принят")
            else:
                connection.execute("UPDATE control.users SET password_hash=%s WHERE id=%s", (hash_password(new_password), actor.user["id"]))
                connection.execute("DELETE FROM control.sessions WHERE user_id=%s", (actor.user["id"],))
                self._audit(connection, actor.user, "auth.password_change", "success")
        if error:
            raise error

    def users(self, limit: int, offset: int) -> list[dict]:
        with self.connection() as connection:
            return connection.execute(
                "SELECT id,username,role,active,created_at FROM control.users ORDER BY created_at,id LIMIT %s OFFSET %s", (limit, offset)
            ).fetchall()

    def create_user(self, actor: Identity, username: str, password: str, role: str) -> dict:
        encoded = hash_password(password)
        with self.connection() as connection:
            row = connection.execute(
                "INSERT INTO control.users (id,username,password_hash,role) VALUES (%s,%s,%s,%s) "
                "RETURNING id,username,role,active,created_at", (uuid4(), username, encoded, role)
            ).fetchone()
            self._audit(connection, actor.user, "users.create", "success", {"user_id": str(row["id"]), "role": role})
            return row

    def update_user(self, actor: Identity, user_id: UUID, role: str | None, active: bool | None) -> dict:
        error, result = None, None
        with self.connection() as connection:
            # Protect the last active administrator across concurrent changes.
            connection.execute("SELECT pg_advisory_xact_lock(7319002)")
            target = connection.execute("SELECT * FROM control.users WHERE id=%s FOR UPDATE", (user_id,)).fetchone()
            if not target:
                error = ControlError(404, "user_not_found", "Пользователь не найден")
            else:
                next_role = role if role is not None else target["role"]
                next_active = active if active is not None else target["active"]
                if target["role"] == "admin" and target["active"] and (next_role != "admin" or not next_active):
                    admins = connection.execute("SELECT count(*) AS n FROM control.users WHERE role='admin' AND active").fetchone()["n"]
                    if admins <= 1:
                        error = ControlError(409, "last_admin", "Нельзя отключить или понизить последнего администратора")
                if error is None:
                    result = connection.execute(
                        "UPDATE control.users SET role=%s,active=%s WHERE id=%s RETURNING id,username,role,active,created_at",
                        (next_role, next_active, user_id),
                    ).fetchone()
                    if next_role != target["role"] or next_active != target["active"]:
                        connection.execute("DELETE FROM control.sessions WHERE user_id=%s", (user_id,))
                    self._audit(connection, actor.user, "users.update", "success", {"user_id": str(user_id), "role": next_role, "active": next_active})
            if error:
                self._audit(connection, actor.user, "users.update", "denied", {"user_id": str(user_id), "code": error.code})
        if error:
            raise error
        return result

    def audit_events(self, limit: int, before: int | None) -> list[dict]:
        with self.connection() as connection:
            return connection.execute(
                "SELECT * FROM control.audit WHERE (%s::bigint IS NULL OR id<%s) ORDER BY id DESC LIMIT %s", (before, before, limit)
            ).fetchall()

    def begin_rotation(self, actor: Identity, operation_id: UUID, reason: str) -> tuple[dict, bool]:
        with self.connection() as connection:
            row = connection.execute(
                "INSERT INTO control.operations (id,actor_id,secret_id,reason,status) "
                "VALUES (%s,%s,'demo-db',%s,'in_progress') ON CONFLICT DO NOTHING RETURNING *",
                (operation_id, actor.user["id"], reason),
            ).fetchone()
            if row:
                self._audit(connection, actor.user, "secrets.rotate", "started", {"operation_id": str(operation_id), "secret_id": "demo-db", "reason": reason})
                return row, True
            row = connection.execute("SELECT * FROM control.operations WHERE id=%s", (operation_id,)).fetchone()
            if row["actor_id"] != actor.user["id"] or row["reason"] != reason:
                raise ControlError(409, "idempotency_conflict", "Ключ операции уже использован другим запросом")
            return row, False

    def finish_rotation(self, actor: Identity, operation_id: UUID, status: str) -> dict:
        with self.connection() as connection:
            row = connection.execute(
                "UPDATE control.operations SET status=%s,finished_at=now() WHERE id=%s AND status='in_progress' RETURNING *", (status, operation_id)
            ).fetchone()
            if row is None:
                raise ControlError(409, "operation_state", "Состояние операции уже изменено")
            self._audit(connection, actor.user, "secrets.rotate", "success" if status == "succeeded" else status,
                        {"operation_id": str(operation_id), "secret_id": "demo-db"})
            return row

    def operation(self, operation_id: UUID) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM control.operations WHERE id=%s", (operation_id,)).fetchone()
            if not row:
                raise ControlError(404, "operation_not_found", "Операция не найдена")
            return row

    def save_scan(self, actor: Identity, result: ScanResult) -> dict:
        # Revalidate before SQL; no arbitrary detector dictionaries or snippets.
        safe = ScanResult.model_validate(result.model_dump()).model_dump()
        with self.connection() as connection:
            row = connection.execute(
                "INSERT INTO control.scans (id,actor_id,findings_count,result) VALUES (%s,%s,%s,%s) RETURNING *",
                (uuid4(), actor.user["id"], len(safe["findings"]), Jsonb(safe)),
            ).fetchone()
            self._audit(connection, actor.user, "scans.create", "success",
                        {"scan_id": str(row["id"]), "findings_count": len(safe["findings"]),
                         "files_scanned": safe["files_scanned"], "skipped_count": len(safe["skipped_files"])})
            return row

    def scans(self, limit: int, offset: int) -> list[dict]:
        with self.connection() as connection:
            return connection.execute(
                "SELECT id,actor_id,created_at,findings_count,result->>'engine' AS engine, "
                "result->>'engine_version' AS engine_version,(result->>'files_scanned')::int AS files_scanned "
                "FROM control.scans ORDER BY created_at DESC,id LIMIT %s OFFSET %s", (limit, offset)
            ).fetchall()

    def scan_report(self, scan_id: UUID) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM control.scans WHERE id=%s", (scan_id,)).fetchone()
            if row is None:
                raise ControlError(404, "scan_not_found", "Отчёт не найден")
            row["result"] = ScanResult.model_validate(row["result"]).model_dump()
            return row
