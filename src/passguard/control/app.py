from contextlib import asynccontextmanager
import os
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import Cookie, Depends, FastAPI, Header, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import httpx

from passguard.config import Settings
from passguard.database import DatabaseUnavailable
from passguard.vault_client import VaultClient, VaultDenied, VaultError, VaultUnavailable
from passguard.control.models import AuthView, ChangePasswordRequest, CreateUserRequest, LoginRequest, RotationRequest, UpdateUserRequest, UserListView, UserView
from passguard.control.repository import ControlError, ControlRepository, Identity
from passguard.control.security import COOKIE_NAME, COOKIE_PATH, SecuritySettings, valid_csrf


def create_app(repository=None, vault=None, security: SecuritySettings | None = None, probe=None) -> FastAPI:
    security = security or SecuritySettings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owned_vault = None
        if repository is None:
            settings = Settings.from_env()
            owned_vault = VaultClient(settings.vault_addr, settings.ca_file, settings.identity_dir)
            app.state.vault = owned_vault
            app.state.repository = ControlRepository(settings, owned_vault)
        else:
            app.state.repository, app.state.vault = repository, vault
        with httpx.Client(base_url=os.getenv("DEMO_URL", "http://demo:8001"), timeout=8, trust_env=False) as demo:
            def default_probe():
                try:
                    response = demo.get("/ready")
                    return response.status_code == 200 and response.json().get("status") == "ready"
                except (httpx.HTTPError, ValueError):
                    return False
            app.state.probe = probe or default_probe
            try:
                yield
            finally:
                if owned_vault:
                    owned_vault.close()

    app = FastAPI(title="PassGuard — управляющий API", version="0.2.0", lifespan=lifespan)

    @app.middleware("http")
    async def browser_protection(request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            if origin is None and referer:
                parsed = urlsplit(referer)
                origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin is not None and origin not in security.allowed_origins:
                return JSONResponse(status_code=403, content={"detail": "Источник запроса не разрешён", "code": "invalid_origin"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.url.path.startswith(COOKIE_PATH):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ControlError)
    async def control_error(_: Request, error: ControlError):
        return JSONResponse(status_code=error.status, content={"detail": error.detail, "code": error.code})

    @app.exception_handler(DatabaseUnavailable)
    @app.exception_handler(VaultError)
    async def dependency_error(_: Request, __: Exception):
        return JSONResponse(status_code=503, content={"detail": "Зависимость управляющего API недоступна", "code": "dependency_unavailable"})

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, error: RequestValidationError):
        # Pydantic's standard response includes input values. Password inputs
        # and arbitrary request bodies must not be echoed into API errors.
        errors = [{"loc": list(item["loc"]), "type": item["type"], "msg": item["msg"]} for item in error.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    def current_identity(request: Request, token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None):
        identity = request.app.state.repository.authenticate(token)
        if identity is None:
            raise ControlError(401, "authentication_required", "Требуется вход в систему")
        return identity

    def allow(*roles):
        def permission(request: Request, identity: Annotated[Identity, Depends(current_identity)],
                       csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None):
            if identity.user["role"] not in roles:
                request.app.state.repository.audit(identity.user, "access.denied", "denied", {"route": request.scope["route"].path})
                raise ControlError(403, "permission_denied", "Недостаточно прав")
            if request.method not in ("GET", "HEAD", "OPTIONS") and not valid_csrf(csrf, identity.csrf_token):
                request.app.state.repository.audit(identity.user, "csrf.denied", "denied")
                raise ControlError(403, "csrf_failed", "CSRF-токен не принят")
            return identity
        return permission

    any_user = allow("admin", "operator", "auditor")
    admins = allow("admin")
    auditors = allow("admin", "auditor")
    operators = allow("admin", "operator")
    prefix = COOKIE_PATH

    def provider(request: Request):
        if request.app.state.vault is None:
            raise VaultUnavailable("Vault client is unavailable")
        return request.app.state.vault

    def clear_cookie(response: Response):
        response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, secure=security.cookie_secure, httponly=True, samesite="strict")

    @app.get("/health", summary="Состояние процесса")
    def health():
        return {"status": "ok", "service": "passguard-control"}

    @app.get("/ready", summary="Доступ к Vault и управляющей базе")
    def ready(request: Request):
        request.app.state.repository.ready()
        return {"status": "ready"}

    @app.post(prefix + "/auth/login", response_model=AuthView, summary="Войти")
    def login(body: LoginRequest, request: Request, response: Response):
        peer = (request.client.host if request.client else "unknown")[:64]
        result = request.app.state.repository.login(body.username, body.password.get_secret_value(), peer, security.session_seconds)
        response.set_cookie(COOKIE_NAME, result.token, max_age=security.session_seconds,
                            path=COOKIE_PATH, httponly=True, secure=security.cookie_secure, samesite="strict")
        return {"user": result.user, "csrf_token": result.csrf_token}

    @app.get(prefix + "/auth/me", response_model=AuthView, summary="Текущий пользователь и CSRF-токен")
    def me(identity: Annotated[Identity, Depends(any_user)]):
        return {"user": identity.user, "csrf_token": identity.csrf_token}

    @app.post(prefix + "/auth/logout", status_code=204, summary="Завершить сессию")
    def logout(request: Request, identity: Annotated[Identity, Depends(any_user)]):
        request.app.state.repository.logout(identity)
        response = Response(status_code=204)
        clear_cookie(response)
        return response

    @app.post(prefix + "/auth/password", status_code=204, summary="Сменить пароль и завершить все свои сессии")
    def password(body: ChangePasswordRequest, request: Request, identity: Annotated[Identity, Depends(any_user)]):
        request.app.state.repository.change_password(identity, body.current_password.get_secret_value(), body.new_password.get_secret_value())
        response = Response(status_code=204)
        clear_cookie(response)
        return response

    @app.get(prefix + "/users", response_model=UserListView, summary="Список пользователей")
    def users(request: Request, _: Annotated[Identity, Depends(admins)],
              limit: Annotated[int, Query(ge=1, le=100)] = 50, offset: Annotated[int, Query(ge=0, le=100000)] = 0):
        return {"items": request.app.state.repository.users(limit, offset)}

    @app.post(prefix + "/users", status_code=201, response_model=UserView, summary="Создать пользователя")
    def create_user(body: CreateUserRequest, request: Request, identity: Annotated[Identity, Depends(admins)]):
        return request.app.state.repository.create_user(identity, body.username, body.password.get_secret_value(), body.role.value)

    @app.patch(prefix + "/users/{user_id}", response_model=UserView, summary="Изменить роль или активность пользователя")
    def update_user(user_id: UUID, body: UpdateUserRequest, request: Request, identity: Annotated[Identity, Depends(admins)]):
        return request.app.state.repository.update_user(identity, user_id, body.role.value if body.role else None, body.active)

    @app.get(prefix + "/audit", summary="Журнал действий")
    def audit(request: Request, _: Annotated[Identity, Depends(auditors)],
              limit: Annotated[int, Query(ge=1, le=100)] = 50, before_id: Annotated[int | None, Query(ge=1)] = None):
        items = request.app.state.repository.audit_events(limit, before_id)
        return {"items": items, "next_before_id": items[-1]["id"] if len(items) == limit else None}

    @app.get(prefix + "/secrets", summary="Метаданные учебного секрета")
    def secrets(request: Request, _: Annotated[Identity, Depends(any_user)]):
        return {"items": [provider(request).database_role("demo-db")]}

    @app.post(prefix + "/checks/demo", summary="Проверить демонстрационное приложение")
    def check_demo(request: Request, identity: Annotated[Identity, Depends(operators)]):
        available = request.app.state.probe()
        request.app.state.repository.audit(identity.user, "checks.demo", "success" if available else "failed")
        return {"status": "ready" if available else "unavailable"}

    @app.post(prefix + "/secrets/demo-db/rotate", summary="Заменить пароль учебной БД")
    def rotate(body: RotationRequest, request: Request, identity: Annotated[Identity, Depends(admins)]):
        repo = request.app.state.repository
        operation, created = repo.begin_rotation(identity, body.idempotency_key, body.reason.value)
        if created:
            try:
                provider(request).rotate_database_password("demo-db")
            except VaultError as error:
                state = "failed" if isinstance(error, VaultDenied) else "unknown"
                operation = repo.finish_rotation(identity, body.idempotency_key, state)
            else:
                operation = repo.finish_rotation(identity, body.idempotency_key, "succeeded")
        status = 202 if operation["status"] == "in_progress" else (502 if operation["status"] in ("failed", "unknown") else 200)
        return JSONResponse(status_code=status, content=jsonable_encoder({"operation": operation, "replayed": not created}))

    @app.get(prefix + "/operations/{operation_id}", summary="Проверить результат операции")
    def operation(operation_id: UUID, request: Request, _: Annotated[Identity, Depends(auditors)]):
        return request.app.state.repository.operation(operation_id)

    return app


app = create_app()
