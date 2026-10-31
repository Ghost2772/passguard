from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from passguard.config import Settings
from passguard.database import DatabaseUnavailable, DocumentRepository
from passguard.vault_client import VaultClient, VaultError


def create_app(repository: DocumentRepository | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        vault = None
        if repository is None:
            settings = Settings.from_env()
            vault = VaultClient(settings.vault_addr, settings.ca_file, settings.identity_dir)
            app.state.repository = DocumentRepository(settings, vault)
        else:
            app.state.repository = repository
        try:
            yield
        finally:
            if vault is not None:
                vault.close()

    app = FastAPI(
        title="PassGuard: демонстрационный сервис",
        description="Учебный сервис получает пароль PostgreSQL из Vault при подключении.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.exception_handler(VaultError)
    async def vault_error(_: Request, __: VaultError):
        return JSONResponse(status_code=503, content={"detail": "Хранилище секретов недоступно"})

    @app.exception_handler(DatabaseUnavailable)
    async def database_error(_: Request, __: DatabaseUnavailable):
        return JSONResponse(status_code=503, content={"detail": "База данных недоступна"})

    @app.get("/health", summary="Проверка работы процесса")
    def health():
        return {"status": "ok", "service": "passguard-demo"}

    @app.get("/ready", summary="Проверка доступа к Vault и базе данных")
    def ready(request: Request):
        request.app.state.repository.list_documents()
        return {"status": "ready"}

    @app.get("/api/documents", summary="Получить учебные документы")
    def documents(request: Request):
        return {"items": request.app.state.repository.list_documents()}

    return app


app = create_app()
