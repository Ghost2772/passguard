from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from passguard.scanner.engine import SourceScanner
from passguard.scanner.errors import ScanError, failure
from passguard.scanner.models import SCANNER_VERSION, ScanResult
from passguard.scanner.upload import read_archive


def create_app(scanner=None):
    scanner = scanner or SourceScanner()
    app = FastAPI(title="PassGuard isolated scanner", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(ScanError)
    async def scan_error(_: Request, error: ScanError):
        return JSONResponse(status_code=error.status, content={"code": error.code, "detail": error.detail})

    @app.get("/health")
    def health():
        if not Path(scanner.binary).is_file():
            raise failure("scanner_unavailable")
        return {"status": "ready", "engine": "gitleaks", "engine_version": SCANNER_VERSION}

    @app.post("/scan", response_model=ScanResult)
    async def scan(request: Request):
        with scanner.slot():
            archive = await read_archive(request)
            try:
                return await run_in_threadpool(scanner.scan, archive)
            except OSError:
                raise failure("scanner_unavailable") from None

    return app


app = create_app()
