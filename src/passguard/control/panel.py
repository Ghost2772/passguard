"""Serve the bundled panel from the API origin; no catch-all for API routes."""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


PANEL_CSP = "; ".join((
    "default-src 'self'", "script-src 'self'", "style-src 'self'",
    "font-src 'self'", "img-src 'self' data:", "connect-src 'self'",
    "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'",
))


def mount_panel(app: FastAPI, directory: Path | None = None):
    directory = directory or Path(os.getenv("PANEL_DIR", "/workspace/panel"))
    headers = {"Cache-Control": "no-cache", "Content-Security-Policy": PANEL_CSP,
               "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
               "Permissions-Policy": "camera=(), microphone=(), geolocation=()"}

    @app.get("/", include_in_schema=False)
    def panel():
        if not (directory / "index.html").is_file():
            return JSONResponse(status_code=503, content={"detail": "Панель не собрана. Собери Docker-образ control."})
        return FileResponse(directory / "index.html", headers=headers)

    if (directory / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=directory / "assets"), name="panel-assets")

    if (directory / "favicon.svg").is_file():
        @app.get("/favicon.svg", include_in_schema=False)
        def favicon():
            return FileResponse(directory / "favicon.svg", headers={"Cache-Control": "no-cache"})
