"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.scans import router as scans_router
from backend.app.config import Settings


def create_app() -> FastAPI:
    settings = Settings.from_environment()
    app = FastAPI(title="Nmap Automator API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.include_router(scans_router)
    return app


app = create_app()
