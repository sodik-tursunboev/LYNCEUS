"""FastAPI app. Run: uvicorn core.api.app:app --no-access-log (access logs would carry raw URLs)."""

from fastapi import FastAPI

from core.config import Settings
from core.log import configure


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure(settings.log_level)
    app = FastAPI(title="MIRAGE", version="0.0.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
