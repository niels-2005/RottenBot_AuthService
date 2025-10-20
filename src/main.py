from fastapi import FastAPI
from .auth.routes import auth_router
from contextlib import asynccontextmanager
from src.db.main import init_db
from src.auth.setup_observability import setup_observability

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the lifespan of the application. This code runs on startup and shutdown.

    Args:
        app (FastAPI): The FastAPI application instance.
    """
    await init_db()
    setup_observability("auth_service")
    yield


version = "v1"

version_prefix = f"/api/{version}"

description = """Rotten Bot Auth API helps you manage user signups, logins, logouts and authentication for the Rotten Bot application."""

app = FastAPI(
    title="Rotten Bot Auth API",
    description=description,
    version=version,
    license_info={"name": "MIT License", "url": "https://opensource.org/license/mit"},
    contact={
        "name": "Niels Scholz",
    },
    terms_of_service="https://example.com/tos",
    openapi_url=f"{version_prefix}/openapi.json",
    docs_url=f"{version_prefix}/docs",
    redoc_url=f"{version_prefix}/redoc",
    lifespan=lifespan,
)

# include the auth router. Endpoints will be available under /api/v1/auth/...
app.include_router(auth_router, prefix=f"{version_prefix}/auth", tags=["auth"])
