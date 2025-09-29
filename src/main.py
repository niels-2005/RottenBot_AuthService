from fastapi import FastAPI
from .auth.routes import auth_router
from contextlib import asynccontextmanager
from src.db.main import init_db


# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     # Startup code here
#     await init_db()
#     yield
#     # Shutdown code here


version = "v1"

version_prefix = f"/api/{version}"

description = "..."

app = FastAPI(
    title="Rotten Bot SignUp API",
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
    # lifespan=lifespan,
)


app.include_router(auth_router, prefix=f"{version_prefix}/auth", tags=["auth"])
