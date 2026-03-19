"""DARKWATCH Pro Intelligence API - v2.0.0 with Auth & Multi-tenant."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from src.shared.config import settings
from src.geo.router import router as geo_router
from src.cyber.router import router as cyber_router
from src.economic.router import router as economic_router
from src.ai.router import router as ai_router
from src.auth.router import router as auth_router
from src.auth.org_router import router as org_router, users_router
from src.auth.assets_router import router as assets_router
from src.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    # Init database tables
    try:
        await init_db()
    except Exception as e:
        print(f"DB init warning: {e}")
    yield


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="DARKWATCH Pro Intelligence API",
    description="Multi-tenant threat intelligence platform with auth.",
    version="2.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all routers
app.include_router(auth_router)
app.include_router(org_router)
app.include_router(users_router)
app.include_router(assets_router)
app.include_router(geo_router)
app.include_router(cyber_router)
app.include_router(economic_router)
app.include_router(ai_router)


@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "2.0.0"}


@app.get("/openapi.json", include_in_schema=False)
async def openapi():
    return app.openapi()
