"""DARKWATCH Pro Intelligence API - v2.1.0"""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from src.auth.router import router as auth_router
from src.auth.org_router import router as org_router, users_router
from src.auth.assets_router import router as assets_router
from src.geo.router import router as geo_router
from src.cyber.router import router as cyber_router
from src.economic.router import router as economic_router
from src.ai.router import router as ai_router
from src.darkweb.router import router as darkweb_router
from src.investigate.router import router as investigate_router
from src.posture.router import router as posture_router
from src.vuln.router import router as vuln_router
from src.news.router import router as news_router
from src.db.database import init_db
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DARKWATCH Pro v2.1.0 starting...")
    await init_db()
    yield

app = FastAPI(title="DARKWATCH Pro Intelligence API", description="Multi-domain threat intelligence platform", version='2.2.0', lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
app.include_router(auth_router)
app.include_router(org_router)
app.include_router(users_router)
app.include_router(assets_router)
app.include_router(geo_router, prefix="/geo", tags=["Geopolitical"])
app.include_router(cyber_router, prefix="/cyber", tags=["Cyber"])
app.include_router(economic_router, prefix="/economic", tags=["Economic"])
app.include_router(ai_router, prefix="/ai", tags=["AI Risk"])
app.include_router(darkweb_router)
app.include_router(investigate_router)
app.include_router(posture_router)
app.include_router(vuln_router)
app.include_router(news_router)

@app.get("/health")
async def health():
    return {"status":"ok","service":"darkwatch-pro-intelligence","version":"2.2.0"}

@app.get("/")
async def root():
    return {"service":"DARKWATCH Pro Intelligence API","version":"2.2.0","modules":["geo","cyber","economic","ai","darkweb","investigate","posture","vuln"]}
