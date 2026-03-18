import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.shared.cache import cache
from src.geo.router import router as geo_router
from src.cyber.router import router as cyber_router
from src.economic.router import router as economic_router
from src.ai.router import router as ai_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DARKWATCH Pro starting...")
    await cache.init()
    yield
    await cache.close()


app = FastAPI(
    title="DARKWATCH Pro Intelligence Service",
    description="Multi-domain threat intelligence API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(geo_router, prefix="/geo", tags=["Geopolitical"])
app.include_router(cyber_router, prefix="/cyber", tags=["Cyber"])
app.include_router(economic_router, prefix="/economic", tags=["Economic"])
app.include_router(ai_router, prefix="/ai", tags=["AI Risk"])


@app.get("/health")
async def health():
    return {"status": "ok", "service": "darkwatch-pro-intelligence", "version": "2.0.0"}


@app.get("/")
async def root():
    return {
        "service": "DARKWATCH Pro Intelligence API",
        "version": "2.0.0",
        "endpoints": {
            "geo": "/geo/risk/{country_code}",
            "cyber": "/cyber/threats",
            "economic": "/economic/signals",
            "ai": "/ai/risk",
            "health": "/health",
            "docs": "/docs",
        }
    }
