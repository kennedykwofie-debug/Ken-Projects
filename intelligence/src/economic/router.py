"""Economic intelligence API routes."""
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter

from src.shared.cache import cache
from src.shared.config import settings
from src.economic.analyser import build_economic_analysis
from src.economic.fred import fetch_all_macro_signals
from src.economic.finnhub import fetch_strategic_markets

logger = logging.getLogger(__name__)
router = APIRouter()

_ECO_CACHE_KEY = "economic:analysis:v1"
_MACRO_CACHE_KEY = "economic:macro:v1"


@router.get("/signals")
async def get_economic_signals() -> Dict[str, Any]:
    """Full economic intelligence picture — macro + markets + risk assessment."""
    cached = await cache.get(_ECO_CACHE_KEY)
    if cached:
        return cached
    data = await build_economic_analysis()
    await cache.set(_ECO_CACHE_KEY, data, ttl=settings.cache_ttl)
    return data


@router.get("/macro")
async def get_macro_signals() -> Dict[str, Any]:
    """FRED macro indicators — yield curve, credit spreads, FSI."""
    cached = await cache.get(_MACRO_CACHE_KEY)
    if cached:
        return cached
    signals = await fetch_all_macro_signals()
    result = {"signals": signals, "count": len(signals), "timestamp": datetime.now(timezone.utc).isoformat()}
    await cache.set(_MACRO_CACHE_KEY, result, ttl=settings.cache_ttl)
    return result


@router.get("/markets")
async def get_strategic_markets() -> Dict[str, Any]:
    """Strategic market data — gold, oil, VIX, Bitcoin, USD index."""
    markets = await fetch_strategic_markets()
    return {"markets": markets, "count": len(markets), "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/risk")
async def get_economic_risk() -> Dict[str, Any]:
    """Overall economic risk assessment."""
    cached = await cache.get(_ECO_CACHE_KEY)
    data = cached or await build_economic_analysis()
    return {
        "overall_risk": data.get("overall_risk", "MEDIUM"),
        "primary_concern": data.get("primary_concern", ""),
        "risk_assessments": data.get("risk_assessments", []),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
