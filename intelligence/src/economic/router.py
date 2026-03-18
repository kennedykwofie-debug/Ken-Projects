"""Economic intelligence API routes."""

import asyncio
import logging
from typing import Any, Dict

from fastapi import APIRouter

from src.shared.cache import cache
from src.shared.config import settings
from src.economic.fred import fetch_all_macro_signals
from src.economic.finnhub import fetch_strategic_quotes
from src.economic.analyser import analyse_macro_signals, signals_to_dict

logger = logging.getLogger(__name__)
router = APIRouter()

_MACRO_CACHE = "economic:macro:v1"
_MARKETS_CACHE = "economic:markets:v1"
_SIGNALS_CACHE = "economic:signals:v1"


@router.get("/macro")
async def get_macro_indicators() -> Dict[str, Any]:
    """
    Federal Reserve macro indicators: yield curve, inflation, employment,
    financial stress index, M2 money supply, credit spreads.
    """
    data = await cache.cached_fetch(
        _MACRO_CACHE,
        ttl=settings.cache_ttl_medium,
        fetcher=fetch_all_macro_signals,
        stale_ttl=settings.cache_ttl_long,
    )
    return {
        "indicators": data or [],
        "count": len(data or []),
        "source": "fred",
    }


@router.get("/markets")
async def get_strategic_markets() -> Dict[str, Any]:
    """
    Strategic market data: global indices, commodities (oil, gold, wheat, copper),
    and geopolitically significant currency pairs.
    """
    data = await cache.cached_fetch(
        _MARKETS_CACHE,
        ttl=300,  # 5 min — markets move fast
        fetcher=fetch_strategic_quotes,
        stale_ttl=settings.cache_ttl_medium,
    )
    return data or {"indices": [], "commodities": [], "forex": []}


@router.get("/signals")
async def get_economic_signals() -> Dict[str, Any]:
    """
    Computed economic risk signals: yield curve inversion, financial stress,
    commodity price stress index, credit spread widening.
    Each signal includes severity rating and plain-English description.
    """
    async def _compute():
        macro, markets = await asyncio.gather(
            fetch_all_macro_signals(),
            fetch_strategic_quotes(),
            return_exceptions=True,
        )
        fred_data = macro if isinstance(macro, list) else []
        market_data = markets if isinstance(markets, dict) else {}
        signals = analyse_macro_signals(fred_data, market_data)
        return signals_to_dict(signals)

    data = await cache.cached_fetch(
        _SIGNALS_CACHE,
        ttl=settings.cache_ttl_short,
        fetcher=_compute,
        stale_ttl=settings.cache_ttl_medium,
    )
    return {
        "signals": data or [],
        "count": len(data or []),
    }
