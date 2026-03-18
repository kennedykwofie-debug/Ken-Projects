"""Finnhub strategic market data fetcher."""
import logging
from typing import Any, Dict, List

from src.shared.config import settings
from src.shared.http import get

logger = logging.getLogger(__name__)

_BASE = "https://finnhub.io/api/v1"

_SYMBOLS = [
    ("GC=F", "Gold", "commodity"),
    ("CL=F", "WTI Crude Oil", "commodity"),
    ("DX-Y.NYB", "US Dollar Index", "currency"),
    ("^TNX", "10Y Treasury Yield", "bond"),
    ("^VIX", "VIX", "volatility"),
    ("BTC-USD", "Bitcoin", "crypto"),
]


async def fetch_quote(symbol: str) -> Dict[str, Any]:
    """Fetch a single quote from Finnhub."""
    if not settings.finnhub_key:
        return {}
    try:
        data = await get(
            f"{_BASE}/quote",
            params={"symbol": symbol, "token": settings.finnhub_key},
        )
        if not data.get("c"):
            return {}
        return {
            "symbol": symbol,
            "price": round(float(data.get("c", 0)), 4),
            "change_pct": round(float(data.get("dp", 0)), 2),
            "high": round(float(data.get("h", 0)), 4),
            "low": round(float(data.get("l", 0)), 4),
            "source": "finnhub",
        }
    except Exception as e:
        logger.debug(f"Finnhub {symbol} error: {e}")
        return {}


async def fetch_strategic_markets() -> List[Dict[str, Any]]:
    """Fetch all strategic market quotes."""
    import asyncio
    results = await asyncio.gather(
        *[fetch_quote(sym) for sym, _, _ in _SYMBOLS],
        return_exceptions=True,
    )
    enriched = []
    for i, r in enumerate(results):
        if isinstance(r, dict) and r.get("symbol"):
            sym, name, category = _SYMBOLS[i]
            enriched.append({**r, "name": name, "category": category})
    return enriched
