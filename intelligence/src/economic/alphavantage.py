"""Alpha Vantage real-time financial market data."""
import asyncio
import logging
from typing import Any, Dict, List
import httpx
from src.shared.config import settings

logger = logging.getLogger(__name__)
_BASE = "https://www.alphavantage.co/query"

async def _fetch(params: Dict) -> Any:
    if not settings.alpha_vantage_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(_BASE, params={**params, "apikey": settings.alpha_vantage_key})
            if r.status_code != 200:
                return None
            d = r.json()
            if "Error Message" in d or "Note" in d:
                logger.warning(f"AlphaVantage: {list(d.keys())}")
                return None
            return d
    except Exception as e:
        logger.error(f"AlphaVantage: {e!r}")
        return None

async def get_forex(from_sym: str, to_sym: str) -> Dict[str, Any]:
    data = await _fetch({"function": "CURRENCY_EXCHANGE_RATE", "from_currency": from_sym, "to_currency": to_sym})
    if not data:
        return {}
    rate = data.get("Realtime Currency Exchange Rate", {})
    return {"pair": f"{from_sym}/{to_sym}", "rate": rate.get("5. Exchange Rate"), "bid": rate.get("8. Bid Price"), "ask": rate.get("9. Ask Price"), "source": "alphavantage"}

async def get_commodity(symbol: str, name: str) -> Dict[str, Any]:
    data = await _fetch({"function": "GLOBAL_QUOTE", "symbol": symbol})
    if not data:
        return {}
    q = data.get("Global Quote", {})
    if not q.get("05. price"):
        return {}
    return {"symbol": symbol, "name": name, "price": q.get("05. price"), "change_pct": q.get("10. change percent", "").replace("%", ""), "source": "alphavantage"}

async def get_strategic_markets() -> List[Dict[str, Any]]:
    """Fetch real commodity and forex data."""
    tasks = [
        get_forex("EUR", "USD"),
        get_forex("GBP", "USD"),
        get_forex("JPY", "USD"),
        get_commodity("GC=F", "Gold Spot"),
        get_commodity("CL=F", "WTI Crude"),
        get_commodity("^VIX", "VIX Index"),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict) and r]
