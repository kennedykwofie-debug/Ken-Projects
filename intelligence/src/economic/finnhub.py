"""
Finnhub market data adapter.
Free API key required. https://finnhub.io/
Provides: stock quotes, forex, commodities, economic indicators.
Rate limit: 60 calls/min on free tier.
"""

import logging
from typing import Any, Dict, List, Optional

from src.shared.config import settings
from src.shared.http import get_json

logger = logging.getLogger(__name__)

_BASE = "https://finnhub.io/api/v1"
_ALLOWED_HOST = "finnhub.io"

# Strategic market indices and commodities for threat-relevant monitoring
STRATEGIC_SYMBOLS = {
    # Major indices — health of global capital markets
    "indices": {
        "SPY":  "S&P 500 ETF",
        "QQQ":  "NASDAQ 100 ETF",
        "VGK":  "Europe ETF",
        "EEM":  "Emerging Markets ETF",
        "EWJ":  "Japan ETF",
        "FXI":  "China Large-Cap ETF",
        "RSX":  "Russia ETF (suspended)",
    },
    # Commodities — supply chain and geopolitical stress indicators
    "commodities": {
        "GC=F":  "Gold",
        "SI=F":  "Silver",
        "CL=F":  "WTI Crude",
        "BZ=F":  "Brent Crude",
        "NG=F":  "Natural Gas",
        "W=F":   "Wheat",
        "C=F":   "Corn",
        "S=F":   "Soybeans",
        "HG=F":  "Copper",
        "PL=F":  "Platinum",
        "PA=F":  "Palladium",
    },
    # Currencies — geopolitical stress reflected in FX
    "forex": {
        "OANDA:USD_RUB": "USD/RUB",
        "OANDA:USD_CNH": "USD/CNH",
        "OANDA:USD_TRY": "USD/TRY",
        "OANDA:USD_UAH": "USD/UAH",
        "OANDA:XAU_USD": "Gold/USD",
    },
}


def _sanitise_quote(symbol: str, name: str, category: str, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    current = raw.get("c")
    prev_close = raw.get("pc")
    high = raw.get("h")
    low = raw.get("l")
    open_price = raw.get("o")

    if current is None or current == 0:
        return None

    try:
        current = float(current)
        prev_close = float(prev_close) if prev_close else current
    except (TypeError, ValueError):
        return None

    change_pct = round(((current - prev_close) / prev_close) * 100, 2) if prev_close else 0

    return {
        "symbol": symbol[:20],
        "name": name[:100],
        "category": category,
        "price": round(current, 4),
        "change_pct": change_pct,
        "high": round(float(high), 4) if high else None,
        "low": round(float(low), 4) if low else None,
        "open": round(float(open_price), 4) if open_price else None,
        "prev_close": round(prev_close, 4),
        "source": "finnhub",
    }


async def fetch_quote(symbol: str, name: str, category: str) -> Optional[Dict[str, Any]]:
    try:
        data = await get_json(
            f"{_BASE}/quote",
            params={"symbol": symbol, "token": settings.finnhub_key},
            allowed_host=_ALLOWED_HOST,
        )
        return _sanitise_quote(symbol, name, category, data)
    except Exception as e:
        logger.warning(f"Finnhub quote failed for {symbol}: {e}")
        return None


async def fetch_strategic_quotes() -> Dict[str, List[Dict[str, Any]]]:
    """Fetch all strategic market quotes in parallel with rate limiting."""
    import asyncio

    async def _with_delay(symbol: str, name: str, category: str, delay: float):
        await asyncio.sleep(delay)
        return await fetch_quote(symbol, name, category)

    tasks = []
    delay = 0.0
    for category, symbols in STRATEGIC_SYMBOLS.items():
        for symbol, name in symbols.items():
            tasks.append(_with_delay(symbol, name, category, delay))
            delay += 0.05  # 50ms between calls — well within 60/min limit]:    results = await asyncio.gather(*tasks, return_exceptions=True)

    output: Dict[str, List[Dict[str, Any]]] = {"indices": [], "commodities": [], "forex": []}
    for result in results:
        if isinstance(result, dict):
            cat = result.get("category", "")
            if cat in output:
                output[cat].append(result)

    return output
