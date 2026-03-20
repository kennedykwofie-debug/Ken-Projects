"""FRED (Federal Reserve Economic Data) macro signal fetcher."""
import asyncio
import logging
from typing import Any, Dict, List

import httpx

from src.shared.config import settings

logger = logging.getLogger(__name__)

_BASE = "https://api.stlouisfed.org/fred/series/observations"

_SERIES = {
    "DFF": "Fed Funds Rate",
    "T10Y2Y": "10Y-2Y Yield Spread",
    "BAMLH0A0HYM2": "High Yield Spread",
    "DCOILWTICO": "WTI Oil Price",
    "DTWEXBGS": "USD Broad Index",
    "VIXCLS": "VIX Volatility Index",
    "STLFSI4": "St. Louis FSI",
    "GVZCLS": "Gold Volatility",
}


async def fetch_series(series_id: str) -> Dict[str, Any]:
    """Fetch latest observation for a FRED series."""
    if not settings.fred_key:
        logger.warning("FRED_KEY not configured")
        return {}
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=True) as client:
            resp = await client.get(
                _BASE,
                params={
                    "series_id": series_id,
                    "api_key": settings.fred_key,
                    "file_type": "json",
                    "sort_order": "desc",
                    "limit": "2",
                },
            )
            resp.raise_for_status()
            data = resp.json()
        if not data:
            logger.error(f"FRED {series_id}: empty response")
            return {}
        obs = data.get("observations", [])
        if not obs:
            logger.error(f"FRED {series_id}: no observations in {list(data.keys())}")
            return {}
        latest = obs[0]
        prev = obs[1] if len(obs) > 1 else {}
        raw_val = latest.get("value", "")
        if not raw_val or raw_val == ".":
            return {}
        val = float(raw_val)
        prev_raw = prev.get("value", "")
        prev_val = float(prev_raw) if prev_raw and prev_raw != "." else 0.0
        return {
            "series_id": series_id,
            "name": _SERIES.get(series_id, series_id),
            "value": round(val, 4),
            "date": str(latest.get("date", ""))[:10],
            "change": round(val - prev_val, 4) if prev_val else 0,
            "source": "fred",
        }
    except Exception as e:
        logger.error(f"FRED fetch_series {series_id} failed: {e!r}")
        return {}


async def fetch_all_macro_signals() -> List[Dict[str, Any]]:
    """Fetch all configured FRED macro signals."""
    results = await asyncio.gather(
        *[fetch_series(sid) for sid in _SERIES], return_exceptions=True
    )
    return [r for r in results if isinstance(r, dict) and r.get("series_id")]
