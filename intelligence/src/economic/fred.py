"""
FRED (Federal Reserve Economic Data) adapter.
Free API key required. https://fred.stlouisfed.org/
Provides macro economic indicators: GDP, inflation, yield curves, employment.
"""

import logging
from typing import Any, Dict, List, Optional

from src.shared.config import settings
from src.shared.http import get_json

logger = logging.getLogger(__name__)

_BASE = "https://api.stlouisfed.org/fred"
_ALLOWED_HOST = "api.stlouisfed.org"

# Curated series for threat-relevant economic monitoring
# These are the signals most correlated with geopolitical instability
MACRO_SERIES: Dict[str, Dict[str, str]] = {
    # Yield curve — inversion = recession signal
    "T10Y2Y":     {"name": "10Y-2Y Yield Spread", "category": "yield_curve",    "unit": "percent"},
    "DGS10":      {"name": "10-Year Treasury",     "category": "yield_curve",    "unit": "percent"},
    "DGS2":       {"name": "2-Year Treasury",      "category": "yield_curve",    "unit": "percent"},
    # Inflation
    "CPIAUCSL":   {"name": "CPI (All Urban)",      "category": "inflation",      "unit": "index"},
    "PCEPI":      {"name": "PCE Price Index",      "category": "inflation",      "unit": "index"},
    # Labour
    "UNRATE":     {"name": "Unemployment Rate",    "category": "labour",         "unit": "percent"},
    "ICSA":       {"name": "Initial Jobless Claims","category": "labour",        "unit": "thousands"},
    # Credit / financial stress
    "DRCCLACBS":  {"name": "Credit Card Delinquency","category": "credit",       "unit": "percent"},
    "STLFSI4":    {"name": "St. Louis Financial Stress","category": "stress",    "unit": "index"},
    "BAMLH0A0HYM2": {"name": "High-Yield Spread",  "category": "credit",        "unit": "percent"},
    # Energy — strategic commodity
    "DCOILWTICO": {"name": "WTI Crude Oil",        "category": "energy",         "unit": "usd_per_barrel"},
    "DCOILBRENTEU":{"name": "Brent Crude",         "category": "energy",         "unit": "usd_per_barrel"},
    # USD strength — global liquidity indicator
    "DTWEXBGS":   {"name": "USD Broad Index",      "category": "fx",             "unit": "index"},
    # Money supply — monetary policy signal
    "M2SL":       {"name": "M2 Money Supply",      "category": "monetary",       "unit": "billions_usd"},
}


def _sanitise_observation(obs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    date = str(obs.get("date", ""))
    value_raw = obs.get("value", "")
    if value_raw == "." or value_raw is None:  # FRED uses "." for missing data
        return None
    try:
        value = float(value_raw)
    except (ValueError, TypeError):
        return None
    return {"date": date[:10], "value": round(value, 4)}


async def fetch_series(series_id: str, limit: int = 10) -> Optional[Dict[str, Any]]:
    """
    Fetch the most recent observations for a FRED series.
    Returns sanitised series data with metadata.
    """
    if series_id not in MACRO_SERIES:
        logger.warning(f"FRED: unknown series {series_id!r} — skipping")
        return None

    meta = MACRO_SERIES[series_id]

    try:
        data = await get_json(
            f"{_BASE}/series/observations",
            params={
                "series_id": series_id,
                "api_key": settings.fred_key,
                "file_type": "json",
                "sort_order": "desc",
                "limit": min(limit, 100),
            },
            allowed_host=_ALLOWED_HOST,
        )
    except Exception as e:
        logger.error(f"FRED fetch failed for {series_id}: {e}")
        return None

    raw_obs = data.get("observations", [])
    observations = [
        s for s in (_sanitise_observation(o) for o in raw_obs)
        if s is not None
    ]

    if not observations:
        return None

    latest = observations[0]
    previous = observations[1] if len(observations) > 1 else None

    change = None
    if previous and previous["value"] != 0:
        change = round(latest["value"] - previous["value"], 4)

    return {
        "series_id": series_id,
        "name": meta["name"],
        "category": meta["category"],
        "unit": meta["unit"],
        "latest_value": latest["value"],
        "latest_date": latest["date"],
        "change": change,
        "observations": observations[:limit],
        "source": "fred",
    }


async def fetch_all_macro_signals() -> List[Dict[str, Any]]:
    """Fetch all curated macro series in parallel."""
    import asyncio
    tasks = [fetch_series(sid, limit=5) for sid in MACRO_SERIES]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]
