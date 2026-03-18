"""Economic signal analyser — synthesises FRED + Finnhub into risk assessments."""
import logging
from typing import Any, Dict, List

from src.economic.fred import fetch_all_macro_signals
from src.economic.finnhub import fetch_strategic_markets

logger = logging.getLogger(__name__)


def _yield_curve_signal(signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assess yield curve (10Y-2Y spread) inversion risk."""
    spread = next((s for s in signals if s.get("series_id") == "T10Y2Y"), None)
    if not spread:
        return {"signal": "yield_curve", "status": "unknown", "risk": "MEDIUM"}
    val = spread.get("value", 0)
    if val < -0.5:
        status, risk = "deeply_inverted", "CRITICAL"
    elif val < 0:
        status, risk = "inverted", "HIGH"
    elif val < 0.5:
        status, risk = "flat", "MEDIUM"
    else:
        status, risk = "normal", "LOW"
    return {"signal": "yield_curve", "spread": val, "status": status, "risk": risk}


def _volatility_signal(markets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assess market volatility (VIX) risk."""
    vix = next((m for m in markets if m.get("symbol") == "^VIX"), None)
    if not vix:
        return {"signal": "volatility", "status": "unknown", "risk": "MEDIUM"}
    val = vix.get("price", 0)
    if val > 35:
        status, risk = "extreme_fear", "CRITICAL"
    elif val > 25:
        status, risk = "elevated", "HIGH"
    elif val > 18:
        status, risk = "moderate", "MEDIUM"
    else:
        status, risk = "calm", "LOW"
    return {"signal": "volatility", "vix": val, "status": status, "risk": risk}


def _commodity_signal(markets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assess commodity stress (oil price) risk."""
    oil = next((m for m in markets if "WTI" in m.get("name", "")), None)
    if not oil:
        return {"signal": "commodity", "status": "unknown", "risk": "MEDIUM"}
    price = oil.get("price", 0)
    change = oil.get("change_pct", 0)
    if abs(change) > 5:
        risk = "HIGH"
    elif abs(change) > 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return {"signal": "commodity", "oil_price": price, "change_pct": change, "risk": risk}


async def build_economic_analysis() -> Dict[str, Any]:
    """Fetch and analyse all economic signals."""
    import asyncio
    macro, markets = await asyncio.gather(
        fetch_all_macro_signals(),
        fetch_strategic_markets(),
        return_exceptions=True,
    )
    macro = macro if isinstance(macro, list) else []
    markets = markets if isinstance(markets, list) else []

    signals = [
        _yield_curve_signal(macro),
        _volatility_signal(markets),
        _commodity_signal(markets),
    ]

    risk_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "unknown": 0}
    max_risk = max(signals, key=lambda s: risk_levels.get(s.get("risk", ""), 0))

    return {
        "macro_signals": macro,
        "market_data": markets,
        "risk_assessments": signals,
        "overall_risk": max_risk.get("risk", "MEDIUM"),
        "primary_concern": max_risk.get("signal", ""),
    }
