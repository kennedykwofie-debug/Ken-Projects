"""
Economic macro signal analyser.
Combines FRED and Finnhub data into actionable risk signals.
Identifies: yield curve inversions, commodity stress, currency crises,
financial stress spikes — all with direct geopolitical relevance.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class MacroSignal:
    signal_id: str
    name: str
    category: str
    value: float
    unit: str
    interpretation: str          # BULLISH | BEARISH | NEUTRAL | STRESS | CRISIS
    severity: str                # LOW | MEDIUM | HIGH | CRITICAL
    description: str
    source: str
:
def _classify_yield_spread(spread: float) -> tuple[str, str]:
    """10Y-2Y spread: negative = inverted = recession warning."""
    if spread <= -0.5:
        return "CRISIS", "CRITICAL"
    if spread <= 0:
        return "STRESS", "HIGH"
    if spread <= 0.5:
        return "BEARISH", "MEDIUM"
    return "NEUTRAL", "LOW"


def _classify_financial_stress(fsi: float) -> tuple[str, str]:
    """St. Louis FSI: >1 = high stress, >2 = crisis territory."""
    if fsi >= 2.0:
        return "CRISIS", "CRITICAL"
    if fsi >= 1.0:
        return "STRESS", "HIGH"
    if fsi >= 0.5:
        return "BEARISH", "MEDIUM"
    return "NEUTRAL", "LOW"


def _classify_high_yield_spread(hy: float) -> tuple[str, str]:
    """High-yield spread: >800bps = crisis, >500bps = stress."""
    if hy >= 8.0:
        return "CRISIS", "CRITICAL"
    if hy >= 5.0:
        return "STRESS", "HIGH"
    if hy >= 3.5:
        return "BEARISH", "MEDIUM"
    return "NEUTRAL", "LOW"


def _classify_oil(price: float, change_pct: float) -> tuple[str, str]:
    """Oil price + momentum as geopolitical stress indicator."""
    if price >= 120 or change_pct >= 10:
        return "STRESS", "HIGH"
    if price >= 90 or change_pct >= 5:
        return "BEARISH", "MEDIUM"
    if price <= 50:
        return "BEARISH", "MEDIUM"  # demand destruction also a risk signal
    return "NEUTRAL", "LOW"


def _commodity_stress_index(commodities: List[Dict[str, Any]]) -> float:
    """
    Compute a 0-100 commodity stress index from price movements.
    Weights: energy 40%, metals 35%, agriculture 25%.
    Large moves in strategic commodities = supply disruption signal.
    """
    energy_symbols = {"CL=F", "BZ=F", "NG=F"}
    metal_symbols = {"GC=F", "SI=F", "HG=F", "PL=F", "PA=F"}
    agri_symbols = {"W=F", "C=F", "S=F"}

    def _score(symbols: set, weight: float) -> float:
        relevant = [c for c in commodities if c.get("symbol") in symbols]
        if not relevant:
            return 0.0
        avg_abs_change = sum(abs(c.get("change_pct", 0)) for c in relevant) / len(relevant)
        # Scale: 1% move = 10 stress points, capped at 100
        return min(100, avg_abs_change * 10) * weight

    return (
        _score(energy_symbols, 0.40)
        + _score(metal_symbols, 0.35)
        + _score(agri_symbols, 0.25)
    )


def analyse_macro_signals(
    fred_series: List[Dict[str, Any]],
    market_data: Dict[str, List[Dict[str, Any]]],
) -> List[MacroSignal]:
    """
    Analyse raw macro data and return list of named risk signals.
    """
    signals: List[MacroSignal] = []
    fred_by_id = {s["series_id"]: s for s in fred_series if "series_id" in s}

    # ── Yield curve ───────────────────────────────────────────────────────────
    spread = fred_by_id.get("T10Y2Y")
    if spread:
        v = spread["latest_value"]
        interp, sev = _classify_yield_spread(v)
        signals.append(MacroSignal(
            signal_id="yield_curve_spread",
            name="Yield Curve (10Y-2Y)",
            category="yield_curve",
            value=v,
            unit="percent",
            interpretation=interp,
            severity=sev,
            description=(
                f"10Y-2Y spread at {v:+.2f}%. "
                + ("Inverted — historical recession precursor." if v < 0
                   else "Positive — no immediate inversion signal.")
            ),
            source="fred",
        ))

    # ── Financial stress ──────────────────────────────────────────────────────
    fsi = fred_by_id.get("STLFSI4")
    if fsi:
        v = fsi["latest_value"]
        interp, sev = _classify_financial_stress(v)
        signals.append(MacroSignal(
            signal_id="financial_stress_index",
            name="St. Louis Financial Stress Index",
            category="stress",
            value=v,
            unit="index",
            interpretation=interp,
            severity=sev,
            description=(
                f"FSI at {v:.3f}. "
                + ("Above 1.0 — elevated financial market stress." if v >= 1.0
                   else "Below 1.0 — below-average financial stress.")
            ),
            source="fred",
        ))

    # ── High yield spread ─────────────────────────────────────────────────────
    hy = fred_by_id.get("BAMLH0A0HYM2")
    if hy:
        v = hy["latest_value"]
        interp, sev = _classify_high_yield_spread(v)
        signals.append(MacroSignal(
            signal_id="high_yield_spread",
            name="High-Yield Credit Spread",
            category="credit",
            value=v,
            unit="percent",
            interpretation=interp,
            severity=sev,
            description=(
                f"HY spread at {v:.2f}%. "
                + ("Crisis-level credit stress." if v >= 8.0
                   else "Elevated credit risk." if v >= 5.0
                   else "Normal credit conditions.")
            ),
            source="fred",
        ))

    # ── Oil price ─────────────────────────────────────────────────────────────
    commodities = market_data.get("commodities", [])
    brent = next((c for c in commodities if c.get("symbol") == "BZ=F"), None)
    if brent:
        v = brent["price"]
        chg = brent.get("change_pct", 0)
        interp, sev = _classify_oil(v, chg)
        signals.append(MacroSignal(
            signal_id="brent_crude",
            name="Brent Crude Oil",
            category="energy",
            value=v,
            unit="usd_per_barrel",
            interpretation=interp,
            severity=sev,
            description=f"Brent at ${v:.2f}/bbl ({chg:+.2f}% today). Energy supply risk indicator.",
            source="finnhub",
        ))

    # ── Commodity stress composite ────────────────────────────────────────────
    stress_idx = _commodity_stress_index(commodities)
    sev = "CRITICAL" if stress_idx >= 70 else "HIGH" if stress_idx >= 40 else "MEDIUM" if stress_idx >= 20 else "LOW"
    signals.append(MacroSignal(
        signal_id="commodity_stress_index",
        name="Commodity Stress Index",
        category="commodities",
        value=round(stress_idx, 1),
        unit="index_0_100",
        interpretation="STRESS" if stress_idx >= 40 else "NEUTRAL",
        severity=sev,
        description=(
            f"Composite commodity volatility index: {stress_idx:.1f}/100. "
            "Measures price movement magnitude across energy, metals, agriculture."
        ),
        source="computed",
    ))

    # Sort by severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    signals.sort(key=lambda s: order.get(s.severity, 99))
    return signals


def signals_to_dict(signals: List[MacroSignal]) -> List[Dict[str, Any]]:
    return [
        {
            "signal_id": s.signal_id,
            "name": s.name,
            "category": s.category,
            "value": s.value,
            "unit": s.unit,
            "interpretation": s.interpretation,
            "severity": s.severity,
            "description": s.description,
            "source": s.source,
        }
        for s in signals
    ]
