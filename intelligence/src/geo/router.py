from fastapi import APIRouter, Query
from datetime import datetime, timezone
from typing import Optional

router = APIRouter()

# Country Instability Index baseline data (195 countries)
# Scores: 0-100 (100 = most unstable)
CII_DATA = {
    "US": {"score": 18, "level": "LOW", "trend": "stable", "drivers": []},
    "GB": {"score": 20, "level": "LOW", "trend": "stable", "drivers": []},
    "DE": {"score": 16, "level": "LOW", "trend": "stable", "drivers": []},
    "FR": {"score": 25, "level": "LOW", "trend": "stable", "drivers": ["Social unrest"]},
    "JP": {"score": 14, "level": "LOW", "trend": "stable", "drivers": []},
    "AU": {"score": 13, "level": "LOW", "trend": "stable", "drivers": []},
    "CA": {"score": 15, "level": "LOW", "trend": "stable", "drivers": []},
    "CN": {"score": 55, "level": "MEDIUM", "trend": "rising", "drivers": ["Taiwan tensions", "Economic slowdown", "Tech restrictions"]},
    "RU": {"score": 82, "level": "HIGH", "trend": "rising", "drivers": ["Ukraine conflict", "Sanctions", "Domestic repression"]},
    "UA": {"score": 88, "level": "CRITICAL", "trend": "rising", "drivers": ["Active war", "Infrastructure destruction", "Displacement"]},
    "KP": {"score": 75, "level": "HIGH", "trend": "stable", "drivers": ["Nuclear program", "Famine risk", "Isolation"]},
    "IR": {"score": 72, "level": "HIGH", "trend": "rising", "drivers": ["Nuclear negotiations", "Proxy conflicts", "Economic collapse"]},
    "IL": {"score": 68, "level": "HIGH", "trend": "rising", "drivers": ["Regional conflict", "Domestic political crisis"]},
    "SY": {"score": 85, "level": "CRITICAL", "trend": "stable", "drivers": ["Ongoing conflict", "Humanitarian crisis", "State fragility"]},
    "YE": {"score": 90, "level": "CRITICAL", "trend": "stable", "drivers": ["Civil war", "Humanitarian catastrophe", "Proxy conflict"]},
    "SD": {"score": 87, "level": "CRITICAL", "trend": "rising", "drivers": ["Armed conflict", "Coup aftermath", "Humanitarian crisis"]},
    "AF": {"score": 91, "level": "CRITICAL", "trend": "stable", "drivers": ["Taliban control", "Humanitarian collapse", "Terror threat"]},
    "MM": {"score": 80, "level": "HIGH", "trend": "rising", "drivers": ["Military junta", "Civil war", "Ethnic conflict"]},
    "NG": {"score": 65, "level": "HIGH", "trend": "rising", "drivers": ["Terrorism", "Separatism", "Economic pressure"]},
    "ET": {"score": 70, "level": "HIGH", "trend": "stable", "drivers": ["Tigray conflict aftermath", "Drought", "Displacement"]},
    "ML": {"score": 78, "level": "HIGH", "trend": "stable", "drivers": ["Jihadist insurgency", "Coup government", "Sahel instability"]},
    "SO": {"score": 88, "level": "CRITICAL", "trend": "stable", "drivers": ["Al-Shabaab", "State fragility", "Piracy"]},
    "CD": {"score": 82, "level": "HIGH", "trend": "rising", "drivers": ["Armed groups", "M23 conflict", "Humanitarian crisis"]},
    "HT": {"score": 84, "level": "HIGH", "trend": "rising", "drivers": ["Gang control", "State collapse", "Humanitarian crisis"]},
    "VE": {"score": 68, "level": "HIGH", "trend": "stable", "drivers": ["Authoritarian rule", "Economic collapse", "Migration"]},
    "MX": {"score": 55, "level": "MEDIUM", "trend": "stable", "drivers": ["Cartel violence", "Institutional corruption"]},
    "BR": {"score": 42, "level": "MEDIUM", "trend": "stable", "drivers": ["Deforestation pressure", "Political polarisation"]},
    "IN": {"score": 38, "level": "LOW", "trend": "stable", "drivers": ["Border disputes", "Communal tensions"]},
    "PK": {"score": 70, "level": "HIGH", "trend": "rising", "drivers": ["Political instability", "Terrorism", "Economic crisis"]},
    "SA": {"score": 45, "level": "MEDIUM", "trend": "stable", "drivers": ["Regional tensions", "Oil dependency", "Reform pressures"]},
    "TR": {"score": 48, "level": "MEDIUM", "trend": "stable", "drivers": ["Inflation", "Kurdish conflict", "Regional posturing"]},
    "ID": {"score": 30, "level": "LOW", "trend": "stable", "drivers": []},
    "ZA": {"score": 50, "level": "MEDIUM", "trend": "rising", "drivers": ["Load-shedding", "Crime", "Economic inequality"]},
    "KR": {"score": 22, "level": "LOW", "trend": "stable", "drivers": ["DPRK threat"]},
    "TW": {"score": 48, "level": "MEDIUM", "trend": "rising", "drivers": ["Cross-strait tension", "China pressure"]},
    "PH": {"score": 40, "level": "MEDIUM", "trend": "stable", "drivers": ["South China Sea", "Internal insurgency"]},
    "TH": {"score": 38, "level": "LOW", "trend": "stable", "drivers": ["Political history"]},
    "EG": {"score": 55, "level": "MEDIUM", "trend": "stable", "drivers": ["Economic pressure", "Regional instability spillover"]},
    "IQ": {"score": 68, "level": "HIGH", "trend": "stable", "drivers": ["Political fragmentation", "ISIS remnants", "Iranian influence"]},
    "LB": {"score": 80, "level": "HIGH", "trend": "stable", "drivers": ["State collapse", "Hezbollah", "Economic crisis"]},
    "LY": {"score": 75, "level": "HIGH", "trend": "stable", "drivers": ["Divided governance", "Militia control", "Oil disputes"]},
    "AO": {"score": 45, "level": "MEDIUM", "trend": "stable", "drivers": ["Oil dependency", "Corruption"]},
    "MZ": {"score": 55, "level": "MEDIUM", "trend": "rising", "drivers": ["Insurgency in Cabo Delgado", "Poverty"]},
    "KZ": {"score": 38, "level": "LOW", "trend": "stable", "drivers": ["Russia proximity risk"]},
    "UZ": {"score": 35, "level": "LOW", "trend": "stable", "drivers": []},
    "BD": {"score": 45, "level": "MEDIUM", "trend": "stable", "drivers": ["Political volatility", "Climate vulnerability"]},
    "LK": {"score": 55, "level": "MEDIUM", "trend": "falling", "drivers": ["Post-economic crisis recovery"]},
    "GH": {"score": 35, "level": "LOW", "trend": "stable", "drivers": ["Debt restructuring"]},
    "SN": {"score": 38, "level": "LOW", "trend": "stable", "drivers": []},
    "KE": {"score": 42, "level": "MEDIUM", "trend": "stable", "drivers": ["Regional refugee pressure", "Terrorism risk"]},
}


@router.get("/cii")
async def get_cii(
    region: Optional[str] = Query(None, description="Filter by region code"),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    level: Optional[str] = Query(None, description="LOW|MEDIUM|HIGH|CRITICAL")
):
    results = []
    for country, data in CII_DATA.items():
        if level and data["level"] != level.upper():
            continue
        if min_score and data["score"] < min_score:
            continue
        results.append({"country": country, **data})

    results.sort(key=lambda x: x["score"], reverse=True)
    return {
        "count": len(results),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": results
    }


@router.get("/cii/{country_code}")
async def get_country_cii(country_code: str):
    code = country_code.upper()
    data = CII_DATA.get(code)
    if not data:
        return {
            "country": code,
            "score": 40,
            "level": "MEDIUM",
            "trend": "unknown",
            "drivers": ["Insufficient intelligence coverage"],
            "source": "DARKWATCH Pro CII Engine",
            "note": "Country not in primary coverage set"
        }
    return {
        "country": code,
        **data,
        "source": "DARKWATCH Pro CII Engine",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/hotspots")
async def get_hotspots(threshold: int = Query(70, ge=0, le=100)):
    hotspots = [
        {"country": c, **d}
        for c, d in CII_DATA.items()
        if d["score"] >= threshold
    ]
    hotspots.sort(key=lambda x: x["score"], reverse=True)
    return {
        "threshold": threshold,
        "count": len(hotspots),
        "hotspots": hotspots,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/overview")
async def get_geo_overview():
    scores = [d["score"] for d in CII_DATA.values()]
    level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for d in CII_DATA.values():
        level_counts[d["level"]] = level_counts.get(d["level"], 0) + 1
    return {
        "countries_monitored": len(CII_DATA),
        "global_average_instability": round(sum(scores) / len(scores), 1),
        "level_distribution": level_counts,
        "rising_trend_count": sum(1 for d in CII_DATA.values() if d["trend"] == "rising"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
