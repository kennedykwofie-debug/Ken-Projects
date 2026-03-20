"""VulnCheck active exploitation intelligence."""
import asyncio
import logging
from typing import Any, Dict, List
import httpx
from src.shared.config import settings

logger = logging.getLogger(__name__)
_BASE = "https://api.vulncheck.com/v3"

async def _get(path: str, params: Dict = None) -> Any:
    if not settings.vulncheck_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(f"{_BASE}{path}",
                headers={"Authorization": f"Bearer {settings.vulncheck_key}"},
                params=params or {})
            if r.status_code != 200:
                logger.warning(f"VulnCheck {path}: {r.status_code} {r.text[:100]}")
                return None
            return r.json()
    except Exception as e:
        logger.error(f"VulnCheck {path}: {e!r}")
        return None

async def get_exploited_cves(limit: int = 20) -> List[Dict[str, Any]]:
    """Get CVEs actively exploited in the wild right now."""
    data = await _get("/index/initial-access", {"limit": str(limit)})
    if not data:
        return []
    results = []
    for item in data.get("data", [])[:limit]:
        cve_id = item.get("cve", [{}])[0].get("id", "") if item.get("cve") else item.get("id", "")
        results.append({
            "id": cve_id,
            "name": item.get("name", ""),
            "description": item.get("description", "")[:200],
            "epss": item.get("epss", {}).get("score") if isinstance(item.get("epss"), dict) else None,
            "ransomware": item.get("ransomware_campaign", False),
            "exploit_available": True,
            "source": "vulncheck",
        })
    return results

async def enrich_cve(cve_id: str) -> Dict[str, Any]:
    """Enrich a specific CVE with exploitation data."""
    data = await _get(f"/index/nist-nvd2", {"cve": cve_id})
    if not data or not data.get("data"):
        return {}
    item = data["data"][0]
    return {
        "id": cve_id,
        "cvss": item.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore") if item.get("metrics") else None,
        "exploit_available": bool(item.get("vulncheck_xdb", [])),
        "poc_count": len(item.get("vulncheck_xdb", [])),
        "ransomware": item.get("vulncheck_reported_exploitation", [{}])[0].get("ransomware", False) if item.get("vulncheck_reported_exploitation") else False,
        "source": "vulncheck",
    }
