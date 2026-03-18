"""AlienVault OTX threat intelligence feed."""
import logging
from typing import Any, Dict, List

from src.shared.http import get

logger = logging.getLogger(__name__)

_BASE = "https://otx.alienvault.com/api/v1"


async def fetch_threat_pulses(api_key: str = "", limit: int = 20) -> List[Dict[str, Any]]:
    """Fetch recent threat pulses from OTX."""
    if not api_key:
        return []
    try:
        data = await get(
            f"{_BASE}/pulses/subscribed?limit={limit}",
            headers={"X-OTX-API-KEY": api_key},
        )
        pulses = data.get("results", [])[:limit]
    except Exception as e:
        logger.error(f"OTX fetch failed: {e}")
        return []
    results = []
    for p in pulses:
        results.append({
            "id": str(p.get("id", ""))[:50],
            "name": str(p.get("name", ""))[:100],
            "threat_type": str(p.get("adversary", "Unknown"))[:50],
            "tags": [str(t)[:30] for t in p.get("tags", [])[:10]],
            "ioc_count": int(p.get("indicators_count", 0)),
            "source": "alienvault_otx",
        })
    logger.info(f"OTX: {len(results)} pulses")
    return results
