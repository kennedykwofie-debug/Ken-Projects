"""URLhaus (abuse.ch) malicious URL feed."""
import logging
from typing import Any, Dict, List

from src.shared.http import get

logger = logging.getLogger(__name__)

_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


async def fetch_malicious_urls() -> List[Dict[str, Any]]:
    """Fetch recent malicious URLs from URLhaus API."""
    try:
        data = await get(_URL)
        urls = data.get("urls", [])[:500]
    except Exception as e:
        logger.error(f"URLhaus fetch failed: {e}")
        return []

    results = []
    for entry in urls:
        url = str(entry.get("url", ""))[:500]
        if not url.startswith(("http://", "https://")):
            continue
        tags = entry.get("tags") or []
        results.append({
            "url": url,
            "threat": str(entry.get("threat", ""))[:50],
            "tags": [str(t)[:30] for t in tags[:5]],
            "date_added": str(entry.get("date_added", ""))[:20],
            "source": "urlhaus",
            "confidence": "high",
        })

    logger.info(f"URLhaus: {len(results)} malicious URLs loaded")
    return results
