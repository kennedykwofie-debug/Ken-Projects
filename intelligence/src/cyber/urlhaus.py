"""URLhaus (abuse.ch) malicious URL feed - uses free CSV download."""
import csv
import io
import logging
from typing import Any, Dict, List

from src.shared.http import get_text

logger = logging.getLogger(__name__)

# Free CSV download - no auth required
_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def _parse_row(row: Dict[str, str]) -> Dict[str, Any]:
    url = row.get("url", "").strip()
    if not url or not url.startswith("http"):
        return {}
    threat = row.get("threat", "").strip() or "malware_download"
    tags_raw = row.get("tags", "") or ""
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    return {
        "url": url[:500],
        "domain": row.get("host", "").strip()[:253],
        "threat": threat,
        "tags": tags,
        "date_added": str(row.get("dateadded", ""))[:20],
        "source": "urlhaus",
    }


async def fetch_malicious_urls() -> List[Dict[str, Any]]:
    try:
        raw = await get_text(_URL)
    except Exception as e:
        logger.error(f"URLhaus fetch failed: {e}")
        return []
    results = []
    # Strip comment lines
    lines = [l for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")]
    cleaned = "\n".join(lines)
    try:
        for row in csv.DictReader(io.StringIO(cleaned)):
            parsed = _parse_row(row)
            if parsed:
                results.append(parsed)
            if len(results) >= 200:
                break
    except Exception as e:
        logger.error(f"URLhaus CSV parse failed: {e}")
        return []
    logger.info(f"URLhaus: {len(results)} malicious URLs")
    return results
