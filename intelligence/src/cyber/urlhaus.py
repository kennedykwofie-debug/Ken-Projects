"""
URLhaus (abuse.ch) — malicious URL database.
Fully public. https://urlhaus.abuse.ch/
Tracks URLs distributing malware payloads.
"""

import csv
import io
import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

from src.shared.http import get_text

logger = logging.getLogger(__name__)

_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
_ALLOWED_HOST = "urlhaus.abuse.ch"

_VALID_TAGS = {
    "exe", "doc", "xls", "zip", "rar", "js", "vbs", "ps1",
    "pdf", "iso", "img", "dll", "bat", "cmd", "hta", "jar",
}]:_VALID_STATUSES = {"online", "offline", "unknown"}]:
def _safe_url_domain(raw_url: str) -> str:
    """Extract domain only — never store full malicious URLs in our data."""
    try:
        parsed = urlparse(raw_url.strip())
        return (parsed.hostname or "")[:200]
    except Exception:
        return ""
:
def _sanitise_row(row: Dict[str, str]) -> Dict[str, Any]:
    domain = _safe_url_domain(row.get("url", ""))
    if not domain:
        return {}

    status = row.get("url_status", "unknown").lower()
    if status not in _VALID_STATUSES:
        status = "unknown"

    tags_raw = row.get("tags", "") or ""
    tags = [t.strip().lower() for t in tags_raw.split(",") if t.strip().lower() in _VALID_TAGS]

    threat = str(row.get("threat", "malware_download"))[:50]
    # Sanitise threat field — only allow alphanumeric + underscore
    threat = "".join(c for c in threat if c.isalnum() or c == "_")

    return {
        "domain": domain,
        "status": status,
        "threat": threat,
        "tags": tags[:10],
        "date_added": str(row.get("dateadded", ""))[:20],
        "threat_type": "malware_distribution",
        "source": "urlhaus",
        "confidence": "high" if status == "online" else "medium",
    }


async def fetch_malicious_urls() -> List[Dict[str, Any]]:
    """
    Fetch and parse the URLhaus recent malicious URL list.
    Stores domain only — not full malicious URLs.
    """
    try:
        raw = await get_text(_URL)
    except Exception as e:
        logger.error(f"URLhaus fetch failed: {e}")
        return []

    results = []
    lines = [l for l in raw.splitlines() if not l.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))

    for row in reader:
        sanitised = _sanitise_row(row)
        if sanitised:
            results.append(sanitised)
        if len(results) >= 5000:
            break

    logger.info(f"URLhaus: {len(results)} malicious domain records loaded")
    return results
