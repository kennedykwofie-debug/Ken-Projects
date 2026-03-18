"""Feodo Tracker (abuse.ch) C2 botnet feed."""
import csv
import io
import logging
from typing import Any, Dict, List

from src.shared.http import get_text

logger = logging.getLogger(__name__)

_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


def _sanitise_row(row: Dict[str, str]) -> Dict[str, Any]:
    # Feodo CSV columns: first_seen, dst_ip, dst_port, c2_status, last_online, malware
    ip = row.get("dst_ip", "").strip() or row.get("ip_address", "").strip()
    if not ip or ip.startswith("#"):
        return {}
    # Validate IP
    parts = ip.split(".")
    if len(parts) != 4:
        return {}
    try:
        if not all(0 <= int(p) <= 255 for p in parts):
            return {}
    except ValueError:
        return {}
    try:
        port = int(row.get("dst_port", "") or row.get("port", "") or 0)
        if not (1 <= port <= 65535):
            port = 0
    except (ValueError, TypeError):
        port = 0
    malware = (row.get("malware", "") or row.get("malware_family", "") or "Unknown").strip()
    if not malware:
        malware = "Unknown"
    return {
        "ip_address": ip,
        "port": port,
        "malware": malware,
        "malware_family": malware,
        "first_seen": str(row.get("first_seen", ""))[:20],
        "last_seen": str(row.get("last_online", "") or row.get("last_seen", ""))[:20],
        "threat_type": "c2_server",
        "source": "feodo_tracker",
        "confidence": "high",
    }


async def fetch_c2_blocklist() -> List[Dict[str, Any]]:
    try:
        raw = await get_text(_URL)
    except Exception as e:
        logger.error(f"Feodo fetch failed: {e}")
        return []
    results = []
    lines = [l for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")]
    cleaned = "\n".join(lines)
    try:
        for row in csv.DictReader(io.StringIO(cleaned)):
            s = _sanitise_row(row)
            if s:
                results.append(s)
            if len(results) >= 500:
                break
    except Exception as e:
        logger.error(f"Feodo CSV parse failed: {e}")
        return []
    logger.info(f"Feodo: {len(results)} C2 records")
    return results
