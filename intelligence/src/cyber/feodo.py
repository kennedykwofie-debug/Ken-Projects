"""Feodo Tracker (abuse.ch) C2 botnet feed."""
import csv
import io
import logging
from typing import Any, Dict, List

from src.shared.http import get

logger = logging.getLogger(__name__)

_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

_VALID_FAMILIES = {
    "Dridex", "Emotet", "QakBot", "TrickBot", "BazarLoader",
    "IcedID", "AsyncRAT", "CobaltStrike", "AgentTesla",
}


def _safe_ip(v: str) -> str:
    parts = v.strip().split(".")
    if len(parts) != 4:
        return ""
    try:
        if all(0 <= int(p) <= 255 for p in parts):
            return v.strip()
    except ValueError:
        pass
    return ""


def _sanitise_row(row: Dict[str, str]) -> Dict[str, Any]:
    ip = _safe_ip(row.get("dst_ip", "") or row.get("ip_address", ""))
    if not ip:
        return {}
    try:
        port = int(row.get("dst_port", "") or row.get("port", "") or 0)
        if not (1 <= port <= 65535):
            port = 0
    except (ValueError, TypeError):
        port = 0
    malware = row.get("malware", "") or row.get("malware_family", "")
    if malware not in _VALID_FAMILIES:
        malware = "Unknown"
    return {
        "ip": ip,
        "port": port,
        "malware_family": malware,
        "first_seen": str(row.get("first_seen", ""))[:20],
        "last_seen": str(row.get("last_seen", ""))[:20],
        "threat_type": "c2_server",
        "source": "feodo_tracker",
        "confidence": "high",
    }


async def fetch_c2_blocklist() -> List[Dict[str, Any]]:
    try:
        resp = await get(_URL)
        if isinstance(resp, str):
            raw = resp
        else:
            return []
    except Exception as e:
        logger.error(f"Feodo fetch failed: {e}")
        return []
    results = []
    for row in csv.DictReader(io.StringIO(raw)):
        if not row or list(row.values())[0].startswith("#"):
            continue
        s = _sanitise_row(row)
        if s:
            results.append(s)
        if len(results) >= 5000:
            break
    logger.info(f"Feodo: {len(results)} C2 records")
    return results
