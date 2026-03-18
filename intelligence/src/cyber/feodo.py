"""
Feodo Tracker (abuse.ch) — C2 botnet infrastructure feed.
Fully public. https://feodotracker.abuse.ch/
Tracks command-and-control servers used by banking trojans and ransomware.
"""

import csv
import io
import logging
from typing import Any, Dict, List

from src.shared.http import get_text

logger = logging.getLogger(__name__)

_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv"
_ALLOWED_HOST = "feodotracker.abuse.ch"

_VALID_MALWARE_FAMILIES = {
    "Dridex", "Emotet", "QakBot", "TrickBot", "BazarLoader",
    "IcedID", "AsyncRAT", "Cobalt Strike", "AgentTesla",
}]:
def _safe_ip(v: str) -> str:
    """Basic IP format validation — 4 octets, each 0-255."""
    parts = v.strip().split(".")
    if len(parts) != 4:
        return ""
    try:
        if all(0 <= int(p) <= 255 for p in parts):
            return v.strip()
    except ValueError:
        pass
    return ""
:
def _sanitise_row(row: Dict[str, str]) -> Dict[str, Any]:
    ip = _safe_ip(row.get("dst_ip", "") or row.get("ip_address", ""))
    if not ip:
        return {}
    port_raw = row.get("dst_port", "") or row.get("port", "")
    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            port = 0
    except (ValueError, TypeError):
        port = 0

    malware = row.get("malware", "") or row.get("malware_family", "")
    # Only include known families; don't pass arbitrary strings
    if malware not in _VALID_MALWARE_FAMILIES:
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
    """
    Fetch and parse the Feodo Tracker C2 IP blocklist.
    Returns sanitised list of C2 server records.
    """
    try:
        raw = await get_text(_URL)
    except Exception as e:
        logger.error(f"Feodo Tracker fetch failed: {e}")
        return []

    results = []
    reader = csv.DictReader(
        io.StringIO(raw),
        delimiter=",",
    )
    for row in reader:
        # Skip comment lines
        if not row or list(row.values())[0].startswith("#"):
            continue
        sanitised = _sanitise_row(row)
        if sanitised:
            results.append(sanitised)

        if len(results) >= 5000:  # cap memory
            break

    logger.info(f"Feodo Tracker: {len(results)} C2 records loaded")
    return results
