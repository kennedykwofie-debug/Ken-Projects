"""
AlienVault OTX (Open Threat Exchange) — public threat intelligence pulses.
Public feed. https://otx.alienvault.com/
Provides IOCs (indicators of compromise): IPs, domains, hashes, CVEs.
"""

import logging
from typing import Any, Dict, List

from src.shared.http import get_json

logger = logging.getLogger(__name__)

_BASE = "https://otx.alienvault.com/api/v1"
_ALLOWED_HOST = "otx.alienvault.com"

# Only fetch high-signal pulse categories
_SUBSCRIBED_TAGS = ["malware", "ransomware", "phishing", "apt", "c2", "cyberattack"]
_MAX_PULSES = 50
_MAX_IOCS_PER_PULSE = 20
:
def _sanitise_indicator(ind: Dict[str, Any]) -> Dict[str, Any]:
    ioc_type = str(ind.get("type", ""))
    # Whitelist safe IOC types
    allowed_types = {
        "IPv4", "IPv6", "domain", "hostname", "URL",
        "FileHash-MD5", "FileHash-SHA256", "CVE",
    }
    if ioc_type not in allowed_types:
        return {}

    indicator = str(ind.get("indicator", ""))[:500]
    if not indicator:
        return {}

    return {
        "type": ioc_type,
        "indicator": indicator,
        "description": str(ind.get("description", ""))[:200],
        "created": str(ind.get("created", ""))[:30],
        "source": "otx",
    }


def _sanitise_pulse(pulse: Dict[str, Any]) -> Dict[str, Any]:
    name = str(pulse.get("name", ""))[:200]
    tags = [str(t)[:50] for t in (pulse.get("tags") or [])[:10]]
    tlp = str(pulse.get("tlp", "white")).lower()

    raw_indicators = pulse.get("indicators", []) or []
    indicators = []
    for ind in raw_indicators[:_MAX_IOCS_PER_PULSE]:
        sanitised = _sanitise_indicator(ind)
        if sanitised:
            indicators.append(sanitised)

    return {
        "id": str(pulse.get("id", ""))[:50],
        "name": name,
        "tags": tags,
        "tlp": tlp if tlp in {"white", "green", "amber", "red"} else "white",
        "created": str(pulse.get("created", ""))[:30],
        "modified": str(pulse.get("modified", ""))[:30],
        "indicator_count": len(indicators),
        "indicators": indicators,
        "target_countries": [str(c)[:3] for c in (pulse.get("targeted_countries") or [])[:20]],
        "adversary": str(pulse.get("adversary", ""))[:100],
        "malware_families": [str(m)[:50] for m in (pulse.get("malware_families") or [])[:10]],
        "source": "otx",
        "confidence": "medium",
    }


async def fetch_threat_pulses(days_back: int = 7) -> List[Dict[str, Any]]:
    """
    Fetch recent public OTX threat intelligence pulses.
    Returns sanitised pulse list with IOCs.
    """
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(tz=timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    try:
        data = await get_json(
            f"{_BASE}/pulses/subscribed",
            params={
                "modified_since": since,
                "limit": _MAX_PULSES,
                "page": 1,
            },
            allowed_host=_ALLOWED_HOST,
        )
    except Exception as e:
        logger.error(f"OTX fetch failed: {e}")
        return []

    pulses = data.get("results", [])
    if not isinstance(pulses, list):
        return []

    sanitised = [_sanitise_pulse(p) for p in pulses[:_MAX_PULSES]]
    logger.info(f"OTX: {len(sanitised)} pulses fetched")
    return sanitised
