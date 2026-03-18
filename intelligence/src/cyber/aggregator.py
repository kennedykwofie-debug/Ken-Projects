"""Cyber threat aggregator. Merges Feodo, URLhaus, OTX feeds into unified threat picture."""
import asyncio
import logging
from typing import Any, Dict, List

from src.cyber.feodo import fetch_c2_blocklist
from src.cyber.urlhaus import fetch_malicious_urls
from src.cyber.otx import fetch_threat_pulses

logger = logging.getLogger(__name__)


def _get_ip(record: Dict[str, Any]) -> str:
    """Get IP from record regardless of field name used."""
    return record.get("ip_address") or record.get("ip") or ""


def _deduplicate_c2(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    result = []
    for r in records:
        ip = _get_ip(r)
        if ip and ip not in seen:
            seen.add(ip)
            result.append(r)
        elif not ip:
            result.append(r)
    return result


async def build_threat_summary() -> Dict[str, Any]:
    """Aggregate all cyber threat feeds into unified summary."""
    feodo, urlhaus, otx = await asyncio.gather(
        fetch_c2_blocklist(),
        fetch_malicious_urls(),
        fetch_threat_pulses(),
        return_exceptions=True,
    )

    c2_records: List[Dict[str, Any]] = feodo if isinstance(feodo, list) else []
    malware_urls: List[Dict[str, Any]] = urlhaus if isinstance(urlhaus, list) else []
    pulses: List[Dict[str, Any]] = otx if isinstance(otx, list) else []

    logger.info(f"Cyber feeds: feodo={len(c2_records)} urlhaus={len(malware_urls)} otx={len(pulses)}")

    # Normalise C2 records - ensure both ip and ip_address fields exist
    normalised_c2 = []
    for r in c2_records:
        ip = _get_ip(r)
        if not ip:
            continue
        normalised_c2.append({
            **r,
            "ip": ip,
            "ip_address": ip,
            "malware": r.get("malware") or r.get("malware_family") or "Unknown",
            "malware_family": r.get("malware_family") or r.get("malware") or "Unknown",
            "threat_score": 70,
            "severity": "HIGH",
        })

    normalised_c2 = _deduplicate_c2(normalised_c2)

    # Normalise URLhaus records
    normalised_urls = []
    for r in malware_urls:
        normalised_urls.append({
            **r,
            "url": r.get("url", ""),
            "domain": r.get("domain", ""),
            "threat": r.get("threat", "malware_download"),
        })

    critical_count = sum(1 for r in normalised_c2 if r.get("severity") == "CRITICAL")
    high_count = sum(1 for r in normalised_c2 if r.get("severity") == "HIGH")
    malware_families = list({r.get("malware_family", "") for r in normalised_c2 if r.get("malware_family") and r.get("malware_family") != "Unknown"})

    return {
        "c2_servers": normalised_c2[:200],
        "malware_domains": normalised_urls[:200],
        "threat_pulses": pulses[:50],
        "summary": {
            "total_c2_servers": len(normalised_c2),
            "critical": critical_count,
            "high": high_count,
            "malware_families": malware_families[:20],
            "active_pulse_count": len(pulses),
            "malware_domain_count": len(normalised_urls),
        },
    }
