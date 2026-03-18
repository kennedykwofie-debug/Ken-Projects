"""
Cyber threat aggregator.
Merges Feodo, URLhaus, OTX feeds into a unified DARKWATCH threat picture.
Enriches high-confidence C2 IPs with AbuseIPDB + Shodan.
"""

import asyncio
import logging
from typing import Any, Dict, List

from src.shared.config import settings
from src.cyber.feodo import fetch_c2_blocklist
from src.cyber.urlhaus import fetch_malicious_urls
from src.cyber.otx import fetch_threat_pulses
from src.cyber.enrichment import batch_enrich_ips

logger = logging.getLogger(__name__)

# Threat severity thresholds
_HIGH_ABUSE_SCORE = 75
_MEDIUM_ABUSE_SCORE = 40


def _deduplicate_by_ip(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate threat records by IP address."""
    seen: set = set()
    result = []
    for r in records:
        ip = r.get("ip", "")
        if ip and ip not in seen:
            seen.add(ip)
            result.append(r)
        elif not ip:
            result.append(r)  # non-IP records (domains, hashes) pass through) -> Dict[str, Any]:
def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= _HIGH_ABUSE_SCORE:
        return "HIGH"
    if score >= _MEDIUM_ABUSE_SCORE:
        return "MEDIUM"
    return "LOW"


async def build_threat_summary() -> Dict[str, Any]:
    """
    Aggregate all cyber threat feeds and return unified summary.
    Enriches top C2 IPs with AbuseIPDB + Shodan.
    """
    feodo_task = fetch_c2_blocklist()
    urlhaus_task = fetch_malicious_urls()
    otx_task = fetch_threat_pulses(days_back=7)

    feodo, urlhaus, otx = await asyncio.gather(
        feodo_task, urlhaus_task, otx_task,
        return_exceptions=True,
    )

    c2_records: List[Dict[str, Any]] = feodo if isinstance(feodo, list) else []
    malware_urls: List[Dict[str, Any]] = urlhaus if isinstance(urlhaus, list) else []
    pulses: List[Dict[str, Any]] = otx if isinstance(otx, list) else []

    # Extract IPs from C2 records for enrichment (top 50 only to stay within rate limits)
    c2_ips = [r["ip"] for r in c2_records if r.get("ip")][:50]

    enriched_ips: List[Dict[str, Any]] = []
    if c2_ips:
        try:
            enriched_ips = await batch_enrich_ips(c2_ips, max_concurrent=5)
        except Exception as e:
            logger.error(f"IP enrichment failed: {e}")

    # Build enrichment lookup
    enrichment_map: Dict[str, Dict[str, Any]] = {
        r["ip"]: r for r in enriched_ips if r.get("ip")
    }

    # Merge C2 records with enrichment
    enriched_c2 = []
    for record in c2_records:
        ip = record.get("ip", "")
        enrichment = enrichment_map.get(ip, {})
        abuse_score = enrichment.get("abuseipdb", {}).get("abuse_score", 0)
        threat_score = enrichment.get("threat_score", 50)  # default medium if not enriched

        enriched_c2.append({
            **record,
            "threat_score": threat_score,
            "severity": _severity_from_score(threat_score),
            "country_code": enrichment.get("abuseipdb", {}).get("country_code", ""),
            "isp": enrichment.get("abuseipdb", {}).get("isp", ""),
            "open_ports": enrichment.get("shodan", {}).get("ports", []),
            "cves": enrichment.get("shodan", {}).get("cves", []),
            "is_tor": enrichment.get("abuseipdb", {}).get("is_tor", False),
            "abuse_score": abuse_score,
        })

    # Deduplicate
    enriched_c2 = _deduplicate_by_ip(enriched_c2)

    # Sort by threat score descending
    enriched_c2.sort(key=lambda r: r.get("threat_score", 0), reverse=True)

    # Compute summary statistics
    critical_count = sum(1 for r in enriched_c2 if r.get("severity") == "CRITICAL")
    high_count = sum(1 for r in enriched_c2 if r.get("severity") == "HIGH")
    malware_families = list({r.get("malware_family", "") for r in enriched_c2 if r.get("malware_family")})

    # Extract top IOCs from OTX pulses
    top_iocs = []
    for pulse in pulses[:10]:
        for ioc in pulse.get("indicators", [])[:5]:
            top_iocs.append({
                **ioc,
                "pulse_name": pulse.get("name", ""),
                "adversary": pulse.get("adversary", ""),
            })

    return {
        "c2_servers": enriched_c2[:500],
        "malware_domains": malware_urls[:500],
        "threat_pulses": pulses[:50],
        "top_iocs": top_iocs[:100],
        "summary": {
            "total_c2_servers": len(enriched_c2),
            "critical": critical_count,
            "high": high_count,
            "malware_families": malware_families[:20],
            "active_pulse_count": len(pulses),
            "malware_domain_count": len(malware_urls),
        },
    }
