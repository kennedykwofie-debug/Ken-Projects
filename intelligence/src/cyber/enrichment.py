"""IP enrichment via AbuseIPDB and Shodan."""
import asyncio
import logging
from typing import Any, Dict, List, Optional

from src.shared.config import settings
from src.shared.http import get

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_SHODAN_URL = "https://api.shodan.io/shodan/host"


def _safe_ip(ip: str) -> str:
    """Validate IPv4 format."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return ""
    try:
        if all(0 <= int(p) <= 255 for p in parts):
            return ip.strip()
    except ValueError:
        pass
    return ""


async def enrich_ip(ip: str) -> Dict[str, Any]:
    """Enrich a single IP with AbuseIPDB and Shodan data."""
    safe = _safe_ip(ip)
    if not safe:
        return {}

    result: Dict[str, Any] = {"ip": safe, "abuseipdb": {}, "shodan": {}, "threat_score": 0}

    # AbuseIPDB
    if settings.abuseipdb_key:
        try:
            data = await get(
                _ABUSEIPDB_URL,
                headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": safe, "maxAgeInDays": "90"},
            )
            d = data.get("data", {})
            result["abuseipdb"] = {
                "abuse_score": int(d.get("abuseConfidenceScore", 0)),
                "country_code": str(d.get("countryCode", ""))[:2],
                "isp": str(d.get("isp", ""))[:100],
                "is_tor": bool(d.get("isTor", False)),
                "total_reports": int(d.get("totalReports", 0)),
            }
        except Exception as e:
            logger.debug(f"AbuseIPDB error for {safe}: {e}")

    # Shodan
    if settings.shodan_key:
        try:
            data = await get(
                f"{_SHODAN_URL}/{safe}",
                params={"key": settings.shodan_key},
            )
            result["shodan"] = {
                "ports": [int(p) for p in data.get("ports", [])[:20]],
                "cves": list(data.get("vulns", {}).keys())[:10],
                "org": str(data.get("org", ""))[:100],
                "hostnames": [str(h)[:100] for h in data.get("hostnames", [])[:5]],
            }
        except Exception as e:
            logger.debug(f"Shodan error for {safe}: {e}")

    # Compute composite threat score
    abuse = result["abuseipdb"].get("abuse_score", 0)
    cve_count = len(result["shodan"].get("cves", []))
    open_ports = len(result["shodan"].get("ports", []))
    score = min(100, int(abuse * 0.6 + cve_count * 5 + open_ports * 0.5))
    result["threat_score"] = score

    return result


async def batch_enrich_ips(
    ips: List[str], max_concurrent: int = 5
) -> List[Dict[str, Any]]:
    """Enrich multiple IPs with concurrency control."""
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _with_sem(ip: str) -> Dict[str, Any]:
        async with semaphore:
            return await enrich_ip(ip)

    results = await asyncio.gather(
        *[_with_sem(ip) for ip in ips[:100]], return_exceptions=True
    )
    return [r for r in results if isinstance(r, dict) and r.get("ip")]
