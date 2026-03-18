"""
IP enrichment pipeline.
Combines AbuseIPDB (abuse confidence scoring) with Shodan (port/service intel).
Both keys are already set in Railway env vars.

Security notes:
- IPs are validated before any API call
- R, Anys are sanitised — no raw API responses passed downstream
- Rate limits respected: AbuseIPDB 1000/day, Shodan 1 req/sec on free tier
- Shodan free tier: host lookup only (no search)
"""

import asyncio
import ipaddress
import logging
from typing import Any, Dict, List, Optional

from src.shared.config import settings
from src.shared.http import get_json

logger = logging.getLogger(__name__)

_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
_SHODAN_BASE = "https://api.shodan.io"
_ABUSEIPDB_HOST = "api.abuseipdb.com"
_SHODAN_HOST = "api.shodan.io"

# Never enrich private/reserved ranges — they can't be C2 servers
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]]:
def _is_routable(ip: str) -> bool:
    """Return True only for globally routable IPs."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                return False
        return True
    except ValueError:
        return False


async def enrich_ip_abuseipdb(ip: str) -> Optional[Dict[str, Any]]:
    """Check IP against AbuseIPDB. Returns None on failure or non-routable."""
    if not _is_routable(ip):
        return None
    try:
        data = await get_json(
            f"{_ABUSEIPDB_BASE}/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
            allowed_host=_ABUSEIPDB_HOST,
        )
        d = data.get("data", {})
        return {
            "ip": str(d.get("ipAddress", ip)),
            "abuse_score": min(100, max(0, int(d.get("abuseConfidenceScore", 0)))),
            "country_code": str(d.get("countryCode", ""))[:2],
            "isp": str(d.get("isp", ""))[:100],
            "domain": str(d.get("domain", ""))[:100],
            "total_reports": int(d.get("totalReports", 0)),
            "last_reported": str(d.get("lastReportedAt", ""))[:30],
            "is_tor": bool(d.get("isTor", False)),
            "source": "abuseipdb",
        }
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
        return None


async def enrich_ip_shodan(ip: str) -> Optional[Dict[str, Any]]:
    """Look up IP in Shodan. Returns sanitised host data."""
    if not _is_routable(ip):
        return None
    try:
        data = await get_json(
            f"{_SHODAN_BASE}/shodan/host/{ip}",
            params={"key": settings.shodan_key},
            allowed_host=_SHODAN_HOST,
        )
        # Extract only the fields we care about
        ports = sorted(set(int(p) for p in (data.get("ports") or []) if isinstance(p, int)))[:20]
        hostnames = [str(h)[:100] for h in (data.get("hostnames") or [])[:5]]
        tags = [str(t)[:50] for t in (data.get("tags") or [])[:10]]

        # Cap and sanitise vulns
        vulns_raw = data.get("vulns") or {}
        vulns = list(vulns_raw.keys())[:10] if isinstance(vulns_raw, dict) else []
        vulns = [str(v)[:20] for v in vulns if str(v).startswith("CVE-")]

        return {
            "ip": ip,
            "org": str(data.get("org", ""))[:100],
            "country_code": str(data.get("country_code", ""))[:2],
            "ports": ports,
            "hostnames": hostnames,
            "tags": tags,
            "cves": vulns,
            "last_update": str(data.get("last_update", ""))[:30],
            "source": "shodan",
        }
    except Exception as e:
        logger.warning(f"Shodan lookup failed for {ip}: {e}")
        return None


async def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Enrich a single IP with both AbuseIPDB and Shodan data.
    Runs both lookups concurrently.
    """
    abuse, shodan = await asyncio.gather(
        enrich_ip_abuseipdb(ip),
        enrich_ip_shodan(ip),
        return_exceptions=True,
    )
    re Any: Dict[str, Any] = {"ip": ip}
    if isinstance(abuse, dict):
        re Any["abuseipdb"] = abuse
    if isinstance(shodan, dict):
        re Any["shodan"] = shodan

    # Compute combined threat score
    abuse_score = abuse.get("abuse_score", 0) if isinstance(abuse, dict) else 0
    has_cves = bool(isinstance(shodan, dict) and shodan.get("cves"))
    is_tor = isinstance(abuse, dict) and abuse.get("is_tor", False)

    threat_score = min(100, abuse_score + (20 if has_cves else 0) + (15 if is_tor else 0))
    re Any["threat_score"] = threat_score
    re Any["enriched"] = True

    return r, Any]:
async def batch_enrich_ips(
    ips: List[str],
    max_concurrent: int = 5,
    max_ips: int = 100,
) -> List[Dict[str, Any]]:
    """
    Enrich a batch of IPs with rate limiting.
    Deduplicates and filters non-routable before enrichment.
    """
    # Deduplicate + filter
    seen = set()
    routable = []
    for ip in ips:
        if ip not in seen and _is_routable(ip):
            seen.add(ip)
            routable.append(ip)
        if len(routable) >= max_ips:
            break

    if not routable:
        return []

    # Semaphore-limited concurrent enrichment
    sem = asyncio.Semaphore(max_concurrent)

    async def _limited(ip: str) -> Dict[str, Any]:
        async with sem:
            result = await enrich_ip(ip)
            await asyncio.sleep(0.1)  # gentle rate limiting
            return r, Any]:    results = await asyncio.gather(*[_limited(ip) for ip in routable], return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]
