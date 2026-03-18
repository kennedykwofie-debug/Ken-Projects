"""Cyber threat intelligence API routes."""
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Query

from src.shared.cache import cache
from src.shared.config import settings
from src.cyber.aggregator import build_threat_summary
from src.cyber.enrichment import enrich_ip

logger = logging.getLogger(__name__)
router = APIRouter()

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_THREAT_CACHE_KEY = "cyber:threats:v1"


@router.get("/threats")
async def get_threat_summary() -> Dict[str, Any]:
    """Unified cyber threat picture from Feodo, URLhaus, and OTX."""
    cached = await cache.get(_THREAT_CACHE_KEY)
    if cached:
        return cached
    data = await build_threat_summary()
    await cache.set(_THREAT_CACHE_KEY, data, ttl=settings.cache_ttl)
    return data


@router.get("/enrich/{ip}")
async def enrich_ip_endpoint(ip: str) -> Dict[str, Any]:
    """Enrich a single IP with AbuseIPDB + Shodan data."""
    if not _IP_RE.match(ip):
        return {"error": "Invalid IP format", "ip": ip}
    cache_key = f"cyber:enrich:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return cached
    data = await enrich_ip(ip)
    if data:
        await cache.set(cache_key, data, ttl=3600)
    return data or {"ip": ip, "enriched": False}


@router.get("/c2")
async def get_c2_servers(
    severity: str = Query(default="all", pattern=r"^(all|CRITICAL|HIGH|MEDIUM|LOW)$"),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """C2 server list from Feodo Tracker enriched with threat intel."""
    cached = await cache.get(_THREAT_CACHE_KEY)
    data = cached or await build_threat_summary()
    c2 = data.get("c2_servers", [])
    if severity != "all":
        c2 = [r for r in c2 if r.get("severity") == severity]
    return {"c2_servers": c2[:limit], "count": len(c2), "severity_filter": severity}


@router.get("/iocs")
async def get_iocs(
    limit: int = Query(default=50, ge=1, le=200)
) -> Dict[str, Any]:
    """Recent indicators of compromise from all feeds."""
    cached = await cache.get(_THREAT_CACHE_KEY)
    data = cached or await build_threat_summary()
    iocs = []
    for c2 in data.get("c2_servers", [])[:limit]:
        iocs.append({"type": "ip", "value": c2.get("ip"), "threat": c2.get("malware_family"), "severity": c2.get("severity")})
    for url in data.get("malware_domains", [])[:limit]:
        iocs.append({"type": "url", "value": url.get("url"), "threat": url.get("threat"), "severity": "HIGH"})
    return {"iocs": iocs[:limit], "count": len(iocs), "timestamp": datetime.now(timezone.utc).isoformat()}
