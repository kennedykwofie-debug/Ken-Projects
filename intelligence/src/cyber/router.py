"""Cyber threat intelligence API routes."""

import logging
import re
from typing import Any, Dict

from fastapi import APIRouter, Query
from slowapi import Limiter
from slowapi.util import get_remote_address

from src.shared.cache import cache
from src.shared.config import settings
from src.cyber.aggregator import build_threat_summary
from src.cyber.enrichment import enrich_ip, _is_routable

logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

_THREAT_CACHE = "cyber:threats:v1"
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"  # IPv4 only for now
)


@router.get("/threats")
async def get_threat_summary() -> Dict[str, Any]:
    """
    Unified cyber threat picture: C2 servers (Feodo), malicious domains (URLhaus),
    threat intelligence pulses (OTX). Top C2 IPs enriched with AbuseIPDB + Shodan.
    """
    data = await cache.cached_fetch(
        _THREAT_CACHE,
        ttl=settings.cache_ttl_short,
        fetcher=build_threat_summary,
        stale_ttl=settings.cache_ttl_medium,
    )
    return data or {"c2_servers": [], "malware_domains": [], "threat_pulses": [], "summary": {}}


@router.get("/enrich/{ip}")
async def enrich_ip_endpoint(ip: str) -> Dict[str, Any]:
    """
    Enrich a single IP address with AbuseIPDB + Shodan intelligence.
    Returns abuse confidence score, ISP, open ports, CVEs.
    """
    # Validate IP format before any processing
    if not _IP_RE.match(ip):
        return {"error": "Invalid IP format", "ip": ip}
    if not _is_routable(ip):
        return {"error": "Non-routable IP address", "ip": ip}

    cache_key = f"cyber:enrich:{ip}:v1"

    async def _fetch():
        return await enrich_ip(ip)

    data = await cache.cached_fetch(
        cache_key,
        ttl=3600,  # 1h — IP reputation changes slowly
        fetcher=_fetch,
        stale_ttl=86400,
    )
    return data or {"ip": ip, "enriched": False}


@router.get("/c2")
async def get_c2_servers(
    severity: str = Query(default="all", pattern=r"^(all|CRITICAL|HIGH|MEDIUM|LOW)$"),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """
    C2 (command-and-control) server list from Feodo Tracker, enriched with
    AbuseIPDB abuse score and Shodan port/CVE data.
    """
    data = await cache.cached_fetch(
        _THREAT_CACHE,
        ttl=settings.cache_ttl_short,
        fetcher=build_threat_summary,
        stale_ttl=settings.cache_ttl_medium,
    )
    c2 = (data or {}).get("c2_servers", [])
    if severity != "all":
        c2 = [r for r in c2 if r.get("severity") == severity]

    return {
        "c2_servers": c2[:limit],
        "count": len(c2),
        "severity_filter": severity,
    }
