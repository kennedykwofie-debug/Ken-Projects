"""Censys internet-wide host scanner for infrastructure enrichment."""
import asyncio
import logging
from typing import Any, Dict, List
import httpx
from src.shared.config import settings

logger = logging.getLogger(__name__)
_BASE = "https://search.censys.io/api/v2"

async def enrich_ip(ip: str) -> Dict[str, Any]:
    if not settings.censys_key:
        return {}
    try:
        creds = tuple(settings.censys_key.split("_", 1)[1].split(":")) if ":" in settings.censys_key else None
        # Censys uses basic auth: api_id:secret
        # Key format: censys_<id>_<secret> or just the token
        key = settings.censys_key
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(f"{_BASE}/hosts/{ip}", headers={"Authorization": f"Basic {key}"})
            if r.status_code == 401:
                # Try bearer
                r = await c.get(f"{_BASE}/hosts/{ip}", headers={"Authorization": f"Bearer {key}"})
            if r.status_code != 200:
                logger.warning(f"Censys {ip}: {r.status_code}")
                return {}
            d = r.json().get("result", {})
        return {
            "ip": ip,
            "services": [{"port": s.get("port"), "proto": s.get("transport_protocol"), "name": s.get("service_name")} for s in d.get("services", [])[:10]],
            "location": d.get("location", {}).get("country"),
            "asn": d.get("autonomous_system", {}).get("asn"),
            "org": d.get("autonomous_system", {}).get("name"),
            "labels": d.get("labels", []),
            "source": "censys",
        }
    except Exception as e:
        logger.error(f"Censys enrich_ip {ip}: {e!r}")
        return {}

async def enrich_domain(domain: str) -> Dict[str, Any]:
    if not settings.censys_key:
        return {}
    try:
        key = settings.censys_key
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(
                f"{_BASE}/hosts/search",
                params={"q": f"dns.reverse_dns.reverse_dns:{domain}", "per_page": "5"},
                headers={"Authorization": f"Bearer {key}"}
            )
            if r.status_code != 200:
                return {}
            hits = r.json().get("result", {}).get("hits", [])
        return {
            "domain": domain,
            "exposed_hosts": [{"ip": h.get("ip"), "services": [s.get("port") for s in h.get("services", [])]} for h in hits],
            "source": "censys",
        }
    except Exception as e:
        logger.error(f"Censys enrich_domain {domain}: {e!r}")
        return {}
