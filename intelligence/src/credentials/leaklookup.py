"""Leak-Lookup breach database search."""
import logging
from typing import Any, Dict, List
import httpx
from src.shared.config import settings

logger = logging.getLogger(__name__)
_BASE = "https://leak-lookup.com/api"

async def search_domain(domain: str) -> Dict[str, Any]:
    """Search Leak-Lookup for breaches by domain."""
    if not settings.leak_lookup_key:
        return {"breaches": [], "total": 0}
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(f"{_BASE}/search",
                data={"key": settings.leak_lookup_key, "type": "domain", "query": domain})
            if r.status_code != 200:
                logger.warning(f"LeakLookup {domain}: {r.status_code}")
                return {"breaches": [], "total": 0}
            data = r.json()
            if data.get("error"):
                logger.warning(f"LeakLookup error: {data['error']}")
                return {"breaches": [], "total": 0}
        sources = data.get("message", {})
        breaches = [{"source": k, "count": len(v) if isinstance(v, list) else v} for k, v in sources.items()] if isinstance(sources, dict) else []
        return {"domain": domain, "breaches": breaches, "total": len(breaches), "source": "leaklookup"}
    except Exception as e:
        logger.error(f"LeakLookup {domain}: {e!r}")
        return {"breaches": [], "total": 0}

async def search_email(email: str) -> Dict[str, Any]:
    if not settings.leak_lookup_key:
        return {"breaches": [], "total": 0}
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(f"{_BASE}/search",
                data={"key": settings.leak_lookup_key, "type": "email_address", "query": email})
            if r.status_code != 200:
                return {"breaches": [], "total": 0}
            data = r.json()
        sources = data.get("message", {})
        return {"email": email, "breaches": list(sources.keys()) if isinstance(sources, dict) else [], "total": len(sources) if isinstance(sources, dict) else 0, "source": "leaklookup"}
    except Exception as e:
        logger.error(f"LeakLookup email {email}: {e!r}")
        return {"breaches": [], "total": 0}
