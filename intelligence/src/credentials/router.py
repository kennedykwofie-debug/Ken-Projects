"""Credentials breach intelligence API routes."""
import logging
from typing import Any, Dict
from fastapi import APIRouter
from src.shared.cache import cache

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/search/{domain}")
async def search_domain_breaches(domain: str) -> Dict[str, Any]:
    """Search for breached credentials across DeHashed and Leak-Lookup."""
    cache_key = f"credentials:domain:{domain}:v1"
    cached = await cache.get(cache_key)
    if cached:
        return cached
    import asyncio
    from src.credentials.dehashed import search_domain as dh_search
    from src.credentials.leaklookup import search_domain as ll_search
    dh, ll = await asyncio.gather(dh_search(domain), ll_search(domain), return_exceptions=True)
    result = {
        "domain": domain,
        "dehashed": dh if isinstance(dh, dict) else {"entries": [], "total": 0},
        "leaklookup": ll if isinstance(ll, dict) else {"breaches": [], "total": 0},
        "total_exposed": (dh.get("total", 0) if isinstance(dh, dict) else 0) + (ll.get("total", 0) if isinstance(ll, dict) else 0),
    }
    await cache.set(cache_key, result, ttl=3600)
    return result

@router.get("/email/{email}")
async def search_email_breaches(email: str) -> Dict[str, Any]:
    """Search for a specific email across breach databases."""
    import asyncio
    from src.credentials.dehashed import search_email as dh_email
    from src.credentials.leaklookup import search_email as ll_email
    dh, ll = await asyncio.gather(dh_email(email), ll_email(email), return_exceptions=True)
    return {
        "email": email,
        "dehashed": dh if isinstance(dh, dict) else {},
        "leaklookup": ll if isinstance(ll, dict) else {},
    }
