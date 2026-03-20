"""Dark Web Monitor router â /darkweb/*"""
import logging
from fastapi import APIRouter, Depends, Query
from src.auth.dependencies import get_current_user, require_analyst
from src.db.models import User
from .ransomware import fetch_ransomware_victims
from .pastes import search_pastes
from .breaches import check_domain_breaches
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/darkweb", tags=["Dark Web"])

@router.get("/ransomware")
async def ransomware_victims(limit: int = Query(50, le=200), _: User = Depends(require_analyst)):
    victims = await fetch_ransomware_victims(limit)
    groups = {}
    for v in victims:
        g = v.get("group","Unknown"); groups[g] = groups.get(g,0)+1
    top = sorted(groups.items(), key=lambda x:x[1], reverse=True)[:10]
    sectors = {}
    for v in victims:
        s = v.get("sector","") or "Unknown"; sectors[s] = sectors.get(s,0)+1
    return {"victims":victims,"total":len(victims),
            "top_groups":[{"group":g,"count":c} for g,c in top],
            "top_sectors":sorted(sectors.items(),key=lambda x:x[1],reverse=True)[:8]}

@router.get("/pastes")
async def paste_search(q: str = Query(...,min_length=3), limit: int = Query(20,le=50), _: User = Depends(require_analyst)):
    return await search_pastes(q, limit)

@router.get("/breaches/{domain}")
async def domain_breaches(domain: str, _: User = Depends(get_current_user)):
    return await check_domain_breaches(domain)

@router.get("/summary")
async def darkweb_summary(_: User = Depends(require_analyst)):
    victims = await fetch_ransomware_victims(200)
    groups,sectors,countries = {},{},{}
    for v in victims:
        g=v.get("group","Unknown"); groups[g]=groups.get(g,0)+1
        s=(v.get("sector","") or "Unknown"); sectors[s]=sectors.get(s,0)+1
        c=(v.get("country","") or "Unknown"); countries[c]=countries.get(c,0)+1
    return {"total_recent_victims":len(victims),"active_groups":len(groups),
            "top_groups":sorted(groups.items(),key=lambda x:x[1],reverse=True)[:8],
            "top_sectors":sorted(sectors.items(),key=lambda x:x[1],reverse=True)[:6],
            "top_countries":sorted(countries.items(),key=lambda x:x[1],reverse=True)[:6]}


@router.get("/intelx/search")
async def intelx_search(q: str, limit: int = 10) -> Dict[str, Any]:
    """Search Intelligence X for dark web mentions."""
    if not q:
        return {"results": [], "count": 0}
    from src.shared.cache import cache
    cache_key = f"intelx:search:{q[:50]}:v1"
    cached = await cache.get(cache_key)
    if cached:
        return cached
    from src.darkweb.intelx import search
    result = await search(q, limit=limit)
    await cache.set(cache_key, result, ttl=900)
    return result

@router.get("/intelx/credentials/{domain}")
async def intelx_credentials(domain: str) -> Dict[str, Any]:
    """Search IntelX for leaked credentials for a domain."""
    from src.shared.cache import cache
    cache_key = f"intelx:creds:{domain}:v1"
    cached = await cache.get(cache_key)
    if cached:
        return cached
    from src.darkweb.intelx import search_credentials
    result = await search_credentials(domain)
    await cache.set(cache_key, result, ttl=900)
    return result
