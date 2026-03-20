"""Vulnerability Intelligence router Ã¢ÂÂ /vuln/*"""
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from src.auth.dependencies import get_current_user, require_analyst
from src.db.models import User
from .nvd import fetch_recent_cves, search_cves
from .kev import fetch_kev, check_cves_in_kev
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/vuln", tags=["Vulnerability"])

@router.get("/recent")
async def recent_cves(days: int = Query(7,le=30), limit: int = Query(20,le=50), severity: Optional[str] = None, _: User = Depends(get_current_user)):
    return await fetch_recent_cves(days=days, limit=limit, severity=severity)

@router.get("/search")
async def search_vulns(q: str = Query(...,min_length=2), limit: int = Query(10,le=20), _: User = Depends(get_current_user)):
    return await search_cves(q, limit)

@router.get("/kev")
async def known_exploited(limit: int = Query(50,le=200), _: User = Depends(get_current_user)):
    return await fetch_kev(limit)

class KevCheckRequest(BaseModel):
    cve_ids: List[str]

@router.post("/kev/check")
async def check_kev(body: KevCheckRequest, _: User = Depends(require_analyst)):
    return await check_cves_in_kev(body.cve_ids)

@router.get("/critical")
async def critical_cves(_: User = Depends(get_current_user)):
    cves_task = fetch_recent_cves(days=14, limit=10, severity="CRITICAL")
    kev_task = fetch_kev(limit=10)
    import asyncio
    cves, kev = await asyncio.gather(cves_task, kev_task)
    return {"recent_critical_cves":cves.get("cves",[]),"actively_exploited_kev":kev.get("vulns",[])[:10],"summary":{"critical_last_14d":cves.get("total",0),"total_kev":kev.get("total",0)}}


@router.get("/exploited")
async def get_exploited(limit: int = 20) -> Dict[str, Any]:
    """CVEs actively exploited right now via VulnCheck."""
    from src.shared.cache import cache
    cached = await cache.get("vulncheck:exploited:v1")
    if cached:
        return cached
    from src.vuln.vulncheck import get_exploited_cves
    cves = await get_exploited_cves(limit=limit)
    result = {"cves": cves, "count": len(cves), "source": "vulncheck"}
    await cache.set("vulncheck:exploited:v1", result, ttl=1800)
    return result
