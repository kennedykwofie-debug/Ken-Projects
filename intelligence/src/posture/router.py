"""Organisational Posture Assessment router — /posture/*"""
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from src.auth.dependencies import get_current_user, require_analyst
from src.db.models import User
from .scanner import scan_domain, scan_ip_range
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/posture", tags=["Posture"])

class ScanRequest(BaseModel):
    domain: Optional[str] = None
    ips: Optional[List[str]] = []

@router.post("/scan")
async def posture_scan(body: ScanRequest, current_user: User = Depends(require_analyst)):
    results = {"org_id":str(current_user.org_id),"scans":[]}
    if body.domain:
        r = await scan_domain(body.domain)
        results["scans"].append(r)
        results["domain_score"] = r.get("score",0)
        results["domain_risk"] = r.get("risk_level","UNKNOWN")
    if body.ips:
        ip_results = await scan_ip_range(body.ips)
        results["ip_scans"] = ip_results
    return results

@router.get("/scan/{domain}")
async def scan_domain_get(domain: str, _: User = Depends(require_analyst)):
    return await scan_domain(domain)
