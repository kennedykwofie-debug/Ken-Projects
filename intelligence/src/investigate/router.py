"""Investigation Workbench router — /investigate/*"""
import logging, re
from fastapi import APIRouter, Depends, HTTPException
from src.auth.dependencies import require_analyst
from src.db.models import User
from .enrichment import enrich_ip, enrich_domain, enrich_hash
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/investigate", tags=["Investigation"])

_IP_RE = re.compile(r'^(?:d{1,3}.){3}d{1,3}$')
_HASH_RE = re.compile(r'^[a-fA-F0-9]{32,64}$')
_DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?.)+[a-zA-Z]{2,}$')

@router.get("/enrich/{indicator:path}")
async def enrich_indicator(indicator: str, _: User = Depends(require_analyst)):
    """Auto-detect indicator type (IP / domain / hash) and enrich from all sources."""
    indicator = indicator.strip()
    if _IP_RE.match(indicator):
        return await enrich_ip(indicator)
    elif _HASH_RE.match(indicator):
        return await enrich_hash(indicator)
    elif _DOMAIN_RE.match(indicator):
        return await enrich_domain(indicator)
    else:
        raise HTTPException(400, f"Cannot detect type for: {indicator}. Provide IP, domain, or MD5/SHA256 hash.")
