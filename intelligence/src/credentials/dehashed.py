"""DeHashed breach database search."""
import logging
from typing import Any, Dict, List
import httpx
from src.shared.config import settings

logger = logging.getLogger(__name__)
_BASE = "https://api.dehashed.com"

async def search_domain(domain: str, size: int = 20) -> Dict[str, Any]:
    """Search DeHashed for breached credentials for a domain."""
    if not settings.dehashed_key:
        return {"entries": [], "total": 0}
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(f"{_BASE}/search",
                params={"query": f"domain:{domain}", "size": size},
                headers={"Accept": "application/json", "Authorization": f"Basic {settings.dehashed_key}"})
            if r.status_code == 401:
                logger.error("DeHashed: invalid credentials")
                return {"entries": [], "total": 0}
            if r.status_code != 200:
                logger.warning(f"DeHashed {domain}: {r.status_code}")
                return {"entries": [], "total": 0}
            data = r.json()
        entries = []
        for e in data.get("entries", [])[:size]:
            entries.append({
                "email": e.get("email", ""),
                "username": e.get("username", ""),
                "database_name": e.get("database_name", ""),
                "hashed_password": bool(e.get("hashed_password")),
                "password": bool(e.get("password")),
            })
        return {"domain": domain, "entries": entries, "total": data.get("total", 0), "source": "dehashed"}
    except Exception as e:
        logger.error(f"DeHashed search {domain}: {e!r}")
        return {"entries": [], "total": 0}

async def search_email(email: str) -> Dict[str, Any]:
    if not settings.dehashed_key:
        return {"entries": [], "total": 0}
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(f"{_BASE}/search",
                params={"query": f"email:{email}", "size": 10},
                headers={"Accept": "application/json", "Authorization": f"Basic {settings.dehashed_key}"})
            if r.status_code != 200:
                return {"entries": [], "total": 0}
            data = r.json()
        return {"email": email, "breaches": [e.get("database_name") for e in data.get("entries", [])], "total": data.get("total", 0), "source": "dehashed"}
    except Exception as e:
        logger.error(f"DeHashed email {email}: {e!r}")
        return {"entries": [], "total": 0}
