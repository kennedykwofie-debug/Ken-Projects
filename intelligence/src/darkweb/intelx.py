"""Intelligence X dark web and leak search."""
import logging
from typing import Any, Dict, List
import httpx
from src.shared.config import settings

logger = logging.getLogger(__name__)
_BASE = "https://2.intelx.io"

async def search(query: str, limit: int = 10) -> Dict[str, Any]:
    """Search IntelX for a domain, email, IP, or hash."""
    if not settings.intelx_key:
        return {"results": [], "count": 0}
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            # Start search
            r = await c.post(f"{_BASE}/intelligent/search",
                headers={"x-key": settings.intelx_key, "Content-Type": "application/json"},
                json={"term": query, "buckets": [], "lookuplevel": 0, "maxresults": limit,
                      "timeout": 5, "datefrom": "", "dateto": "", "sort": 4, "media": 0, "terminate": []})
            if r.status_code != 200:
                logger.warning(f"IntelX search start: {r.status_code}")
                return {"results": [], "count": 0}
            search_id = r.json().get("id")
            if not search_id:
                return {"results": [], "count": 0}

            # Get results
            import asyncio
            await asyncio.sleep(2)
            res = await c.get(f"{_BASE}/intelligent/search/result",
                headers={"x-key": settings.intelx_key},
                params={"id": search_id, "limit": limit, "offset": 0})
            if res.status_code != 200:
                return {"results": [], "count": 0}
            data = res.json()

        records = []
        for item in data.get("records", [])[:limit]:
            records.append({
                "name": item.get("name", ""),
                "date": str(item.get("date", ""))[:10],
                "bucket": item.get("bucket", ""),
                "type": item.get("type", 0),
                "media": item.get("media", 0),
            })
        return {"results": records, "count": data.get("total", len(records)), "query": query, "source": "intelx"}
    except Exception as e:
        logger.error(f"IntelX search {query}: {e!r}")
        return {"results": [], "count": 0}

async def search_credentials(domain: str) -> Dict[str, Any]:
    """Search for leaked credentials for a domain."""
    result = await search(f"@{domain}", limit=20)
    cred_records = [r for r in result.get("results", []) if r.get("bucket") in ("pastes", "leaks", "darkweb")]
    return {"domain": domain, "leaked_records": cred_records, "total": result.get("count", 0), "source": "intelx"}
