"""News Intelligence router — /news/*"""
import os
import logging
import asyncio
import json
import httpx
from fastapi import APIRouter, Depends, HTTPException
from src.auth.dependencies import require_analyst
from src.db.models import User
from src.shared.cache import cache

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/news", tags=["News Intelligence"])
NEWS_KEY = os.getenv("NEWS_API_KEY", "")
BASE = "https://newsapi.org/v2"

async def _fetch_news(q: str, page_size: int = 10) -> dict:
    if not NEWS_KEY:
        return {"status": "key_not_configured", "key": "NEWS_API_KEY", "articles": []}
    cache_key = f"news:{q[:50]}:{page_size}"
    cached = await cache.get(cache_key)
    if cached:
        return json.loads(cached)
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(f"{BASE}/everything", params={
                "q": q, "pageSize": page_size, "language": "en",
                "sortBy": "publishedAt", "apiKey": NEWS_KEY
            })
            r.raise_for_status()
            data = r.json()
            articles = [{
                "title": a["title"],
                "source": a["source"]["name"],
                "url": a["url"],
                "published": a["publishedAt"],
                "description": (a.get("description") or "")[:200],
                "image": a.get("urlToImage", "")
            } for a in data.get("articles", [])
              if a.get("title") and "[Removed]" not in a.get("title", "")]
            result = {"total": data.get("totalResults", 0), "articles": articles, "query": q}
            await cache.set(cache_key, json.dumps(result), ttl=900)
            return result
    except Exception as e:
        logger.error(f"News fetch error: {e}")
        return {"status": "error", "detail": str(e), "articles": []}

@router.get("/headlines")
async def get_headlines(_: User = Depends(require_analyst)):
    """Top combined threat intelligence headlines."""
    cyber, geo = await asyncio.gather(
        _fetch_news("cybersecurity hacking data breach ransomware CVE exploit", 6),
        _fetch_news("geopolitical sanctions conflict espionage nation state attack", 6),
    )
    all_articles = sorted(
        cyber.get("articles", []) + geo.get("articles", []),
        key=lambda x: x.get("published", ""), reverse=True
    )
    return {"total": len(all_articles), "articles": all_articles[:12]}

@router.get("/cyber")
async def get_cyber_news(_: User = Depends(require_analyst)):
    """Latest cybersecurity news."""
    return await _fetch_news("cybersecurity ransomware zero day vulnerability exploit hacker APT malware", 12)

@router.get("/geopolitical")
async def get_geopolitical(_: User = Depends(require_analyst)):
    """Geopolitical risk and conflict news."""
    return await _fetch_news("geopolitical risk sanctions war diplomacy espionage nation state", 12)

@router.get("/search")
async def search_news(q: str, limit: int = 10, _: User = Depends(require_analyst)):
    """Search news by keyword."""
    if not q or len(q.strip()) < 2:
        raise HTTPException(400, "Query must be at least 2 characters")
    return await _fetch_news(q.strip(), min(limit, 20))

@router.get("/summary")
async def news_summary(_: User = Depends(require_analyst)):
    """Combined intelligence news summary."""
    cyber, geo = await asyncio.gather(
        _fetch_news("ransomware APT data breach malware", 5),
        _fetch_news("geopolitical risk nation state attack sanctions", 5),
    )
    return {
        "cyber_headlines": cyber.get("articles", [])[:5],
        "geo_headlines": geo.get("articles", [])[:5],
        "total_cyber": cyber.get("total", 0),
        "total_geo": geo.get("total", 0),
    }
