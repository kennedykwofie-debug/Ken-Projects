"""News Intelligence router — /news/*"""
import os, logging, httpx
from fastapi import APIRouter, Depends, HTTPException
from src.auth.dependencies import require_analyst
from src.db.models import User
from shared.cache import cache

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/news", tags=["News Intelligence"])
NEWS_KEY = os.getenv("NEWS_API_KEY","")
BASE = "https://newsapi.org/v2"

async def _fetch_news(q:str, page_size:int=10, language:str="en", sort:str="publishedAt"):
    if not NEWS_KEY:
        return {"status":"key_not_configured","key":"NEWS_API_KEY"}
    cache_key = f"news:{q}:{page_size}"
    cached = await cache.get(cache_key)
    if cached:
        import json; return json.loads(cached)
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{BASE}/everything", params={"q":q,"pageSize":page_size,"language":language,"sortBy":sort,"apiKey":NEWS_KEY})
        data = r.json()
        articles = [{"title":a["title"],"source":a["source"]["name"],"url":a["url"],"published":a["publishedAt"],"description":a.get("description",""),"image":a.get("urlToImage","")} for a in data.get("articles",[])]
        result = {"total":data.get("totalResults",0),"articles":articles,"query":q}
        await cache.set(cache_key, __import__("json").dumps(result), ttl=900)
        return result
    except Exception as e:
        logger.error(f"News fetch error: {e}")
        return {"status":"error","detail":str(e)}

@router.get("/headlines")
async def get_headlines(_:User=Depends(require_analyst)):
    """Top cyber threat intelligence headlines."""
    return await _fetch_news("cyber attack OR data breach OR ransomware OR APT OR malware", page_size=15)

@router.get("/geopolitical")
async def get_geopolitical(_:User=Depends(require_analyst)):
    """Geopolitical risk and conflict news."""
    return await _fetch_news("geopolitical risk OR sanctions OR military conflict OR espionage OR nation state", page_size=15)

@router.get("/cyber")
async def get_cyber_news(_:User=Depends(require_analyst)):
    """Latest cybersecurity news."""
    return await _fetch_news("cybersecurity OR zero day OR vulnerability OR exploit OR hacker", page_size=15)

@router.get("/search")
async def search_news(q:str, limit:int=10, _:User=Depends(require_analyst)):
    """Search news by keyword."""
    if not q or len(q) < 2:
        raise HTTPException(400, "Query must be at least 2 characters")
    return await _fetch_news(q, page_size=min(limit,20))

@router.get("/summary")
async def news_summary(_:User=Depends(require_analyst)):
    """Combined intelligence news summary."""
    import asyncio
    cyber, geo = await asyncio.gather(
        _fetch_news("ransomware OR APT OR data breach", page_size=5),
        _fetch_news("geopolitical risk OR nation state attack OR sanctions", page_size=5),
    )
    return {
        "cyber_headlines": cyber.get("articles",[])[:5],
        "geo_headlines": geo.get("articles",[])[:5],
        "total_cyber": cyber.get("total",0),
        "total_geo": geo.get("total",0),
    }
