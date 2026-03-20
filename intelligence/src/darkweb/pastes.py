"""Paste site + dark web search via IntelX (optional INTELX_KEY)."""
import logging, os, asyncio
from typing import Any, Dict
from src.shared.http import fetch_json
logger = logging.getLogger(__name__)
INTELX_KEY = os.getenv("INTELX_KEY","")

async def search_pastes(query: str, limit: int = 20) -> Dict[str, Any]:
    if not INTELX_KEY:
        return {"status":"key_not_configured","key":"INTELX_KEY","data":[],"query":query}
    try:
        init = await fetch_json("https://2.intelx.io/intelligent/search",
            headers={"x-key":INTELX_KEY}, params={"q":query,"limit":limit,"media":0,"sort":4})
        if not init or "id" not in init:
            return {"status":"error","data":[],"query":query}
        await asyncio.sleep(1)
        res = await fetch_json("https://2.intelx.io/intelligent/search/result",
            headers={"x-key":INTELX_KEY}, params={"id":init["id"],"limit":limit})
        records = [{"name":r.get("name",""),"date":r.get("date",""),"bucket":r.get("bucket",""),"source":"intelx"}
                   for r in (res or {}).get("records",[])]
        return {"status":"ok","data":records,"query":query}
    except Exception as e:
        logger.error(f"intelx: {e}")
        return {"status":"error","data":[],"query":query}
