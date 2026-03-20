"""Ransomware.live + RansomWatch live victim tracking — no key needed."""
import logging
from typing import Any, Dict, List
from src.shared.http import fetch_json
logger = logging.getLogger(__name__)
_RL = "https://api.ransomware.live/recentvictims"
_RW = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

async def fetch_ransomware_victims(limit: int = 50) -> List[Dict[str, Any]]:
    try:
        data = await fetch_json(_RL)
        if isinstance(data, list) and data:
            return [{"victim":v.get("victim",""),"group":v.get("group",""),"country":v.get("country",""),"sector":v.get("activity",""),"published":v.get("published",""),"url":v.get("post_url",""),"source":"ransomware.live"} for v in data[:limit]]
    except Exception as e:
        logger.warning(f"ransomware.live: {e}")
    try:
        data = await fetch_json(_RW)
        if isinstance(data, list):
            return [{"victim":v.get("post_title",""),"group":v.get("group_name",""),"country":"","sector":"","published":v.get("discovered",""),"url":"","source":"ransomwatch"} for v in data[:limit]]
    except Exception as e:
        logger.warning(f"ransomwatch: {e}")
    return []
