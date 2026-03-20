"""Credential breach monitoring — HIBP domain + Dehashed."""
import logging, os
from typing import Any, Dict
from src.shared.http import fetch_json
logger = logging.getLogger(__name__)
HIBP_KEY = os.getenv("HIBP_KEY","")
DEHASHED_KEY = os.getenv("DEHASHED_KEY","")

async def check_domain_breaches(domain: str) -> Dict[str, Any]:
    out = {"domain":domain,"hibp":[],"dehashed":[],"total_exposed":0}
    if HIBP_KEY:
        try:
            data = await fetch_json(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers={"hibp-api-key":HIBP_KEY,"user-agent":"DARKWATCH-Pro"})
            if isinstance(data, dict):
                for breach, emails in data.items():
                    out["hibp"].append({"breach":breach,"count":len(emails)})
                    out["total_exposed"] += len(emails)
        except Exception as e:
            logger.warning(f"HIBP: {e}")
    else:
        out["hibp_status"] = "key_not_configured"
    if DEHASHED_KEY:
        try:
            data = await fetch_json("https://api.dehashed.com/search",
                headers={"Accept":"application/json"},
                params={"query":f"domain:{domain}","size":10})
            if data:
                out["dehashed"] = (data.get("entries") or [])[:10]
                out["total_exposed"] += data.get("total",0)
        except Exception as e:
            logger.warning(f"Dehashed: {e}")
    else:
        out["dehashed_status"] = "key_not_configured"
    return out
