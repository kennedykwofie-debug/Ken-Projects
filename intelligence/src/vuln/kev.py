"""CISA Known Exploited Vulnerabilities (KEV) catalogue — no key needed."""
import logging
from typing import Any, Dict, List
from src.shared.http import fetch_json
from src.shared.cache import cache
logger = logging.getLogger(__name__)
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def fetch_kev(limit: int = 50) -> Dict[str, Any]:
    cached = await cache.get("kev:all")
    if cached:
        return {**cached, "cached": True}
    try:
        data = await fetch_json(_KEV_URL)
        if not data:
            return {"vulns":[],"total":0,"status":"error"}
        vulns = []
        for v in (data.get("vulnerabilities") or [])[:limit]:
            vulns.append({"cve_id":v.get("cveID",""),"vendor":v.get("vendorProject",""),"product":v.get("product",""),"name":v.get("vulnerabilityName",""),"date_added":v.get("dateAdded",""),"due_date":v.get("dueDate",""),"description":v.get("shortDescription","")[:200],"ransomware_use":v.get("knownRansomwareCampaignUse","Unknown")})
        result = {"vulns":vulns,"total":len(data.get("vulnerabilities",[])), "catalog_version":data.get("catalogVersion",""),"date_released":data.get("dateReleased",""),"status":"ok"}
        await cache.set("kev:all", result, ttl=3600)
        return result
    except Exception as e:
        logger.error(f"KEV fetch: {e}")
        return {"vulns":[],"total":0,"status":"error","error":str(e)}

async def check_cves_in_kev(cve_ids: List[str]) -> Dict[str, Any]:
    kev = await fetch_kev(limit=1000)
    kev_set = {v["cve_id"]: v for v in kev.get("vulns",[])}
    results = []
    for cve_id in cve_ids:
        if cve_id in kev_set:
            results.append({**kev_set[cve_id],"in_kev":True})
        else:
            results.append({"cve_id":cve_id,"in_kev":False})
    return {"results":results,"kev_matches":sum(1 for r in results if r.get("in_kev"))}
