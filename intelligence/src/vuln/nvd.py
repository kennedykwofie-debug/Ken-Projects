"""NIST NVD CVE feed with optional API key for higher rate limits."""
import logging, os
from typing import Any, Dict, List
from src.shared.http import fetch_json
logger = logging.getLogger(__name__)
NVD_KEY = os.getenv("NVD_KEY","")
_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def fetch_recent_cves(days: int = 7, limit: int = 20, severity: str = None) -> Dict[str,Any]:
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {"pubStartDate":start+"Z","pubEndDate":end+"Z","resultsPerPage":min(limit,50)}
    if severity:
        params["cvssV3Severity"] = severity.upper()
    headers = {}
    if NVD_KEY:
        headers["apiKey"] = NVD_KEY
    try:
        data = await fetch_json(_NVD, params=params, headers=headers)
        if not data:
            return {"cves":[],"total":0,"status":"error"}
        cves = []
        for item in (data.get("vulnerabilities") or []):
            cve = item.get("cve",{})
            metrics = cve.get("metrics",{})
            cvss = None
            for version in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                m = metrics.get(version,[])
                if m:
                    cvss = m[0].get("cvssData",{})
                    break
            descs = cve.get("descriptions",[])
            desc = next((d["value"] for d in descs if d.get("lang")=="en"),"")
            refs = [r.get("url","") for r in (cve.get("references") or [])[:3]]
            cves.append({"id":cve.get("id",""),"published":cve.get("published",""),"description":desc[:300],"cvss_score":cvss.get("baseScore",0) if cvss else 0,"severity":cvss.get("baseSeverity","") if cvss else "","vector":cvss.get("vectorString","") if cvss else "","references":refs})
        return {"cves":cves,"total":data.get("totalResults",0),"status":"ok"}
    except Exception as e:
        logger.error(f"NVD fetch: {e}")
        return {"cves":[],"total":0,"status":"error","error":str(e)}

async def search_cves(keyword: str, limit: int = 10) -> Dict[str,Any]:
    params = {"keywordSearch":keyword,"resultsPerPage":min(limit,20)}
    headers = {"apiKey":NVD_KEY} if NVD_KEY else {}
    try:
        data = await fetch_json(_NVD, params=params, headers=headers)
        if not data:
            return {"cves":[],"total":0}
        cves = []
        for item in (data.get("vulnerabilities") or []):
            cve = item.get("cve",{})
            descs = cve.get("descriptions",[])
            desc = next((d["value"] for d in descs if d.get("lang")=="en"),"")
            cves.append({"id":cve.get("id",""),"published":cve.get("published",""),"description":desc[:250]})
        return {"cves":cves,"total":data.get("totalResults",0)}
    except Exception as e:
        return {"cves":[],"total":0,"error":str(e)}
