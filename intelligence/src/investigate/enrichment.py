"""Multi-source enrichment for IPs, domains, hashes, emails."""
import logging, os, asyncio
from typing import Any, Dict
from src.shared.http import fetch_json, fetch_text
logger = logging.getLogger(__name__)
VT_KEY = os.getenv("VIRUSTOTAL_KEY","")
GREYNOISE_KEY = os.getenv("GREYNOISE_KEY","")
SHODAN_KEY = os.getenv("SHODAN_KEY","")
IPINFO_KEY = os.getenv("IPINFO_KEY","")
URLSCAN_KEY = os.getenv("URLSCAN_KEY","")

async def enrich_ip(ip: str) -> Dict[str,Any]:
    tasks = {}
    async def vt():
        if not VT_KEY: return {"status":"key_not_configured","key":"VIRUSTOTAL_KEY"}
        return await fetch_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey":VT_KEY}) or {}
    async def gn():
        if not GREYNOISE_KEY: return {"status":"key_not_configured","key":"GREYNOISE_KEY"}
        return await fetch_json(f"https://api.greynoise.io/v3/community/{ip}", headers={"key":GREYNOISE_KEY}) or {}
    async def sh():
        if not SHODAN_KEY: return {"status":"key_not_configured","key":"SHODAN_KEY"}
        return await fetch_json(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}") or {}
    async def ii():
        url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_KEY: url += f"?token={IPINFO_KEY}"
        return await fetch_json(url) or {}
    results = await asyncio.gather(vt(), gn(), sh(), ii(), return_exceptions=True)
    vt_r, gn_r, sh_r, ii_r = [(r if not isinstance(r,Exception) else {"error":str(r)}) for r in results]
    # parse VT
    vt_stats = {}
    if "data" in vt_r:
        attrs = vt_r["data"].get("attributes",{})
        vt_stats = {"malicious":attrs.get("last_analysis_stats",{}).get("malicious",0),
                    "suspicious":attrs.get("last_analysis_stats",{}).get("suspicious",0),
                    "reputation":attrs.get("reputation",0),
                    "country":attrs.get("country",""),"asn":attrs.get("asn","")}
    return {"ip":ip,"virustotal":vt_stats,"greynoise":gn_r,"shodan":{"ports":sh_r.get("ports",[]),"org":sh_r.get("org",""),"os":sh_r.get("os",""),"vulns":list(sh_r.get("vulns",{}).keys())[:10]} if "ports" in sh_r else sh_r,"ipinfo":ii_r,"type":"ip"}

async def enrich_domain(domain: str) -> Dict[str,Any]:
    async def vt():
        if not VT_KEY: return {"status":"key_not_configured","key":"VIRUSTOTAL_KEY"}
        return await fetch_json(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey":VT_KEY}) or {}
    async def us():
        if not URLSCAN_KEY: return {"status":"key_not_configured","key":"URLSCAN_KEY"}
        return await fetch_json(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5", headers={"API-Key":URLSCAN_KEY}) or {}
    async def tf():
        return await fetch_json(f"https://threatfox-api.abuse.ch/api/v1/", params={"query":"search_ioc","search_term":domain}) or {}
    results = await asyncio.gather(vt(), us(), tf(), return_exceptions=True)
    vt_r, us_r, tf_r = [(r if not isinstance(r,Exception) else {"error":str(r)}) for r in results]
    vt_stats = {}
    if "data" in vt_r:
        attrs = vt_r["data"].get("attributes",{})
        vt_stats = {"malicious":attrs.get("last_analysis_stats",{}).get("malicious",0),"reputation":attrs.get("reputation",0),"categories":attrs.get("categories",{})}
    return {"domain":domain,"virustotal":vt_stats,"urlscan":{"results":(us_r.get("results") or [])[:3]} if "results" in us_r else us_r,"threatfox":{"iocs":(tf_r.get("data") or [])[:5]} if "data" in tf_r else tf_r,"type":"domain"}

async def enrich_hash(hash_val: str) -> Dict[str,Any]:
    async def vt():
        if not VT_KEY: return {"status":"key_not_configured","key":"VIRUSTOTAL_KEY"}
        return await fetch_json(f"https://www.virustotal.com/api/v3/files/{hash_val}", headers={"x-apikey":VT_KEY}) or {}
    async def mb():
        data = await fetch_json("https://mb-api.abuse.ch/api/v1/", params={"query":"get_info","hash":hash_val})
        return data or {}
    results = await asyncio.gather(vt(), mb(), return_exceptions=True)
    vt_r, mb_r = [(r if not isinstance(r,Exception) else {"error":str(r)}) for r in results]
    vt_stats = {}
    if "data" in vt_r:
        attrs = vt_r["data"].get("attributes",{})
        vt_stats = {"malicious":attrs.get("last_analysis_stats",{}).get("malicious",0),"type_description":attrs.get("type_description",""),"size":attrs.get("size",0),"names":attrs.get("names",[])[:5]}
    return {"hash":hash_val,"virustotal":vt_stats,"malwarebazaar":mb_r.get("data",[{}])[0] if mb_r.get("data") else {},"type":"hash"}
