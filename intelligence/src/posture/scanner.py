"""Asset exposure scanning — Shodan + HIBP + CVE cross-reference."""
import logging, os
from typing import Any, Dict, List
from src.shared.http import fetch_json
logger = logging.getLogger(__name__)
SHODAN_KEY = os.getenv("SHODAN_KEY","")
HIBP_KEY = os.getenv("HIBP_KEY","")

async def scan_domain(domain: str) -> Dict[str,Any]:
    results = {"domain":domain,"shodan":{},"hibp":{},"score":100,"findings":[]}
    # Shodan DNS resolve + host lookup
    if SHODAN_KEY:
        try:
            dns = await fetch_json(f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={SHODAN_KEY}")
            ip = (dns or {}).get(domain)
            if ip:
                host = await fetch_json(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}") or {}
                ports = host.get("ports",[])
                vulns = list(host.get("vulns",{}).keys())
                results["shodan"] = {"ip":ip,"ports":ports,"org":host.get("org",""),"vulns":vulns[:10],"open_port_count":len(ports)}
                if len(ports) > 10: results["score"] -= 15; results["findings"].append(f"{len(ports)} open ports detected")
                if vulns: results["score"] -= min(40, len(vulns)*10); results["findings"].append(f"{len(vulns)} CVEs found in Shodan")
        except Exception as e:
            logger.warning(f"Shodan scan: {e}")
    else:
        results["shodan"] = {"status":"key_not_configured","key":"SHODAN_KEY"}
    # HIBP domain breach check
    if HIBP_KEY:
        try:
            data = await fetch_json(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}", headers={"hibp-api-key":HIBP_KEY,"user-agent":"DARKWATCH-Pro"})
            if isinstance(data, dict):
                total = sum(len(v) for v in data.values())
                results["hibp"] = {"breaches":list(data.keys()),"exposed_emails":total}
                if total > 0: results["score"] -= min(30, 10+total//100); results["findings"].append(f"{total} credentials exposed in {len(data)} breach(es)")
        except Exception as e:
            logger.warning(f"HIBP posture: {e}")
    else:
        results["hibp"] = {"status":"key_not_configured","key":"HIBP_KEY"}
    results["score"] = max(0, results["score"])
    results["risk_level"] = "CRITICAL" if results["score"]<40 else "HIGH" if results["score"]<60 else "MEDIUM" if results["score"]<80 else "LOW"
    return results

async def scan_ip_range(ips: List[str]) -> List[Dict[str,Any]]:
    if not SHODAN_KEY:
        return [{"status":"key_not_configured","key":"SHODAN_KEY"}]
    import asyncio
    tasks = [fetch_json(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}") for ip in ips[:10]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out = []
    for ip, r in zip(ips[:10], results):
        if isinstance(r, Exception) or not r:
            out.append({"ip":ip,"error":"not found"})
        else:
            out.append({"ip":ip,"ports":r.get("ports",[]),"org":r.get("org",""),"vulns":list(r.get("vulns",{}).keys())[:5],"os":r.get("os","")})
    return out
