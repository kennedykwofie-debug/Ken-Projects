"""Cyber threat aggregator. Merges Feodo, URLhaus, OTX feeds with geo enrichment."""
import asyncio
import logging
from typing import Any, Dict, List, Optional

from src.cyber.feodo import fetch_c2_blocklist
from src.cyber.urlhaus import fetch_malicious_urls
from src.cyber.otx import fetch_threat_pulses
from src.shared.http import get_text

logger = logging.getLogger(__name__)

# Country code -> name mapping for geo enrichment
_CC = {
    "US":"United States","GB":"United Kingdom","DE":"Germany","CN":"China","RU":"Russia",
    "NL":"Netherlands","FR":"France","BR":"Brazil","SG":"Singapore","IN":"India",
    "JP":"Japan","CA":"Canada","AU":"Australia","KR":"South Korea","HK":"Hong Kong",
    "UA":"Ukraine","PL":"Poland","SE":"Sweden","IT":"Italy","ES":"Spain",
    "TR":"Turkey","IR":"Iran","VN":"Vietnam","TH":"Thailand","ID":"Indonesia",
    "NG":"Nigeria","ZA":"South Africa","MX":"Mexico","AR":"Argentina","CZ":"Czech Republic",
    "RO":"Romania","HU":"Hungary","BG":"Bulgaria","LT":"Lithuania","LV":"Latvia",
    "EE":"Estonia","FI":"Finland","NO":"Norway","DK":"Denmark","CH":"Switzerland",
    "AT":"Austria","BE":"Belgium","PT":"Portugal","GR":"Greece","IL":"Israel",
    "SA":"Saudi Arabia","AE":"UAE","PK":"Pakistan","BD":"Bangladesh","PH":"Philippines",
}

# Malware family metadata: description, category, risk
_MALWARE_META = {
    "Emotet":    {"desc":"Banking trojan / malware dropper, spreads via phishing", "cat":"Trojan", "risk":"CRITICAL"},
    "QakBot":    {"desc":"Banking trojan with lateral movement capabilities",       "cat":"Trojan", "risk":"CRITICAL"},
    "Dridex":    {"desc":"Financial malware targeting banking credentials",          "cat":"Trojan", "risk":"CRITICAL"},
    "TrickBot":  {"desc":"Modular banking trojan, often precursor to ransomware",   "cat":"Trojan", "risk":"CRITICAL"},
    "BazarLoader":{"desc":"Stealthy loader used to deploy ransomware payloads",     "cat":"Loader", "risk":"HIGH"},
    "IcedID":    {"desc":"Banking trojan with web injection capabilities",           "cat":"Trojan", "risk":"HIGH"},
    "AsyncRAT":  {"desc":"Remote access trojan with keylogging and screen capture", "cat":"RAT",    "risk":"HIGH"},
    "CobaltStrike":{"desc":"Commercial pen-test tool abused for post-exploitation", "cat":"Toolkit","risk":"CRITICAL"},
    "AgentTesla":{"desc":"Credential stealer targeting emails and browsers",        "cat":"Stealer","risk":"HIGH"},
    "Pikabot":   {"desc":"Modular backdoor with anti-analysis techniques",          "cat":"Backdoor","risk":"HIGH"},
    "Lumma":     {"desc":"Infostealer targeting crypto wallets and credentials",     "cat":"Stealer","risk":"HIGH"},
    "RemcosRAT": {"desc":"Commercial RAT used for surveillance and espionage",      "cat":"RAT",    "risk":"HIGH"},
    "DarkGate":  {"desc":"Multi-function malware loader with RAT capabilities",     "cat":"Loader", "risk":"CRITICAL"},
    "XWorm":     {"desc":"RAT with clipboard hijacking and keylogging",             "cat":"RAT",    "risk":"HIGH"},
    "Unknown":   {"desc":"Unclassified malware family",                             "cat":"Unknown","risk":"MEDIUM"},
}


def _get_ip(record: Dict[str, Any]) -> str:
    return record.get("ip_address") or record.get("ip") or ""


def _get_malware_meta(family: str) -> Dict[str, str]:
    return _MALWARE_META.get(family, _MALWARE_META["Unknown"])


async def _geo_lookup(ip: str) -> Dict[str, Any]:
    """Free geo lookup via ip-api.com (no key needed, 1000/min free)."""
    try:
        raw = await get_text(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting")
        import json
        data = json.loads(raw)
        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", "") or data.get("org", ""),
                "asn": data.get("as", ""),
                "is_proxy": data.get("proxy", False),
                "is_hosting": data.get("hosting", False),
            }
    except Exception as e:
        logger.debug(f"Geo lookup failed for {ip}: {e}")
    return {}


async def _geo_enrich_batch(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enrich up to 20 IPs with geo data concurrently."""
    to_enrich = records[:20]
    ips = [_get_ip(r) for r in to_enrich]
    tasks = [_geo_lookup(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    enriched = []
    for i, r in enumerate(records):
        geo = results[i] if i < len(results) and isinstance(results[i], dict) else {}
        malware = r.get("malware_family") or r.get("malware") or "Unknown"
        meta = _get_malware_meta(malware)
        risk = meta["risk"]
        enriched.append({
            **r,
            "ip": _get_ip(r),
            "ip_address": _get_ip(r),
            "malware": malware,
            "malware_family": malware,
            "malware_desc": meta["desc"],
            "malware_cat": meta["cat"],
            "severity": risk,
            "threat_score": 90 if risk == "CRITICAL" else 75 if risk == "HIGH" else 50,
            "country": geo.get("country", ""),
            "country_code": geo.get("country_code", ""),
            "region": geo.get("region", ""),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", ""),
            "asn": geo.get("asn", ""),
            "is_proxy": geo.get("is_proxy", False),
            "is_hosting": geo.get("is_hosting", False),
        })
    return enriched


def _deduplicate_c2(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    result = []
    for r in records:
        ip = _get_ip(r)
        if ip and ip not in seen:
            seen.add(ip)
            result.append(r)
        elif not ip:
            result.append(r)
    return result


async def build_threat_summary() -> Dict[str, Any]:
    feodo, urlhaus, otx = await asyncio.gather(
        fetch_c2_blocklist(),
        fetch_malicious_urls(),
        fetch_threat_pulses(),
        return_exceptions=True,
    )

    c2_records: List[Dict[str, Any]] = feodo if isinstance(feodo, list) else []
    malware_urls: List[Dict[str, Any]] = urlhaus if isinstance(urlhaus, list) else []
    pulses: List[Dict[str, Any]] = otx if isinstance(otx, list) else []

    logger.info(f"Feeds raw: feodo={len(c2_records)} urlhaus={len(malware_urls)} otx={len(pulses)}")

    c2_records = _deduplicate_c2(c2_records)

    # Geo-enrich C2 servers
    enriched_c2 = await _geo_enrich_batch(c2_records)
    enriched_c2.sort(key=lambda r: r.get("threat_score", 0), reverse=True)

    # Enrich URLhaus domains
    enriched_urls = []
    for r in malware_urls:
        enriched_urls.append({
            **r,
            "url": r.get("url", ""),
            "domain": r.get("domain", ""),
            "threat": r.get("threat", "malware_download"),
            "tags": r.get("tags", []),
            "date_added": r.get("date_added", ""),
            "source": "urlhaus",
        })

    critical_count = sum(1 for r in enriched_c2 if r.get("severity") == "CRITICAL")
    high_count = sum(1 for r in enriched_c2 if r.get("severity") == "HIGH")
    families = list({r.get("malware_family","") for r in enriched_c2 if r.get("malware_family") and r.get("malware_family") != "Unknown"})

    return {
        "c2_servers": enriched_c2[:200],
        "malware_domains": enriched_urls[:200],
        "threat_pulses": pulses[:50],
        "summary": {
            "total_c2_servers": len(enriched_c2),
            "critical": critical_count,
            "high": high_count,
            "malware_families": families[:20],
            "active_pulse_count": len(pulses),
            "malware_domain_count": len(enriched_urls),
        },
    }
