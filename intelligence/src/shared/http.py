"""Shared HTTP client utilities."""
from typing import Optional, Any
import httpx

DEFAULT_TIMEOUT = 15.0
DEFAULT_HEADERS = {
    "User-Agent": "DARKWATCH-Intelligence/2.0",
    "Accept": "application/json",
}


async def fetch_json(
    url: str,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[Any]:
    """Async GET request returning parsed JSON or None on error."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers=merged, params=params)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        print(f"fetch_json error for {url}: {e}")
        return None


async def fetch_text(
    url: str,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[str]:
    """Async GET request returning raw text or None on error."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers=merged, params=params)
            r.raise_for_status()
            return r.text
    except Exception as e:
        print(f"fetch_text error for {url}: {e}")
        return None


# Aliases used by existing modules
get = fetch_json        # used by otx.py, enrichment.py, finnhub.py, fred.py
get_text = fetch_text   # used by feodo.py, urlhaus.py
