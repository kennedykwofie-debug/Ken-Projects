"""Shared HTTP client utilities."""
import asyncio
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
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=merged_headers, params=params)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        print(f"HTTP error {e.response.status_code} for {url}")
        return None
    except Exception as e:
        print(f"Request failed for {url}: {e}")
        return None


async def fetch_text(
    url: str,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[str]:
    """Async GET request returning raw text or None on error."""
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=merged_headers, params=params)
            response.raise_for_status()
            return response.text
    except Exception as e:
        print(f"Request failed for {url}: {e}")
        return None
