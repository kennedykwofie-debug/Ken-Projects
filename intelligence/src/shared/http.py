import httpx
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
MAX_REDIRECTS = 5


async def get(url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None) -> Any:
    """Fetch URL, auto-detecting JSON vs text response."""
    async with httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=10),
    ) as client:
        resp = await client.get(url, headers=headers or {}, params=params or {})
        resp.raise_for_status()
        ct = resp.headers.get("content-type", "")
        if "json" in ct:
            return resp.json()
        return resp.text


async def get_text(url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None) -> str:
    """Fetch URL and always return raw text."""
    async with httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=10),
    ) as client:
        resp = await client.get(url, headers=headers or {}, params=params or {})
        resp.raise_for_status()
        return resp.text


async def post(url: str, headers: Optional[Dict] = None, json: Optional[Dict] = None) -> Any:
    async with httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
    ) as client:
        resp = await client.post(url, headers=headers or {}, json=json or {})
        resp.raise_for_status()
        return resp.json()
