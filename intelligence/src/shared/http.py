import httpx
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0
MAX_REDIRECTS = 0


async def get(url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None) -> Any:
    async with httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=10),
    ) as client:
        resp = await client.get(url, headers=headers or {}, params=params or {})
        resp.raise_for_status()
        return resp.json()


async def post(url: str, headers: Optional[Dict] = None, json: Optional[Dict] = None) -> Any:
    async with httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=False,
    ) as client:
        resp = await client.post(url, headers=headers or {}, json=json or {})
        resp.raise_for_status()
        return resp.json()
