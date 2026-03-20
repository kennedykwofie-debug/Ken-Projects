"""Shared HTTP client utilities."""
import asyncio
from typing import Optional,Any
import httpx

DEFAULT_TIMEOUT=15.0
DEFAULT_HEADERS={"User-Agent":"DARKWATCH-Intelligence/2.0","Accept":"application/json"}

async def fetch_json(url,headers=None,params=None,timeout=DEFAULT_TIMEOUT):
    h={**DEFAULT_HEADERS,**(headers or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r=await client.get(url,headers=h,params=params)
            r.raise_for_status()
            return r.json()
    except httpx.HTTPStatusError as e:print(f"HTTP error {e.response.status_code} for {url}");return None
    except Exception as e:print(f"Request failed for {url}: {e}");return None

async def fetch_text(url,headers=None,params=None,timeout=DEFAULT_TIMEOUT):
    h={**DEFAULT_HEADERS,**(headers or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r=await client.get(url,headers=h,params=params)
            r.raise_for_status()
            return r.text
    except Exception as e:print(f"Request failed for {url}: {e}");return None
