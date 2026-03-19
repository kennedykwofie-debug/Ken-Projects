"""Redis cache utilities."""
import os
import json
from typing import Optional, Any
import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL", "")
_redis_client = None


async def get_redis():
    global _redis_client
    if not REDIS_URL:
        return None
    if not _redis_client:
        _redis_client = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return _redis_client


async def cache_get(key: str) -> Optional[Any]:
    client = await get_redis()
    if not client:
        return None
    try:
        value = await client.get(key)
        return json.loads(value) if value else None
    except Exception:
        return None


async def cache_set(key: str, value: Any, ttl: int = 300) -> bool:
    client = await get_redis()
    if not client:
        return False
    try:
        await client.set(key, json.dumps(value), ex=ttl)
        return True
    except Exception:
        return False


async def cache_delete(key: str) -> bool:
    client = await get_redis()
    if not client:
        return False
    try:
        await client.delete(key)
        return True
    except Exception:
        return False
