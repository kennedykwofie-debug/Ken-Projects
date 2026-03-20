"""Redis cache client."""
import os, json
from typing import Optional, Any
import redis.asyncio as aioredis

REDIS_URL = os.getenv("REDIS_URL", "")
_client = None

async def _get_client():
    global _client
    if not REDIS_URL:
        return None
    if not _client:
        _client = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return _client


class CacheClient:
    """Async cache client compatible with .get() / .set() / .delete() interface."""

    async def get(self, key: str) -> Optional[Any]:
        client = await _get_client()
        if not client:
            return None
        try:
            value = await client.get(key)
            return json.loads(value) if value else None
        except Exception:
            return None

    async def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        client = await _get_client()
        if not client:
            return False
        try:
            await client.set(key, json.dumps(value), ex=ttl)
            return True
        except Exception:
            return False

    async def delete(self, key: str) -> bool:
        client = await _get_client()
        if not client:
            return False
        try:
            await client.delete(key)
            return True
        except Exception:
            return False


# Singleton instance used by routers: from src.shared.cache import cache
cache = CacheClient()

# Backwards-compat helpers
async def cache_get(key: str) -> Optional[Any]:
    return await cache.get(key)

async def cache_set(key: str, value: Any, ttl: int = 300) -> bool:
    return await cache.set(key, value, ttl)

async def cache_delete(key: str) -> bool:
    return await cache.delete(key)
