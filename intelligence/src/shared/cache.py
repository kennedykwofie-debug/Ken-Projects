import time
from typing import Any, Optional
import logging

logger = logging.getLogger(__name__)


class InMemoryCache:
    def __init__(self):
        self._store: dict = {}
        self._expiry: dict = {}

    async def init(self):
        logger.info("Cache initialised (in-memory)")

    async def close(self):
        self._store.clear()
        self._expiry.clear()

    def _is_expired(self, key: str) -> bool:
        exp = self._expiry.get(key)
        return exp is not None and time.time() > exp

    async def get(self, key: str) -> Optional[Any]:
        if key not in self._store or self._is_expired(key):
            self._store.pop(key, None)
            return None
        return self._store[key]

    async def set(self, key: str, value: Any, ttl: int = 300):
        self._store[key] = value
        self._expiry[key] = time.time() + ttl

    async def delete(self, key: str):
        self._store.pop(key, None)
        self._expiry.pop(key, None)


cache = InMemoryCache()
