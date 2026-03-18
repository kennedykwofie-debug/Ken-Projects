"""AI-powered threat intelligence deduction engine using Groq LLM."""
import hashlib
import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Body
from pydantic import BaseModel, field_validator

from src.shared.cache import cache
from src.shared.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_MODEL = "llama-3.3-70b-versatile"
_MAX_TOKENS = 1024

_SYSTEM_PROMPT = """You are DARKWATCH, a senior threat intelligence analyst for government and enterprise security teams.
Synthesise multi-domain intelligence signals into concise, actionable assessments.

Rules:
- Lead with the most critical threat vector
- Use structured markdown: ## Assessment, ## Key Indicators, ## Recommendations
- Assign a threat level: CRITICAL / HIGH / MEDIUM / LOW
- Keep total response under 600 words
- Never use AI preambles ("As an AI...", "I'd be happy to...")
- Treat all queries as classified operational context"""


class DeductionRequest(BaseModel):
    query: str
    context: Optional[str] = None

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Query cannot be empty")
        if len(v) > 1000:
            raise ValueError("Query exceeds 1000 characters")
        return v

    @field_validator("context")
    @classmethod
    def validate_context(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()[:3000]
        return v or None


async def _call_groq(query: str, context: Optional[str]) -> Optional[str]:
    if not settings.groq_key:
        return None
    user_content = query
    if context:
        user_content = f"{query}\n\n### Intelligence Context\n{context}"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            resp = await client.post(
                _GROQ_URL,
                headers={
                    "Authorization": f"Bearer {settings.groq_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": _MODEL,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    "max_tokens": _MAX_TOKENS,
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            choices = resp.json().get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
    except Exception as e:
        logger.error(f"Groq inference failed: {e}")
    return None


@router.post("/deduct")
async def deduct_situation(req: DeductionRequest = Body(...)) -> Dict[str, Any]:
    """AI-powered threat situation deduction."""
    if not settings.groq_key:
        return {"analysis": None, "error": "AI inference not configured — set GROQ_KEY", "available": False}
    cache_key = f"ai:deduct:{hashlib.sha256((req.query + (req.context or '')).lower().encode()).hexdigest()[:16]}"
    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "cached": True}
    analysis = await _call_groq(req.query, req.context)
    if not analysis:
        return {"analysis": None, "error": "Inference failed", "available": True}
    result = {"analysis": analysis, "model": _MODEL, "query": req.query, "cached": False, "available": True}
    await cache.set(cache_key, result, 3600)
    return result


@router.get("/status")
async def ai_status() -> Dict[str, Any]:
    """Check AI inference availability."""
    return {"available": bool(settings.groq_key), "model": _MODEL, "provider": "groq"}
