"""
AI intelligence deduction engine.
Uses Groq (fast LLM inference) to synthesise geo, cyber, and economic signals
into actionable intelligence briefs. Original system prompt — no WM code.
Falls back gracefully if Groq key not configured.
"""

import hashlib
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body
from pydantic import BaseModel, field_validator

from src.shared.cache import cache
from src.shared.config import settings
from src.shared.http import get_json

logger = logging.getLogger(__name__)
router = APIRouter()

_GROQ_BASE = "https://api.groq.com/openai/v1/chat/completions"
_GROQ_HOST = "api.groq.com"
_MODEL = "llama-3.3-70b-versatile"
_MAX_TOKENS = 1024
_CACHE_TTL = 3600  # 1 hour — analysis is expensive

_SYSTEM_PROMPT = """You are DARKWATCH, a senior threat intelligence analyst serving government, \
defence, and enterprise security teams.

Your role: synthesise multi-domain intelligence signals into concise, actionable assessments.

Rules:
- Lead with the most critical threat vector
- Use structured markdown: ## Assessment, ## Key Indicators, ## Recommendations
- Be precise and factual — no speculation beyond what signals support
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
            raise ValueError("Query exceeds maximum length of 1000 characters")
        return v

    @field_validator("context")
    @classmethod
    def validate_context(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()[:3000]  # cap context length
        return v or None


async def _call_groq(query: str, context: Optional[str]) -> Optional[str]:
    if not settings.groq_key:
        return None

    user_content = query
    if context:
        user_content = f"{query}\n\n### Intelligence Context\n{context}"

    try:
        data = await get_json(
            _GROQ_BASE,
            headers={
                "Authorization": f"Bearer {settings.groq_key}",
                "Content-Type": "application/json",
            },
            # POST body via params workaround — use direct httpx for POST
            allowed_host=_GROQ_HOST,
        )
    except Exception:
        pass

    # Use httpx directly for POST
    import httpx
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            resp = await client.post(
                _GROQ_BASE,
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
                    "temperature": 0.3,  # low temp = more factual, less creative
                },
            )
            resp.raise_for_status()
            result = resp.json()
            choices = result.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
    except Exception as e:
        logger.error(f"Groq inference failed: {e}")

    return None


@router.post("/deduct")
async def deduct_situation(req: DeductionRequest = Body(...)) -> Dict[str, Any]:
    """
    AI-powered threat situation deduction.
    Provide a query and optional intelligence context.
    Returns a structured threat assessment with severity rating.
    """
    if not settings.groq_key:
        return {
            "analysis": None,
            "error": "AI inference not configured — set GROQ_KEY environment variable",
            "available": False,
        }

    # Cache by hash of query+context to avoid duplicate LLM calls
    cache_key = f"ai:deduct:{hashlib.sha256((req.query + (req.context or '')).lower().encode()).hexdigest()[:16]}"

    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "cached": True}

    analysis = await _call_groq(req.query, req.context)

    if not analysis:
        return {"analysis": None, "error": "Inference failed", "available": True}

    result = {
        "analysis": analysis,
        "model": _MODEL,
        "query": req.query,
        "cached": False,
        "available": True,
    }

    await cache.set(cache_key, result, _CACHE_TTL)
    return result


@router.get("/status")
async def ai_status() -> Dict[str, Any]:
    """Check AI inference availability."""
    return {
        "available": bool(settings.groq_key),
        "model": _MODEL,
        "provider": "groq",
    }
