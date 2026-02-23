"""AI-powered scan result analysis using DeepSeek (Claude Haiku as fallback).

Fase 0: module present and ready; called optionally when AI keys are configured.
Fase 2+: integrated into Monitor tier alerts and deep-scan narrative summaries.

Follows the same DeepSeek-primary / Claude-fallback pattern as SecurityScan API.
"""

import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from app.config import get_settings
from app.models.scan import EndpointResult

logger = logging.getLogger(__name__)

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"

MAX_RETRIES = 2

ANALYSIS_PROMPT = """You are a security analyst reviewing the health of AI agent skill dependencies.

Scan results (JSON):
{scan_json}

Write a concise (2-4 sentences) risk assessment for an AI agent deciding whether to install this skill.
Focus on actionable findings: what is risky, why, and what action to take.
Reply in JSON: {{"summary": "...", "key_risk": "...", "action": "PROCEED|REVIEW|BLOCK"}}"""


class DeepSeekInsightGenerator:
    """Generates natural-language insight from scan results using DeepSeek."""

    def __init__(self):
        settings = get_settings()
        self.api_key = settings.deepseek_api_key
        self.fallback_key = settings.anthropic_api_key

    def is_available(self) -> bool:
        return bool(self.api_key) or bool(self.fallback_key)

    async def analyze(
        self,
        endpoints: List[EndpointResult],
        overall_score: int,
        scan_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Return insight dict or None if no AI key is configured / all attempts fail."""
        if not self.is_available():
            return None

        scan_summary = {
            "scan_id": scan_id,
            "overall_score": overall_score,
            "endpoints": [
                {
                    "url": r.url,
                    "status": r.status,
                    "score": r.score,
                    "flags": r.flags,
                    "ssl_expires_days": r.ssl_expires_days,
                    "in_blacklist": r.in_blacklist,
                }
                for r in endpoints
            ],
        }
        prompt = ANALYSIS_PROMPT.format(scan_json=json.dumps(scan_summary, indent=2))

        if self.api_key:
            result = await self._call_deepseek(prompt)
            if result is not None:
                return result
            logger.warning("DeepSeek insight failed; trying Claude fallback")

        if self.fallback_key:
            return await self._call_claude(prompt)

        return None

    async def _call_deepseek(self, prompt: str) -> Optional[Dict[str, Any]]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": DEEPSEEK_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 256,
            "temperature": 0.2,
        }
        for attempt in range(MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=20) as client:
                    resp = await client.post(DEEPSEEK_API_URL, headers=headers, json=payload)
                    resp.raise_for_status()
                    content = resp.json()["choices"][0]["message"]["content"].strip()
                    return self._parse_json(content)
            except httpx.HTTPStatusError as e:
                logger.error(f"DeepSeek insights HTTP {e.response.status_code} (attempt {attempt+1})")
                raise  # let caller decide on fallback
            except Exception as e:
                logger.warning(f"DeepSeek insights error (attempt {attempt+1}): {e}")
        return None

    async def _call_claude(self, prompt: str) -> Optional[Dict[str, Any]]:
        headers = {
            "x-api-key": self.fallback_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": ANTHROPIC_MODEL,
            "max_tokens": 256,
            "system": "You are a security analyst. Reply only with valid JSON.",
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(ANTHROPIC_API_URL, headers=headers, json=payload)
                resp.raise_for_status()
                content = resp.json()["content"][0]["text"].strip()
                return self._parse_json(content)
        except Exception as e:
            logger.error(f"Claude fallback insights error: {e}")
            return None

    @staticmethod
    def _parse_json(text: str) -> Optional[Dict[str, Any]]:
        # Strip markdown fences if present
        for fence in ("```json", "```"):
            if text.startswith(fence):
                text = text[len(fence):]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        try:
            result, _ = json.JSONDecoder().raw_decode(text)
            return result
        except json.JSONDecodeError as e:
            logger.error(f"AI insights JSON parse error: {e}")
            return None


# Module-level singleton
_generator: Optional[DeepSeekInsightGenerator] = None


def get_insight_generator() -> DeepSeekInsightGenerator:
    global _generator
    if _generator is None:
        _generator = DeepSeekInsightGenerator()
    return _generator
