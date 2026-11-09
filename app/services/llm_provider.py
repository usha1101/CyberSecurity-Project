import json
import logging
import re
from typing import Dict, Any, Optional, Tuple, List
import httpx
from groq import AsyncGroq, RateLimitError, APIStatusError
from google import genai
from app.config import settings

logger = logging.getLogger("zeroguard.llm")


class LLMService:
    """Manages multi-provider LLM integrations with non-blocking execution and graceful fallback."""

    def __init__(self):
        self.groq_client: Optional[AsyncGroq] = None
        self.gemini_client: Optional[genai.Client] = None

        if settings.GROQ_API_KEY:
            try:
                self.groq_client = AsyncGroq(api_key=settings.GROQ_API_KEY)
            except Exception as e:
                logger.warning(f"Could not initialize Groq client: {e}")

        if settings.GEMINI_API_KEY:
            try:
                self.gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY)
            except Exception as e:
                logger.warning(f"Could not initialize Gemini client: {e}")

    def get_provider_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Returns readiness status for all free-tier providers."""
        return {
            "groq": {
                "name": "Groq Cloud (Free Tier)",
                "model": settings.GROQ_MODEL,
                "configured": bool(settings.GROQ_API_KEY and len(settings.GROQ_API_KEY) > 10),
                "is_primary": settings.LLM_PROVIDER == "groq",
            },
            "gemini": {
                "name": "Google Gemini (Free Tier)",
                "model": settings.GEMINI_MODEL,
                "configured": bool(settings.GEMINI_API_KEY and len(settings.GEMINI_API_KEY) > 10),
                "is_primary": settings.LLM_PROVIDER == "gemini",
            },
            "ollama": {
                "name": "Ollama Local Fallback",
                "model": settings.OLLAMA_MODEL,
                "endpoint": settings.OLLAMA_BASE_URL,
                "configured": True,  # Available locally
                "is_primary": settings.LLM_PROVIDER == "ollama",
            },
        }

    async def _is_ollama_reachable(self) -> bool:
        """Quick 300ms health probe to see if local Ollama daemon is active."""
        try:
            async with httpx.AsyncClient(timeout=0.3) as client:
                resp = await client.get(settings.OLLAMA_BASE_URL.rstrip("/"))
                return resp.status_code in (200, 404)
        except Exception:
            return False

    async def generate_security_analysis(
        self,
        system_prompt: str,
        user_prompt: str,
        preferred_provider: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """
        Executes non-blocking LLM inference.
        Returns: (raw_json_response, provider_used, model_used)
        """
        active_provider = preferred_provider or settings.LLM_PROVIDER

        # Define priority order for fallback
        order = [active_provider]
        for p in ["groq", "gemini", "ollama"]:
            if p not in order:
                order.append(p)

        last_error = None
        for prov in order:
            try:
                if prov == "groq" and self._is_groq_ready():
                    logger.info("Dispatching semantic reasoning request to Groq Cloud...")
                    response_text = await self._call_groq(system_prompt, user_prompt)
                    return response_text, "groq", settings.GROQ_MODEL

                elif prov == "gemini" and self._is_gemini_ready():
                    logger.info("Dispatching semantic reasoning request to Google Gemini...")
                    response_text = await self._call_gemini(system_prompt, user_prompt)
                    return response_text, "gemini", settings.GEMINI_MODEL

                elif prov == "ollama" and (active_provider == "ollama" or await self._is_ollama_reachable()):
                    logger.info("Attempting local Ollama inference...")
                    response_text = await self._call_ollama(system_prompt, user_prompt)
                    if response_text:
                        return response_text, "ollama", settings.OLLAMA_MODEL

            except RateLimitError as rle:
                logger.warning(
                    f"Groq API Rate Limit (HTTP 429) encountered: {rle}. "
                    "Automatically failing over to alternative cloud provider (Google Gemini)..."
                )
                last_error = rle
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    logger.warning(f"Provider '{prov}' rate limited (HTTP 429): {e}. Failing over to alternative provider...")
                else:
                    logger.warning(f"Provider '{prov}' execution failed: {str(e)}. Proceeding to fallback...")
                last_error = e

        # If all free cloud and local LLM endpoints are unavailable (e.g. offline dev test or missing keys),
        # return structured fallback synthesized from deterministic AST triage to keep backend completely functional.
        logger.info("No active cloud/local LLM keys available. Utilizing built-in heuristic security analyzer.")
        return "", "heuristic_fallback", "deterministic-appsec-v1"

    def _is_groq_ready(self) -> bool:
        return bool(settings.GROQ_API_KEY and len(settings.GROQ_API_KEY.strip()) > 5)

    def _is_gemini_ready(self) -> bool:
        return bool(settings.GEMINI_API_KEY and len(settings.GEMINI_API_KEY.strip()) > 5)

    async def _call_groq(self, system_prompt: str, user_prompt: str) -> str:
        """Invokes Groq API with JSON mode enabled and automatic model fallback."""
        if not self.groq_client or getattr(self.groq_client, "api_key", None) != settings.GROQ_API_KEY:
            self.groq_client = AsyncGroq(api_key=settings.GROQ_API_KEY)

        models_to_try = [settings.GROQ_MODEL]
        for alt_model in ["qwen/qwen3.8-27b", "openai/gpt-oss-120b", "openai/gpt-oss-20b"]:
            if alt_model not in models_to_try:
                models_to_try.append(alt_model)

        last_groq_err = None
        for model_candidate in models_to_try:
            try:
                completion = await self.groq_client.chat.completions.create(
                    model=model_candidate,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    max_tokens=4096,
                )
                return completion.choices[0].message.content or "{}"
            except RateLimitError as rle:
                # Immediate 429 rate limit escalation to next provider (Gemini)
                raise rle
            except Exception as e:
                if "429" in str(e):
                    raise RateLimitError(message="Rate limit (HTTP 429) on Groq", response=None, body=None)
                if "model_not_found" in str(e) or "404" in str(e):
                    logger.info(f"Groq model '{model_candidate}' unavailable on this tier. Attempting '{models_to_try[-1]}'")
                    last_groq_err = e
                    continue
                raise e

        if last_groq_err:
            raise last_groq_err
        return "{}"

    async def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        """Invokes Google Gemini via google-genai async client."""
        if not self.gemini_client or getattr(self.gemini_client, "_api_key", None) != settings.GEMINI_API_KEY:
            self.gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY)
            self.gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY)

        combined_prompt = f"{system_prompt}\n\nStrictly output valid JSON only.\n\nUser Code & Analysis Target:\n{user_prompt}"

        response = await self.gemini_client.aio.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=combined_prompt,
        )
        return response.text or "{}"

    async def _call_ollama(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Calls local Ollama API via OpenAI-compatible endpoint with fast connect timeout."""
        endpoint = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/chat/completions"
        payload = {
            "model": settings.OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1},
        }

        timeout_config = httpx.Timeout(15.0, connect=2.0)
        try:
            async with httpx.AsyncClient(timeout=timeout_config) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.debug(f"Ollama connection attempt failed: {e}")
            return None
        return None

    @staticmethod
    def extract_clean_json(text: str) -> Dict[str, Any]:
        """Robustly extracts and parses JSON even if wrapped in markdown code blocks."""
        text = text.strip()
        if not text:
            return {}

        # 1. Try direct json load
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Try regex extraction from ```json ... ``` or ``` ... ```
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # 3. Find outermost { ... }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass

        return {}


llm_service = LLMService()
