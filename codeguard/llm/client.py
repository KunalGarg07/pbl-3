"""Pluggable LLM clients. The default is a local Ollama model, so submitted code never leaves the machine."""
import json
from dataclasses import dataclass

import requests

from codeguard.config import settings


class LLMUnavailable(RuntimeError):
    """No LLM is configured or reachable. Explanations fall back to retrieval-only mode."""


@dataclass
class LLMReply:
    text: str
    provider: str
    model: str
    seconds: float


class OllamaClient:
    provider = "ollama"

    def __init__(self, model: str | None = None, url: str | None = None, timeout_s: int | None = None):
        self.model = model or settings.ollama_model
        self.url = (url or settings.ollama_url).rstrip("/")
        self.timeout_s = timeout_s or settings.llm_timeout_s

    def available(self) -> bool:
        try:
            tags = requests.get(f"{self.url}/api/tags", timeout=3).json()
        except (requests.RequestException, ValueError):
            return False
        names = {m.get("name", "") for m in tags.get("models", [])}
        return any(n == self.model or n.split(":")[0] == self.model for n in names)

    def generate_json(self, system: str, prompt: str, max_tokens: int = 900) -> LLMReply:
        payload = {
            "model": self.model, "stream": False, "format": "json",
            "options": {"temperature": 0.1, "num_predict": max_tokens, "num_ctx": 8192},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        try:
            response = requests.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout_s)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise LLMUnavailable(f"Ollama request failed: {exc}") from exc
        return LLMReply(data["message"]["content"], self.provider, self.model,
                        data.get("total_duration", 0) / 1e9)


class AnthropicClient:
    """Optional hosted model. Needs ANTHROPIC_API_KEY in .env; submitted code is sent to the API."""
    provider = "anthropic"

    def __init__(self, model: str | None = None):
        self.model = model or settings.anthropic_model

    def available(self) -> bool:
        import os
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return bool(os.getenv("ANTHROPIC_API_KEY"))

    def generate_json(self, system: str, prompt: str, max_tokens: int = 900) -> LLMReply:
        import time
        import anthropic
        started = time.time()
        try:
            message = anthropic.Anthropic().messages.create(
                model=self.model, max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": prompt + "\n\nRespond with the JSON object only."}],
            )
        except anthropic.APIError as exc:
            raise LLMUnavailable(f"Anthropic request failed: {exc}") from exc
        text = "".join(block.text for block in message.content if block.type == "text")
        return LLMReply(text, self.provider, self.model, time.time() - started)


def get_client(provider: str | None = None):
    provider = (provider or settings.llm_provider).lower()
    if provider == "none":
        raise LLMUnavailable("LLM disabled (CODEGUARD_LLM_PROVIDER=none)")
    client = {"ollama": OllamaClient, "anthropic": AnthropicClient}.get(provider)
    if client is None:
        raise LLMUnavailable(f"Unknown LLM provider '{provider}'")
    instance = client()
    if not instance.available():
        raise LLMUnavailable(f"{provider} model '{instance.model}' is not available")
    return instance


def parse_json_object(text: str) -> dict:
    """Parse the first JSON object in a reply (models sometimes wrap it in prose or code fences)."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise
