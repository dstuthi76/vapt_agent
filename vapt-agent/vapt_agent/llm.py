"""Pluggable LLM client (Anthropic, OpenAI-compatible, Ollama, or none).

The LLM is used for: understanding the analyst's request, ranking/justifying candidate
actions produced by the rule engine, answering questions about the assessment, and
writing narrative text for the report. It NEVER creates findings, CVEs, CVSS scores,
targets or tools: every LLM output is validated against evidence before use, and any
text it writes is labelled as AI-generated inference."""
from __future__ import annotations

import json
import re
from typing import Optional

import requests

from . import config
from .knowledge import extract_cves


class LLM:
    def __init__(self):
        self.provider = config.LLM_PROVIDER
        self.last_error: Optional[str] = None

    @property
    def enabled(self) -> bool:
        if self.provider == "anthropic":
            return bool(config.ANTHROPIC_API_KEY)
        if self.provider == "openai":
            return bool(config.OPENAI_API_KEY)
        return self.provider == "ollama"

    def describe(self) -> str:
        if not self.enabled:
            return "rule-engine only (no LLM configured)"
        model = {"anthropic": config.ANTHROPIC_MODEL, "openai": config.OPENAI_MODEL,
                 "ollama": config.OLLAMA_MODEL}[self.provider]
        return f"{self.provider}:{model}"

    def chat(self, system: str, user: str, max_tokens: int = 1200) -> Optional[str]:
        if not self.enabled:
            return None
        try:
            if self.provider == "anthropic":
                r = requests.post("https://api.anthropic.com/v1/messages", timeout=config.LLM_TIMEOUT, headers={
                    "x-api-key": config.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                    "content-type": "application/json"}, json={
                    "model": config.ANTHROPIC_MODEL, "max_tokens": max_tokens, "system": system,
                    "messages": [{"role": "user", "content": user}]})
                r.raise_for_status()
                return "".join(b.get("text", "") for b in r.json()["content"])
            if self.provider == "openai":
                r = requests.post(f"{config.OPENAI_BASE_URL}/chat/completions", timeout=config.LLM_TIMEOUT,
                                  headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}"}, json={
                    "model": config.OPENAI_MODEL, "max_tokens": max_tokens, "temperature": 0.1,
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
            if self.provider == "ollama":
                r = requests.post(f"{config.OLLAMA_URL}/api/chat", timeout=config.LLM_TIMEOUT * 3, json={
                    "model": config.OLLAMA_MODEL, "stream": False, "options": {"temperature": 0.1},
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
                    proxies={"http": None, "https": None})
                r.raise_for_status()
                return r.json()["message"]["content"]
        except Exception as e:  # LLM failure must never break the assessment
            self.last_error = f"{type(e).__name__}: {str(e)[:200]}"
        return None

    def chat_json(self, system: str, user: str, max_tokens: int = 1200) -> Optional[dict]:
        txt = self.chat(system + "\nRespond with ONLY a JSON object, no prose.", user, max_tokens)
        if not txt:
            return None
        m = re.search(r"\{.*\}", txt, re.S)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


def ground_text(text: str, allowed_cves: set[str]) -> tuple[str, list[str]]:
    """Remove any CVE id the LLM mentions that is not present in tool evidence."""
    removed = []
    for c in extract_cves(text):
        if c not in allowed_cves:
            removed.append(c)
            text = re.sub(re.escape(c), "[unverified reference removed]", text, flags=re.I)
    return text, removed


llm = LLM()
