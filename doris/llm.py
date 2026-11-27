"""DeepSeek through the Sprites gateway (OpenAI-compatible chat API)."""

from __future__ import annotations

import os

from . import gateway

MODEL = os.environ.get("DORIS_MODEL", "deepseek-flash")


def deepseek(messages: list[dict], json_mode: bool = False, temperature: float = 0.7) -> str:
    body = {"model": MODEL, "messages": messages, "temperature": temperature,
            "max_tokens": 600}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    r = gateway.call("deepseek", "POST", "/chat/completions", body, timeout=90)
    return r["choices"][0]["message"]["content"]
