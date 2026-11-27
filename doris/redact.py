"""Scrub anything personal before it reaches the public diary or docs/runs."""

from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)")
SECRET_RE = re.compile(
    r"\b(sk-[\w-]{10,}|sk_(live|test)_[\w]{10,}|ghp_[\w]{20,}|xox[abp]-[\w-]{10,}|"
    r"Bearer\s+[\w.-]{16,})\b"
)

DORIS_DOMAINS = ("agentmail.to",)


def redact(text: str, keep_doris: bool = True) -> str:
    def email_sub(m: re.Match) -> str:
        addr = m.group(0)
        if keep_doris and addr.lower().endswith(DORIS_DOMAINS):
            return addr
        return "[email]"

    text = SECRET_RE.sub("[secret]", text)
    text = EMAIL_RE.sub(email_sub, text)
    text = PHONE_RE.sub("[phone]", text)
    return text


def redact_obj(obj):
    """Redact every string inside a JSON-like structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
