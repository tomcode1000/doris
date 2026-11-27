"""Doris's home asks the trap to open a link, through the 'trap-door' connector.

The connector holds the door secret and forwards to the trap's public URL;
the trap checks it against a stored hash, inspects, answers, and rewinds
itself. Nothing here holds a secret.
"""

from __future__ import annotations

import time

from . import gateway
from .rules import link_policy


def wait_until_clean(call=gateway.call, every: float = 10, limit: float = 300,
                     sleep=time.sleep) -> bool:
    """The trap rewinds itself after every visit, which can take a minute or
    two. Ask its /health until it is clean rather than knocking and failing."""
    waited = 0.0
    while waited <= limit:
        try:
            h = call("trapdoor", "GET", "/health", timeout=30)
            if not h.get("dirty") and not h.get("busy"):
                return True
        except gateway.GatewayError:
            pass  # waking up or mid-rewind
        sleep(every)
        waited += every
    return False


def inspect(url: str, canary: tuple[str, str] | None = None, call=gateway.call,
            retries: int = 3, wait: float = 10) -> dict:
    action, why = link_policy(url)
    if action == "refuse":
        return {"input_url": url, "skipped": why}
    if action == "record_only":
        return {"input_url": url, "skipped": why, "download": True}
    body = {"url": url, "canary": list(canary) if canary else None}
    wait_until_clean(call)
    last = None
    for attempt in range(retries):
        try:
            return call("trapdoor", "POST", "/inspect", body, timeout=150)
        except gateway.GatewayError as e:
            last = e
            if e.status not in (429, 502, 503, 504):
                break
            time.sleep(wait * (attempt + 1))  # trap is busy or still rewinding
    return {"input_url": url, "error": f"trap unavailable: {last}"[:200]}
