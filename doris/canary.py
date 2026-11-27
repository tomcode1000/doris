"""Fake details Doris 'falls for it' with.

A canary is a login made up for one scam: an email address that belongs to
Doris and a password that exists nowhere else. If either ever shows up again
(a scammer emails the canary address, or quotes the password), we know which
trap leaked it. Canaries are never card numbers or bank details.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

WORDS = ("marmalade", "teacup", "knitting", "biscuit", "budgie", "doily", "crumpet",
         "slipper", "kettle", "rosebush", "bingo", "cardigan")


@dataclass(frozen=True)
class Canary:
    case_id: str
    token: str
    email: str
    password: str


def make_canary(case_id: str, inbox_local: str, inbox_domain: str, secret: bytes) -> Canary:
    token = hmac.new(secret, case_id.encode(), hashlib.sha256).hexdigest()[:10]
    word = WORDS[int(token[:2], 16) % len(WORDS)]
    password = f"{word.capitalize()}{secrets.randbelow(90) + 10}!{token[-4:]}"
    email = f"{inbox_local}+{token}@{inbox_domain}"
    return Canary(case_id=case_id, token=token, email=email, password=password)


def find_tripped(text: str, canaries: list[Canary]) -> list[Canary]:
    """Canaries whose address token or password appears in this text."""
    low = text.lower()
    return [c for c in canaries if c.token in low or c.password.lower() in low]
