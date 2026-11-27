"""Hard rules. Nothing Doris does gets past these, whatever the model says.

The model (Jev for decisions, an LLM for Doris's voice) proposes; these
functions decide. Every rule has tests in tests/test_rules.py.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlsplit

ENGAGE_MIN_P_SCAM = 0.85  # Doris only talks to senders Jev is this sure are scammers
REPLY_GAP = timedelta(hours=4)  # at most one reply per thread every 4 hours
MAX_REPLIES_PER_THREAD = 12
MAX_REPLIES_PER_DAY = 40

# Never reply into these: a spoofed "From" on a real institution would mean
# Doris pesters the real bank or government, not the scammer.
PROTECTED_SUFFIXES = (".gov", ".mil", ".edu", ".gov.uk", ".gov.ng", ".police.uk", ".int")
DOWNLOAD_EXTENSIONS = (
    ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".apk",
    ".dmg", ".pkg", ".iso", ".img", ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm",
)
THREAT_WORDS = re.compile(
    r"\b(kill|hurt|harm|shoot|bomb|hack (you|your)|i know where you live|"
    r"i will find you|dox)\b",
    re.IGNORECASE,
)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}\b")
DIGIT_RUN = re.compile(r"(?:\d[ -]?){13,19}")


@dataclass
class Verdict:
    label: str  # "scam" | "suspicious" | "safe"
    p_scam: float
    reasons: list[str] = field(default_factory=list)


@dataclass
class Thread:
    scammer: str
    replies_sent: int = 0
    last_reply_at: datetime | None = None


def may_engage(v: Verdict) -> bool:
    """Doris plays along only with confirmed scams. Suspicious is not enough."""
    return v.label == "scam" and v.p_scam >= ENGAGE_MIN_P_SCAM


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(".")


def may_reply_to(addr: str | None, family: set[str]) -> tuple[bool, str]:
    if not addr or "@" not in addr:
        return False, "no reply address"
    addr = addr.lower()
    if addr in {f.lower() for f in family}:
        return False, "address belongs to the family"
    dom = _domain(addr)
    if any(dom == s.lstrip(".") or dom.endswith(s) for s in PROTECTED_SUFFIXES):
        return False, f"protected domain {dom}"
    if addr.startswith(("no-reply", "noreply", "donotreply", "mailer-daemon", "postmaster")):
        return False, "automated mailbox"
    return True, "ok"


def reply_budget_ok(t: Thread, now: datetime, sent_today: int) -> tuple[bool, str]:
    if sent_today >= MAX_REPLIES_PER_DAY:
        return False, "daily reply cap reached"
    if t.replies_sent >= MAX_REPLIES_PER_THREAD:
        return False, "thread reply cap reached"
    if t.last_reply_at and now - t.last_reply_at < REPLY_GAP:
        return False, "too soon since last reply"
    return True, "ok"


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def outgoing_text_problems(text: str, family_identifiers: list[str]) -> list[str]:
    """Reasons this reply must not be sent. Empty list means it may go."""
    problems = []
    for run in DIGIT_RUN.findall(text):
        digits = re.sub(r"\D", "", run)
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            problems.append("contains a card-like number")
            break
    if IBAN_RE.search(text):
        problems.append("contains a bank account number (IBAN)")
    if THREAT_WORDS.search(text):
        problems.append("contains threatening language")
    low = text.lower()
    for ident in family_identifiers:
        if ident and len(ident) >= 3 and ident.lower() in low:
            problems.append("mentions the family")
            break
    if len(text) > 4000:
        problems.append("too long")
    return problems


def link_policy(url: str) -> tuple[str, str]:
    """What the trap may do with a link: 'open', 'record_only' or 'refuse'."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "refuse", "unparseable"
    if parts.scheme not in ("http", "https"):
        return "refuse", f"scheme {parts.scheme or 'none'}"
    host = (parts.hostname or "").lower()
    if not host:
        return "refuse", "no host"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return "refuse", "private address"
    except ValueError:
        if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
            return "refuse", "local host name"
    if parts.path.lower().endswith(DOWNLOAD_EXTENSIONS):
        return "record_only", "file download: hashed, never run"
    return "open", "ok"


def defang(url: str) -> str:
    """Make a scam link safe to publish (not clickable)."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")
