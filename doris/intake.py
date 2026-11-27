"""Turn a forwarded scam email into a clean case.

A family member forwards a scam to Doris. The outer message is from the
family member; the scam itself is quoted inside. We need the scammer's
address (who Doris talks to), the links (what the trap opens), and the text,
and we must drop the family member's identity so Doris never leaks it.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"""\bhttps?://[^\s<>"'\)\]]+""", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?'\""

# Lines that start a quoted original in Gmail, Outlook, Apple Mail and Yahoo.
FORWARD_MARKERS = re.compile(
    r"^-{2,}\s*(forwarded message|original message)\s*-{2,}\s*$"
    r"|^begin forwarded message:\s*$",
    re.IGNORECASE | re.MULTILINE,
)
INNER_FROM = re.compile(r"^\s*\*?from:\*?\s*(.+)$", re.IGNORECASE | re.MULTILINE)
INNER_REPLY_TO = re.compile(r"^\s*\*?reply-to:\*?\s*(.+)$", re.IGNORECASE | re.MULTILINE)
INNER_SUBJECT = re.compile(r"^\s*\*?subject:\*?\s*(.+)$", re.IGNORECASE | re.MULTILINE)


@dataclass
class Case:
    forwarder: str  # family member who sent it in (never published)
    scammer: str | None  # address Doris would reply to
    subject: str
    text: str  # scam body with the forwarder's identity removed
    urls: list[str] = field(default_factory=list)
    is_forward: bool = True


class _HrefCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)

    def handle_data(self, data):
        self.text.append(data)


def extract_urls(text: str) -> list[str]:
    """All http(s) links in order of first appearance, without duplicates."""
    seen: dict[str, None] = {}
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(_TRAILING_PUNCT)
        if url and url not in seen:
            seen[url] = None
    return list(seen)


def _body_parts(msg: EmailMessage) -> tuple[str, str]:
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", "replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            plain.append(content)
        elif ctype == "text/html":
            html.append(content)
        elif ctype == "message/rfc822":  # attached original, handled by walk()
            continue
    return "\n".join(plain), "\n".join(html)


def _addr(value: str) -> str | None:
    name, addr = parseaddr(value.strip())
    addr = addr.strip().lower()
    return addr if "@" in addr else None


def scrub_identity(text: str, identifiers: list[str]) -> str:
    """Remove the family member's address and name from the scam text."""
    out = text
    for ident in identifiers:
        if ident and len(ident) >= 3:
            out = re.sub(re.escape(ident), "[family]", out, flags=re.IGNORECASE)
    return out


def parse_forward(raw: bytes | str) -> Case:
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    fwd_name, fwd_addr = parseaddr(str(msg.get("From", "")))
    fwd_addr = fwd_addr.lower()
    outer_subject = str(msg.get("Subject", "")).strip()

    plain, html = _body_parts(msg)
    hrefs: list[str] = []
    if html:
        p = _HrefCollector()
        p.feed(html)
        hrefs = [h for h in p.hrefs if h.lower().startswith(("http://", "https://"))]
        if not plain:
            plain = "".join(p.text)

    # An attached original (message/rfc822) carries real headers: prefer it.
    scammer = None
    subject = re.sub(r"^\s*(fwd?|fw)\s*:\s*", "", outer_subject, flags=re.IGNORECASE)
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            inner = part.get_payload(0) if part.is_multipart() else None
            if inner is not None:
                reply_to = _addr(str(inner.get("Reply-To", "")))
                scammer = reply_to or _addr(str(inner.get("From", "")))
                subject = str(inner.get("Subject", subject)).strip() or subject
                break

    marker = FORWARD_MARKERS.search(plain)
    quoted = plain[marker.end():] if marker else plain
    is_forward = bool(marker) or scammer is not None
    if scammer is None and marker:
        rt = INNER_REPLY_TO.search(quoted)
        fr = INNER_FROM.search(quoted)
        scammer = (_addr(rt.group(1)) if rt else None) or (_addr(fr.group(1)) if fr else None)
        sm = INNER_SUBJECT.search(quoted)
        if sm:
            subject = sm.group(1).strip()
    if scammer == fwd_addr:
        scammer = None  # never treat the family member as the scammer

    identifiers = [fwd_addr, fwd_name.strip()] if fwd_name.strip() else [fwd_addr]
    for _, a in getaddresses([str(msg.get("To", "")), str(msg.get("Cc", ""))]):
        if a and not a.lower().endswith("@agentmail.to"):
            identifiers.append(a.lower())
    text = scrub_identity(quoted.strip(), identifiers)

    urls = extract_urls(plain)
    for h in hrefs:
        if h not in urls:
            urls.append(h)
    return Case(forwarder=fwd_addr, scammer=scammer, subject=subject, text=text,
                urls=urls, is_forward=is_forward)
