"""Report confirmed phishing pages to Netcraft for takedown, and check back.

Netcraft's public reporting API (no key):
  POST https://report.netcraft.com/api/v3/report/urls {"email", "urls": [{"url", "reason"}]}
  GET  https://report.netcraft.com/api/v3/submission/<uuid>
Doris reports under her own address, never the family's.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .rules import LEGIT_SITES, base_domain, link_policy

API = "https://report.netcraft.com/api/v3"


def worth_reporting(record: dict) -> tuple[bool, str]:
    """Only pages the trap actually saw asking for secrets, on the scam's own site."""
    from urllib.parse import urlsplit
    if record.get("skipped") or record.get("error"):
        return False, "trap could not inspect it"
    final = record.get("final_url") or ""
    if link_policy(final)[0] != "open":
        return False, "final page not a normal web page"
    host = urlsplit(final).hostname or ""
    if base_domain(host) in LEGIT_SITES:
        return False, f"ended on real site {base_domain(host)}"
    if not set(record.get("asks_for") or []) & {"password", "card", "bank", "identity", "otp"}:
        return False, "page did not ask for anything sensitive"
    return True, "asks for " + ", ".join(sorted(set(record["asks_for"]) &
                                                {"password", "card", "bank", "identity", "otp"}))


def _post(path: str, body: dict, timeout=30) -> dict:
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "doris-scam-agent"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode("utf-8", "replace")[:300]}


def report(url: str, reason: str, reporter: str, post=_post) -> dict:
    return post("/report/urls", {"email": reporter, "urls": [{"url": url, "reason": reason[:500]}]})


def status(uuid: str, timeout=30) -> dict:
    req = urllib.request.Request(f"{API}/submission/{uuid}", headers={"User-Agent": "doris-scam-agent"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"error": e.code}
