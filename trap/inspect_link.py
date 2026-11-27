"""Runs INSIDE the trap Sprite. Opens one link the way a victim would and
records what the trap is: where it really leads, what it asks for, where it
is hosted. Never downloads or runs files. Prints one JSON object.

Usage: python inspect_link.py <url> [--fill-canary email password]
"""

import base64
import json
import socket
import sys
import time
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

NAV_TIMEOUT_MS = 20000
SENSITIVE = {
    "password": ("password", "passwd", "pass", "pin", "passcode"),
    "card": ("card", "cc-number", "cardnumber", "cvv", "cvc", "expiry", "exp"),
    "bank": ("iban", "sort", "routing", "account"),
    "identity": ("ssn", "dob", "birth", "passport", "bvn", "nin", "mother"),
    "otp": ("otp", "code", "token", "2fa", "verification"),
    "email": ("email", "e-mail", "username", "login", "user"),
    "phone": ("phone", "mobile", "tel"),
}


def classify_field(attrs: dict) -> list[str]:
    hay = " ".join(str(v).lower() for v in attrs.values() if v)
    kinds = [k for k, words in SENSITIVE.items() if any(w in hay for w in words)]
    if attrs.get("type") == "password" and "password" not in kinds:
        kinds.append("password")
    return kinds


def resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def main() -> None:
    url = sys.argv[1]
    canary = sys.argv[3:5] if len(sys.argv) >= 5 and sys.argv[2] == "--fill-canary" else None
    out = {"input_url": url, "started_at": time.time(), "redirects": [], "downloads_blocked": []}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(accept_downloads=False, java_script_enabled=True,
                                  user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                                              "Chrome/131.0 Safari/537.36"))
        page = ctx.new_page()
        page.on("download", lambda d: (out["downloads_blocked"].append(d.url), d.cancel()))
        page.on("framenavigated", lambda f: f == page.main_frame and out["redirects"].append(f.url))
        try:
            resp = page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            out["status"] = resp.status if resp else None
        except Exception as e:  # dead sites are a result too
            out["error"] = type(e).__name__ + ": " + str(e).splitlines()[0][:200]
        out["final_url"] = page.url
        host = urlsplit(page.url).hostname or ""
        out["final_host"] = host
        out["final_ips"] = resolve(host) if host else []
        try:
            out["title"] = page.title()[:200]
            fields = page.eval_on_selector_all(
                "input, select, textarea",
                "els => els.map(e => ({type: e.type, name: e.name, id: e.id, "
                "placeholder: e.placeholder, autocomplete: e.autocomplete, "
                "label: (e.labels && e.labels[0] ? e.labels[0].innerText : '')}))")
            out["fields"] = [dict(f, asks_for=classify_field(f)) for f in fields
                             if f.get("type") not in ("hidden", "submit", "button")]
            out["asks_for"] = sorted({k for f in out["fields"] for k in f["asks_for"]})
            out["screenshot_png_b64"] = base64.b64encode(
                page.screenshot(full_page=False)).decode()
            if canary and "password" in out["asks_for"]:
                out["canary_filled"] = fill_canary(page, *canary)
        except Exception as e:
            out.setdefault("error", type(e).__name__ + ": " + str(e).splitlines()[0][:200])
        browser.close()
    out["finished_at"] = time.time()
    print(json.dumps(out))


def fill_canary(page, email: str, password: str) -> bool:
    """Type the fake login into the trap's form and submit it. Login only:
    card, bank and identity fields are never filled."""
    filled = False
    for el in page.query_selector_all("input"):
        t = (el.get_attribute("type") or "text").lower()
        attrs = {"type": t, "name": el.get_attribute("name"), "id": el.get_attribute("id"),
                 "placeholder": el.get_attribute("placeholder")}
        kinds = classify_field(attrs)
        if any(k in kinds for k in ("card", "bank", "identity", "otp", "phone")):
            continue
        if t == "password":
            el.fill(password)
            filled = True
        elif "email" in kinds or t == "email":
            el.fill(email)
    if filled:
        page.keyboard.press("Enter")
        page.wait_for_timeout(3000)
    return filled


if __name__ == "__main__":
    main()
