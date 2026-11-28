"""Doris's home: the public diary page, and the wake-up bell.

Runs as a Sprite service on doris-home (port 8080). A request to the URL
wakes the Sprite; /wake (and any page view after a quiet spell) runs one
cycle in the background. Nothing on these pages is secret: diary text is
redacted and scam links are defanged before it is stored.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import brain, llm, mailbox, takedown, trapdoor
from .ledger import Ledger

APP = Path(os.environ.get("DORIS_HOME", "/home/sprite/app"))
STATE = APP / "state"
WEB = APP / "web"
LOCK = threading.Lock()
LAST = {"at": 0.0, "result": None}
MIN_GAP = 20  # seconds between cycles


def canary_secret() -> bytes:
    p = STATE / "canary.key"
    if not p.exists():
        STATE.mkdir(parents=True, exist_ok=True)
        p.write_text(secrets.token_hex(32))
    return bytes.fromhex(p.read_text().strip())


def real_deps() -> brain.Deps:
    return brain.Deps(
        llm=llm.deepseek, mail_new=mailbox.new_messages, mail_get=mailbox.get_message,
        mail_raw=mailbox.get_raw, mail_done=mailbox.mark_done, mail_send=mailbox.send,
        mail_reply=mailbox.reply, inspect=trapdoor.inspect,
        report=lambda url, reason, reporter: takedown.report(url, reason, reporter),
        family_inbox=mailbox.FAMILY_INBOX, doris_inbox=mailbox.DORIS_INBOX,
        secret=canary_secret())


def run_cycle() -> None:
    if not LOCK.acquire(blocking=False):
        return
    try:
        if time.time() - LAST["at"] < MIN_GAP:
            return
        LAST["at"] = time.time()
        st = brain.State(STATE / "state.json")
        lg = Ledger(STATE / "ledger.jsonl")
        LAST["result"] = brain.cycle(real_deps(), st, lg)
    except Exception as e:  # noqa: BLE001
        LAST["result"] = {"error": f"{type(e).__name__}: {e}"[:200]}
    finally:
        LOCK.release()


def public_view() -> dict:
    p = STATE / "state.json"
    d = json.loads(p.read_text()) if p.exists() else {}
    lg = Ledger(STATE / "ledger.jsonl")
    ok, bad = lg.verify()
    return {"stats": d.get("stats", {}), "diary": d.get("diary", [])[:100],
            "cases": len(d.get("threads", {})), "ledger": {"entries": len(lg.entries()),
                                                           "head": lg.head(), "intact": ok},
            "inboxes": {"forward_to": mailbox.FAMILY_INBOX, "doris": mailbox.DORIS_INBOX},
            "last_cycle": LAST}


def public_cases() -> list[dict]:
    """Cases for the public site. Scammer addresses are withheld, every text is
    redacted, links are defanged, and the family is never included."""
    p = STATE / "state.json"
    d = json.loads(p.read_text()) if p.exists() else {}
    by_case: dict[str, list] = {}
    for e in Ledger(STATE / "ledger.jsonl").entries():
        cid = (e.get("data") or {}).get("case")
        if cid:
            by_case.setdefault(cid, []).append({"at": e["at"], "kind": e["kind"],
                                                "hash": e["hash"][:10]})
    out = []
    for t in d.get("threads", {}).values():
        history = [{"who": h["who"], "at": h.get("at"),
                    "text": _clean(h.get("text", ""))} for h in t.get("history", [])]
        last = history[-1]["who"] if history else None
        out.append({
            "case": t["case_id"], "kind": t.get("kind") or "other", "opened_at": t.get("opened_at"),
            "status": "Doris waiting for a reply" if last == "doris" else "Scammer replied",
            "letters": t.get("replies_sent", 0),
            "scammer_replies": sum(1 for h in history[1:] if h["who"] == "scammer"),
            "history": history, "log": by_case.get(t["case_id"], [])[-20:],
        })
    out.sort(key=lambda c: c["case"], reverse=True)
    return out


def _clean(text: str) -> str:
    import re
    from .redact import redact
    from .rules import defang
    return re.sub(r"https?://\S+", lambda m: defang(m.group(0)), redact(text))[:3000]


PAGES = {"/": "index.html", "/index.html": "index.html", "/diary": "diary.html",
         "/case": "case.html", "/how-it-works": "how-it-works.html", "/evidence": "evidence.html"}
TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".jpg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".svg": "image/svg+xml"}


class Home(BaseHTTPRequestHandler):
    server_version = "doris-home"

    def log_message(self, *a):
        pass

    def _send(self, code, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _wake(self):
        threading.Thread(target=run_cycle, daemon=True).start()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            return self._send(200, b'{"ok":true}')
        if path in ("/wake",):
            self._wake()
            return self._send(202, b'{"waking":true}')
        if path == "/api/diary":
            if time.time() - LAST["at"] > 120:
                self._wake()
            return self._send(200, json.dumps(public_view()).encode())
        if path == "/evidence" and not (WEB / "evidence.html").exists():
            self.send_response(302)  # until the Evidence page is designed and built
            self.send_header("Location", "https://github.com/tomcode1000/doris/blob/main/docs/EVAL.md")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/api/cases":
            return self._send(200, json.dumps(public_cases()).encode())
        if path in PAGES and (WEB / PAGES[path]).exists():
            if time.time() - LAST["at"] > 120:
                self._wake()
            return self._send(200, (WEB / PAGES[path]).read_bytes(), "text/html; charset=utf-8")
        if path.startswith("/assets/"):
            f = (WEB / path.lstrip("/")).resolve()
            if f.is_file() and (WEB / "assets").resolve() in f.parents and f.suffix in TYPES:
                return self._send(200, f.read_bytes(), TYPES[f.suffix])
        self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path.split("?")[0] == "/wake":  # e.g. an AgentMail webhook; body ignored
            self._wake()
            return self._send(202, b'{"waking":true}')
        self._send(404, b'{"error":"not found"}')


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("0.0.0.0", port), Home).serve_forever()


if __name__ == "__main__":
    main()
