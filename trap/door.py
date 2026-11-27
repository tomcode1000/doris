"""The trap's only door. Runs as a Sprite service on the trap (port 8080).

POST /inspect {"url": ..., "canary": [email, password] | null}
  - needs "Authorization: Bearer <secret>"; the trap stores only the SHA-256
    of the secret, the secret itself lives in a Fly connector on doris-home
  - opens the link with inspect_link.py, returns the JSON record
  - then rewinds this whole Sprite to its clean checkpoint, from the inside
GET /health -> {"ok": true}  (no secret needed, reveals nothing)

Standard library only, so the clean checkpoint stays small.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
HASH_FILE = HERE / "door.sha256"
PY = os.environ.get("TRAP_PY", "/home/sprite/trapenv/bin/python")
INSPECT = str(HERE / "inspect_link.py")
CLEAN_PREFIX = "clean trap"
BUSY = threading.Lock()
MAX_BODY = 8192


def secret_ok(header: str | None, stored_hex: str) -> bool:
    if not header or not header.startswith("Bearer ") or not stored_hex:
        return False
    given = hashlib.sha256(header[7:].strip().encode()).hexdigest()
    return hmac.compare_digest(given, stored_hex.strip().lower())


def clean_checkpoint_id(listing: str) -> str | None:
    """Newest checkpoint whose comment starts with 'clean trap'.
    `sprite-env checkpoints list` prints JSON; plain text is also accepted."""
    try:
        items = json.loads(listing)
        ids = [(int(c["id"][1:]), c["id"]) for c in items
               if str(c.get("id", "")).startswith("v") and str(c.get("id"))[1:].isdigit()
               and str(c.get("comment", "")).lower().startswith(CLEAN_PREFIX)]
        return max(ids)[1] if ids else None
    except (ValueError, TypeError, KeyError):
        pass
    best = None
    for line in listing.splitlines():
        if CLEAN_PREFIX in line.lower():
            for tok in line.split():
                if tok.startswith("v") and tok[1:].isdigit():
                    n = int(tok[1:])
                    if best is None or n > best[0]:
                        best = (n, tok)
                    break
    return best[1] if best else None


SOCK = "/.sprite/api.sock"


def _sock(method: str, path: str, timeout: int = 30) -> str:
    """Talk to this Sprite's own management socket. stdin is closed: the
    sprite-env helper hangs waiting on it when run from a service."""
    return subprocess.run(["curl", "-s", "-m", str(timeout), "-X", method, "--unix-socket", SOCK,
                           f"http://sprite{path}"], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout + 5).stdout


DIRTY = HERE / "DIRTY"  # never in the clean checkpoint: only a real rewind removes it


def rewind(sock=_sock) -> str | None:
    cp = clean_checkpoint_id(sock("GET", "/v1/checkpoints"))
    if cp:
        sock("POST", f"/v1/checkpoints/{cp}/restore", 60)
    return cp


def rewind_until_clean(sock=_sock, attempts: int = 6, wait: float = 20, sleep=None) -> bool:
    """Keep asking for a rewind; Fly's restore call sometimes hangs. Returns
    True once a request went through (the Sprite then restarts clean)."""
    import time
    sleep = sleep or time.sleep
    for _ in range(attempts):
        try:
            out = sock("POST", "/v1/checkpoints/" + (clean_checkpoint_id(
                sock("GET", "/v1/checkpoints")) or "none") + "/restore", 60)
            if '"accepted"' in out or "Restore initiated" in out:
                return True
        except subprocess.TimeoutExpired:
            pass
        sleep(wait)
    return False


def watchdog(check_every: float = 60, sleep=None, rounds=None) -> None:
    """If the trap stays dirty (crash, restart, a dropped call), keep rewinding."""
    import time
    sleep = sleep or time.sleep
    n = 0
    while rounds is None or n < rounds:
        n += 1
        sleep(check_every)
        if DIRTY.exists():
            rewind_until_clean(attempts=1)


class Door(BaseHTTPRequestHandler):
    server_version = "doris-trap"

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def log_message(self, *a):  # no request logs on disk
        pass

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True, "busy": BUSY.locked(), "dirty": DIRTY.exists()})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/inspect":
            return self._send(404, {"error": "not found"})
        stored = HASH_FILE.read_text().strip() if HASH_FILE.exists() else ""
        if not secret_ok(self.headers.get("Authorization"), stored):
            return self._send(401, {"error": "no"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(400, {"error": "bad body"})
        try:
            req = json.loads(self.rfile.read(n))
            url = str(req["url"])
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"error": "bad json"})
        if DIRTY.exists() or not BUSY.acquire(blocking=False):
            return self._send(429, {"error": "busy"})
        DIRTY.write_text("visited a scam page; waiting for rewind\n")
        cmd = [PY, INSPECT, url]
        canary = req.get("canary")
        if isinstance(canary, list) and len(canary) == 2:
            cmd += ["--fill-canary", str(canary[0]), str(canary[1])]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            line = (p.stdout.strip().splitlines() or ["{}"])[-1]
            try:
                result = json.loads(line)
            except ValueError:
                result = {"error": "inspector output unreadable", "stderr": p.stderr[-300:]}
        except subprocess.TimeoutExpired:
            result = {"input_url": url, "error": "timeout"}
        result["rewinding"] = True
        try:
            self._send(200, result)
        except OSError:
            pass  # caller hung up; the trap must still be rewound
        finally:
            rewind_until_clean()  # lock never released: this Sprite is about to be rewound


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    threading.Thread(target=watchdog, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", port), Door).serve_forever()


if __name__ == "__main__":
    main()
