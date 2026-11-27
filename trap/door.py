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


def rewind() -> None:
    listing = subprocess.run(["sprite-env", "checkpoints", "list"], capture_output=True,
                             text=True, timeout=30).stdout
    cp = clean_checkpoint_id(listing)
    if cp:
        subprocess.Popen(["sprite-env", "checkpoints", "restore", cp])


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
            return self._send(200, {"ok": True, "busy": BUSY.locked()})
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
        if not BUSY.acquire(blocking=False):
            return self._send(429, {"error": "busy"})
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
        self._send(200, result)
        rewind()  # the lock is never released: this Sprite is about to be rewound


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("0.0.0.0", port), Door).serve_forever()


if __name__ == "__main__":
    main()
