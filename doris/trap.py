"""Doris's home drives the trap Sprite through the Sprites API, via a connector
whose endpoint allow-list covers only the trap's exec and checkpoint routes.
The home never holds a Sprites token, and cannot touch any other Sprite.

One inspection = run the inspector in the trap, then rewind the trap to its
clean checkpoint, so nothing a scam page did survives to the next link.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse

from . import gateway
from .rules import link_policy

TRAP = os.environ.get("DORIS_TRAP", "doris-trap")
CLEAN_CHECKPOINT = os.environ.get("DORIS_TRAP_CLEAN", "v2")
PY = "/home/sprite/trapenv/bin/python"
INSPECTOR = "/home/sprite/trap/inspect_link.py"


def _exec(cmd: list[str], timeout: float = 120) -> str:
    q = urllib.parse.urlencode([("cmd", c) for c in cmd])
    out = gateway.call("sprites", "POST", f"/v1/sprites/{TRAP}/exec?{q}", body=b"",
                       timeout=timeout, raw=True)
    return out.decode("utf-8", "replace")


def _restore() -> None:
    gateway.call("sprites", "POST", f"/v1/sprites/{TRAP}/checkpoints/{CLEAN_CHECKPOINT}/restore",
                 body=b"", timeout=180, raw=True)


def parse_inspector_output(out: str) -> dict:
    """The inspector prints one JSON object; exec may add noise around it."""
    for line in reversed(out.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return {"error": "no inspector output", "raw_tail": out[-300:]}


def inspect(url: str, canary: tuple[str, str] | None = None, run=_exec, restore=_restore) -> dict:
    """Open url in the trap, record it, rewind the trap. Always rewinds."""
    action, why = link_policy(url)
    if action == "refuse":
        return {"input_url": url, "skipped": why}
    if action == "record_only":
        return {"input_url": url, "skipped": why, "download": True}
    cmd = [PY, INSPECTOR, url]
    if canary:
        cmd += ["--fill-canary", canary[0], canary[1]]
    t0 = time.time()
    try:
        result = parse_inspector_output(run(cmd))
    except gateway.GatewayError as e:
        result = {"input_url": url, "error": str(e)[:200]}
    finally:
        r0 = time.time()
        try:
            restore()
            rewound = True
        except gateway.GatewayError:
            rewound = False
    result["trap_seconds"] = round(r0 - t0, 2)
    result["rewound"] = rewound
    result["rewind_seconds"] = round(time.time() - r0, 2)
    return result
