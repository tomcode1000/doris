"""Append-only, hash-chained record of everything Doris does.

Each entry carries the hash of the one before it, so any edit or deletion
breaks the chain and verify() says where. The latest hash is also written
into Box file metadata, so the record can be checked against a third party.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def head(self) -> str:
        e = self.entries()
        return e[-1]["hash"] if e else GENESIS

    def append(self, kind: str, data: dict, at: datetime | None = None) -> dict:
        prev = self.head()
        body = {
            "at": (at or datetime.now(timezone.utc)).isoformat(),
            "kind": kind,
            "data": data,
        }
        entry = {**body, "prev": prev, "hash": _digest(prev, body)}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """(True, None) if intact, else (False, index of first bad entry)."""
        prev = GENESIS
        for i, e in enumerate(self.entries()):
            body = {"at": e["at"], "kind": e["kind"], "data": e["data"]}
            if e.get("prev") != prev or e.get("hash") != _digest(prev, body):
                return False, i
            prev = e["hash"]
        return True, None
