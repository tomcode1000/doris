"""Evidence locker (Box) and campaign memory (Pinecone), both through Sprites
connectors. Both are best-effort: if either service fails, Doris carries on and
the failure is written to the ledger.

Box: each trap visit / report is filed as a JSON record whose name and body
carry the ledger hash at that moment; Box's own file record (id, sha1, size)
is read back and logged, so the record can be checked against a third party.
The Box connector allows upload and read but not edit or delete.

Pinecone: each scam's text goes into an index with Pinecone's hosted embedding
(llama-text-embed-v2), so no model key is needed. A new scam that scores high
against an earlier case is flagged as a likely repeat campaign.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid

from . import gateway

BOX_FOLDER_NAME = "Doris evidence"
INDEX = os.environ.get("DORIS_PINECONE_INDEX", "doris-scams")
NAMESPACE = os.environ.get("DORIS_PINECONE_NS", "scams")
SAME_CAMPAIGN = 0.6  # similarity at or above this is reported as a likely repeat


def _multipart(attrs: dict, filename: str, payload: bytes) -> tuple[bytes, str]:
    b = "doris" + uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"attributes\"\r\n\r\n"
            f"{json.dumps(attrs)}\r\n--{b}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{filename}\"\r\nContent-Type: application/json\r\n\r\n").encode()
    return body + payload + f"\r\n--{b}--\r\n".encode(), f"multipart/form-data; boundary={b}"


class Box:
    def __init__(self, call=gateway.call, state: dict | None = None):
        self.call = call
        self.state = state if state is not None else {}

    def folder_id(self) -> str:
        if self.state.get("box_folder"):
            return self.state["box_folder"]
        try:
            fid = self.call("box", "POST", "/2.0/folders",
                            {"name": BOX_FOLDER_NAME, "parent": {"id": "0"}})["id"]
        except gateway.GatewayError as e:  # 409: it already exists
            try:
                fid = json.loads(e.body)["context_info"]["conflicts"][0]["id"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise e from None
        self.state["box_folder"] = fid
        return fid

    def file(self, case_id: str, kind: str, record: dict, ledger_head: str) -> dict:
        """Upload one record; return Box's own receipt for it."""
        payload = json.dumps({"case": case_id, "kind": kind, "ledger_head": ledger_head,
                              "record": record}, indent=1, sort_keys=True).encode()
        name = f"{case_id}-{kind}-{ledger_head[:12]}-{uuid.uuid4().hex[:6]}.json"
        body, ctype = _multipart({"name": name, "parent": {"id": self.folder_id()}}, name, payload)
        up = self.call("box", "POST", "/upload/files/content", body=body,
                       headers={"Content-Type": ctype})
        entry = up["entries"][0]
        local_sha1 = hashlib.sha1(payload).hexdigest()
        return {"box_file_id": entry["id"], "name": entry["name"], "box_sha1": entry.get("sha1"),
                "sha1_matches": entry.get("sha1") == local_sha1, "size": entry.get("size")}


class Campaigns:
    def __init__(self, call=gateway.call):
        self.call = call

    def similar(self, text: str, top_k: int = 3) -> list[dict]:
        r = self.call("pinecone", "POST", f"/indexes/{INDEX}/records/namespaces/{NAMESPACE}/search",
                      {"query": {"inputs": {"text": text[:2000]}, "top_k": top_k},
                       "fields": ["kind", "case"]})
        return [{"case": h["fields"].get("case", h["_id"]), "kind": h["fields"].get("kind"),
                 "score": round(float(h["_score"]), 3)} for h in r.get("result", {}).get("hits", [])]

    def add(self, case_id: str, text: str, kind: str) -> None:
        rec = {"_id": case_id, "text": text[:2000], "case": case_id, "kind": kind or "other"}
        self.call("pinecone", "POST", f"/indexes/{INDEX}/records/namespaces/{NAMESPACE}/upsert",
                  body=json.dumps(rec).encode(), headers={"Content-Type": "application/x-ndjson"},
                  raw=True)


def likely_repeat(hits: list[dict], exclude: str | None = None) -> dict | None:
    best = [h for h in hits if h["case"] != exclude and h["score"] >= SAME_CAMPAIGN]
    return max(best, key=lambda h: h["score"]) if best else None
