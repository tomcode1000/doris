import hashlib
import json

import pytest

from doris import brain, evidence, gateway
from doris.ledger import Ledger
from tests.test_brain import PHISH, World


class FakeBox:
    """Records what Doris files; mimics Box's upload receipt (sha1 of the body)."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, service, method, path, body=None, **kw):
        self.calls.append((method, path))
        if self.fail:
            raise gateway.GatewayError(503, "box down")
        if path == "/2.0/folders":
            return {"id": "F1"}
        if path == "/upload/files/content":
            raw = body.split(b"application/json\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
            name = json.loads(body.split(b"\r\n\r\n", 1)[1].split(b"\r\n", 1)[0])["name"]
            return {"entries": [{"id": "B1", "name": name, "sha1": hashlib.sha1(raw).hexdigest(),
                                 "size": len(raw)}]}
        raise AssertionError(path)


def test_box_file_returns_receipt_with_matching_sha1():
    fake = FakeBox()
    r = evidence.Box(call=fake).file("case-0001", "trap-visit", {"final_url": "x"}, "a" * 64)
    assert r["box_file_id"] == "B1" and r["sha1_matches"] is True
    assert r["name"].startswith("case-0001-trap-visit-aaaaaaaaaaaa-")
    assert ("POST", "/2.0/folders") in fake.calls


def test_box_reuses_existing_folder_on_conflict():
    def call(service, method, path, body=None, **kw):
        if path == "/2.0/folders":
            raise gateway.GatewayError(409, json.dumps({"context_info": {"conflicts": [{"id": "OLD"}]}}))
    assert evidence.Box(call=call).folder_id() == "OLD"


def test_box_folder_cached():
    fake = FakeBox()
    b = evidence.Box(call=fake)
    b.folder_id(), b.folder_id()
    assert fake.calls.count(("POST", "/2.0/folders")) == 1


@pytest.mark.parametrize("hits,repeat", [
    ([{"case": "case-0003", "kind": "parcel", "score": 0.83}], "case-0003"),
    ([{"case": "case-0003", "kind": "parcel", "score": 0.41}], None),
    ([{"case": "case-0009", "kind": "parcel", "score": 0.99}], None),  # itself
    ([], None),
])
def test_likely_repeat(hits, repeat):
    r = evidence.likely_repeat(hits, exclude="case-0009")
    assert (r["case"] if r else None) == repeat


def test_campaigns_search_and_upsert_shape():
    seen = []

    def call(service, method, path, body=None, **kw):
        seen.append((service, path, body, kw.get("headers")))
        if path.endswith("/search"):
            return {"result": {"hits": [{"_id": "case-0002", "_score": 0.8123,
                                         "fields": {"case": "case-0002", "kind": "parcel"}}]}}
        return b""
    c = evidence.Campaigns(call=call)
    assert c.similar("pay the fee") == [{"case": "case-0002", "kind": "parcel", "score": 0.812}]
    c.add("case-0003", "pay the fee", "parcel")
    assert seen[0][1] == "/indexes/doris-scams/records/namespaces/scams/search"
    assert seen[1][1].endswith("/upsert") and seen[1][3]["Content-Type"] == "application/x-ndjson"
    assert json.loads(seen[1][2]) == {"_id": "case-0003", "text": "pay the fee", "case": "case-0003",
                                      "kind": "parcel"}


class FakeCampaigns:
    def __init__(self, hits=None, fail=False):
        self.hits, self.fail, self.added = hits or [], fail, []

    def similar(self, text):
        if self.fail:
            raise gateway.GatewayError(503, "pinecone down")
        return self.hits

    def add(self, case_id, text, kind):
        if self.fail:
            raise gateway.GatewayError(503, "pinecone down")
        self.added.append(case_id)


def run_with(tmp_path, box=None, campaigns=None):
    w = World()
    w.forward("m1", PHISH)
    d = w.deps()
    d.box, d.campaigns = box, campaigns
    st, lg = brain.State(tmp_path / "s.json"), Ledger(tmp_path / "l.jsonl")
    res = brain.cycle(d, st, lg)
    return w, st, lg, res


def test_trap_visit_is_filed_in_box_with_ledger_head(tmp_path):
    fake = FakeBox()
    _, _, lg, _ = run_with(tmp_path, box=evidence.Box(call=fake))
    filed = [e for e in lg.entries() if e["kind"] == "box_filed"]
    assert filed and filed[0]["data"]["sha1_matches"] is True and lg.verify() == (True, None)


def test_repeat_campaign_flagged_in_diary(tmp_path):
    camp = FakeCampaigns(hits=[{"case": "case-0042", "kind": "phishing", "score": 0.88}])
    _, st, lg, _ = run_with(tmp_path, campaigns=camp)
    assert camp.added == ["case-0001"]
    assert any("CASE 0042 again" in e["text"] for e in st.d["diary"])
    assert any(e["kind"] == "campaign_match" for e in lg.entries())


def test_box_and_pinecone_failures_never_stop_doris(tmp_path):
    w, st, lg, res = run_with(tmp_path, box=evidence.Box(call=FakeBox(fail=True)),
                              campaigns=FakeCampaigns(fail=True))
    assert res == {"family": 1, "doris": 0, "errors": 0}
    assert len(w.sent) == 1 and st.d["stats"]["doris_letters"] == 1  # Doris still wrote
    assert {e["data"]["service"] for e in lg.entries() if e["kind"] == "service_error"} == {"box", "pinecone"}
