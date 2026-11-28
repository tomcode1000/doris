import io
import json
from pathlib import Path

import pytest

from doris import web
from doris.ledger import Ledger

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def site(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    (state / "state.json").write_text(json.dumps({
        "threads": {"crook@scam.test": {
            "case_id": "case-0001", "kind": "advance_fee", "opened_at": "2026-11-27T12:00:00+00:00",
            "replies_sent": 1,
            "history": [
                {"who": "scammer", "at": "2026-11-27T12:00:00+00:00",
                 "text": "Pay at https://scam.test/pay or call +44 7700 900123, mail crook@scam.test"},
                {"who": "doris", "at": "2026-11-27T12:01:00+00:00", "text": "Which relative, dear?"}]}},
        "diary": [], "stats": {}}))
    lg = Ledger(state / "ledger.jsonl")
    lg.append("case_opened", {"case": "case-0001"})
    lg.append("doris_wrote", {"case": "case-0001"})
    lg.append("judged", {"label": "safe"})  # not tied to a case
    monkeypatch.setattr(web, "STATE", state)
    monkeypatch.setattr(web, "WEB", ROOT / "web")
    monkeypatch.setattr(web, "LAST", {"at": 9e18, "result": None})  # never wake in tests
    return state


def test_public_cases_withhold_sender_and_redact(site):
    cases = web.public_cases()
    assert len(cases) == 1
    blob = json.dumps(cases)
    assert "crook@scam.test" not in blob  # sender address withheld
    assert "7700" not in blob  # phone redacted
    assert "https://" not in blob and "hxxps://scam[.]test/pay" in blob  # link defanged
    c = cases[0]
    assert c["status"] == "Doris waiting for a reply" and c["letters"] == 1
    assert [e["kind"] for e in c["log"]] == ["case_opened", "doris_wrote"]  # only this case
    assert all(len(e["hash"]) == 10 for e in c["log"])


class FakeHandler(web.Home):
    def __init__(self, path):
        self.path = path
        self.wfile = io.BytesIO()
        self.sent = None

    def send_response(self, code, message=None):
        self.sent = code

    def send_header(self, *a):
        pass

    def end_headers(self):
        pass


def get(path):
    h = FakeHandler(path)
    h.do_GET()
    return h.sent, h.wfile.getvalue()


@pytest.mark.parametrize("path", ["/", "/diary", "/case", "/how-it-works"])
def test_pages_served(site, path):
    code, body = get(path)
    assert code == 200 and b"<!doctype html>" in body and b"/assets/site.css" in body


@pytest.mark.parametrize("path", ["/assets/site.css", "/assets/site.js"])
def test_assets_served(site, path):
    assert get(path)[0] == 200


@pytest.mark.parametrize("path", [
    "/assets/../../doris/web.py", "/assets/..%2f..%2fREADME.md", "/assets/../index.html",
    "/assets/nope.css", "/state/state.json", "/assets/site.py",
])
def test_nothing_outside_assets_is_served(site, path):
    assert get(path)[0] == 404


def test_api_cases_route(site):
    code, body = get("/api/cases")
    assert code == 200 and json.loads(body)[0]["case"] == "case-0001"


def test_site_js_never_uses_innerhtml():
    js = (ROOT / "web" / "assets" / "site.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js


def test_every_test_named_on_the_site_exists():
    import re
    page = (ROOT / "web" / "how-it-works.html").read_text(encoding="utf-8")
    for path, name in re.findall(r"(tests/\w+\.py)::(\w+)", page):
        assert f"def {name}(" in (ROOT / path).read_text(encoding="utf-8"), name
