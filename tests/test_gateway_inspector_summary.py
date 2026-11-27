import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

from doris import gateway

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_gateway_builds_url_without_any_auth_header(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"], seen["method"] = req.full_url, req.get_method()
        seen["headers"] = {k.lower(): v for k, v in req.header_items()}
        seen["body"] = req.data
        return FakeResp(b'{"ok": true}')
    monkeypatch.setattr(gateway.urllib.request, "urlopen", fake_urlopen)
    out = gateway.call("deepseek", "POST", "/chat/completions", {"a": 1})
    assert out == {"ok": True}
    assert seen["url"] == f"{gateway.GATEWAY}/{gateway.CONNECTORS['deepseek']}/chat/completions"
    assert seen["method"] == "POST" and json.loads(seen["body"]) == {"a": 1}
    assert "authorization" not in seen["headers"]  # the gateway adds the key, never us


def test_gateway_raw_bytes(monkeypatch):
    monkeypatch.setattr(gateway.urllib.request, "urlopen", lambda req, timeout: FakeResp(b"\x89PNG"))
    assert gateway.call("box", "GET", "/x", raw=True) == b"\x89PNG"


def test_gateway_http_error_carries_status(monkeypatch):
    def boom(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"denies all sprites"))
    monkeypatch.setattr(gateway.urllib.request, "urlopen", boom)
    with pytest.raises(gateway.GatewayError) as e:
        gateway.call("pinecone", "GET", "/indexes")
    assert e.value.status == 403 and "denies" in e.value.body


def test_gateway_unconfigured_connector_refuses(monkeypatch):
    monkeypatch.setitem(gateway.CONNECTORS, "sprites", "")
    with pytest.raises(gateway.GatewayError):
        gateway.call("sprites", "POST", "/v1/sprites/doris-trap/exec")


def test_no_secrets_in_source():
    import re
    pat = re.compile(r"sk-[A-Za-z0-9]{20,}|pcsk_[A-Za-z0-9_]{20,}|am_[A-Za-z0-9]{24,}")
    for p in list((ROOT / "doris").glob("*.py")) + list((ROOT / "trap").glob("*.py")):
        assert not pat.search(p.read_text(encoding="utf-8")), p


inspector = load("trap/inspect_link.py", "inspect_link")


@pytest.mark.parametrize("attrs,expect", [
    ({"type": "password", "name": "pass"}, ["password"]),
    ({"type": "text", "name": "cardnumber", "placeholder": "1234 1234"}, ["card"]),
    ({"type": "text", "name": "cvv"}, ["card"]),
    ({"type": "email", "name": "email", "label": "Email address"}, ["email"]),
    ({"type": "tel", "name": "mobile"}, ["phone"]),
    ({"type": "text", "name": "otp_code"}, ["otp"]),
    ({"type": "text", "name": "dob", "label": "Date of birth"}, ["identity"]),
    ({"type": "text", "name": "iban"}, ["bank"]),
    ({"type": "text", "name": "q", "placeholder": "Search"}, []),
])
def test_inspector_field_classification(attrs, expect):
    got = inspector.classify_field(attrs)
    for k in expect:
        assert k in got
    if not expect:
        assert got == []


summary = load("scripts/test_summary.py", "test_summary")


def test_summary_from_junit(tmp_path):
    x = tmp_path / "r.xml"
    x.write_text('<testsuites><testsuite tests="10" failures="1" errors="0" skipped="2"/></testsuites>')
    s = summary.summarize(str(x))
    assert (s["passed"], s["failed"], s["skipped"], s["color"]) == (7, 1, 2, "red")
    assert s["message"] == "7 passed, 1 failed"


def test_summary_all_green(tmp_path):
    x = tmp_path / "r.xml"
    x.write_text('<testsuite tests="5" failures="0" errors="0" skipped="0"/>')
    s = summary.summarize(str(x))
    assert s["message"] == "5 passed" and s["color"] == "brightgreen"
