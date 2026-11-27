import json

from doris.canary import find_tripped, make_canary
from doris.ledger import GENESIS, Ledger
from doris.redact import redact, redact_obj

SECRET = b"test-secret"


def test_ledger_chain_and_verify(tmp_path):
    lg = Ledger(tmp_path / "l.jsonl")
    assert lg.head() == GENESIS
    a = lg.append("case_opened", {"case": "c1"})
    b = lg.append("reply_sent", {"case": "c1", "n": 1})
    assert b["prev"] == a["hash"]
    assert lg.verify() == (True, None)


def test_ledger_detects_edit(tmp_path):
    p = tmp_path / "l.jsonl"
    lg = Ledger(p)
    lg.append("a", {"x": 1})
    lg.append("b", {"x": 2})
    lines = p.read_text().splitlines()
    e = json.loads(lines[0])
    e["data"]["x"] = 99
    lines[0] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n")
    assert lg.verify() == (False, 0)


def test_ledger_detects_deletion(tmp_path):
    p = tmp_path / "l.jsonl"
    lg = Ledger(p)
    for i in range(3):
        lg.append("k", {"i": i})
    lines = p.read_text().splitlines()
    p.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert lg.verify() == (False, 1)


def test_canary_is_deterministic_per_case_and_unique_across_cases():
    a1 = make_canary("case-1", "doris", "agentmail.to", SECRET)
    a2 = make_canary("case-1", "doris", "agentmail.to", SECRET)
    b = make_canary("case-2", "doris", "agentmail.to", SECRET)
    assert a1.token == a2.token
    assert a1.token != b.token
    assert a1.email == f"doris+{a1.token}@agentmail.to"


def test_canary_never_looks_like_a_card():
    from doris.rules import outgoing_text_problems
    for i in range(50):
        c = make_canary(f"case-{i}", "doris", "agentmail.to", SECRET)
        assert outgoing_text_problems(f"{c.email} {c.password}", []) == []


def test_find_tripped_by_token_or_password():
    c1 = make_canary("case-1", "doris", "agentmail.to", SECRET)
    c2 = make_canary("case-2", "doris", "agentmail.to", SECRET)
    assert find_tripped(f"to: {c1.email}", [c1, c2]) == [c1]
    assert find_tripped(f"your password {c2.password} is wrong", [c1, c2]) == [c2]
    assert find_tripped("nothing here", [c1, c2]) == []


def test_redact_emails_phones_secrets_but_keeps_doris():
    t = ("mail mum@example.com or call +44 7700 900123, key sk-abcdefghijklmnop, "
         "Doris is doris@agentmail.to")
    r = redact(t)
    assert "mum@example.com" not in r and "[email]" in r
    assert "7700" not in r and "[phone]" in r
    assert "sk-abcdefghijklmnop" not in r and "[secret]" in r
    assert "doris@agentmail.to" in r


def test_redact_obj_walks_structures():
    o = {"a": ["x@y.com", {"b": "call 0803 123 4567"}], "n": 3}
    r = redact_obj(o)
    assert r == {"a": ["[email]", {"b": "call [phone]"}], "n": 3}
