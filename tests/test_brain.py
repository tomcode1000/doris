import json
from datetime import datetime, timedelta, timezone

import pytest

from doris import brain, gateway, takedown, trapdoor
from doris.ledger import Ledger

FAMILY = "ask-doris@agentmail.to"
DORIS = "doris.pemberton@agentmail.to"
T0 = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)

PHISH = """\
From: Mum Smith <mum@example.com>
To: ask-doris@agentmail.to
Subject: Fwd: Account suspended

---------- Forwarded message ---------
From: Bank <alerts@secure-bank-verify.test>
Subject: Account suspended

Verify now at https://secure-bank-verify.test/login or lose access. Mum Smith
"""

GENUINE = """\
From: Mum Smith <mum@example.com>
To: ask-doris@agentmail.to
Subject: Fwd: Sunday lunch

---------- Forwarded message ---------
From: Maureen <maureen@example.com>
Subject: Sunday lunch

Trifle on Sunday? Maureen
"""

SCAM_JSON = '{"label":"scam","p_scam":0.97,"kind":"phishing","reasons":["fake bank link"]}'
SAFE_JSON = '{"label":"safe","p_scam":0.02,"kind":"none","reasons":["a friend"]}'


class World:
    """Fake AgentMail, model and trap, recording everything Doris does."""

    def __init__(self, verdict=SCAM_JSON, trap_record=None):
        self.inbox = {FAMILY: [], DORIS: []}
        self.raw, self.full = {}, {}
        self.sent, self.replies, self.done, self.reports, self.visits = [], [], [], [], []
        self.verdict = verdict
        self.now = T0
        self.trap_record = trap_record or {
            "final_url": "https://secure-bank-verify.test/login", "asks_for": ["email", "password"]}

    def llm(self, messages, json_mode=False, temperature=0.7):
        return self.verdict if json_mode else "Oh hello dear, which bank was that? Love, Doris"

    def deps(self):
        return brain.Deps(
            llm=self.llm,
            mail_new=lambda inbox: [m for m in self.inbox[inbox] if m["message_id"] not in self.done],
            mail_get=lambda inbox, mid: self.full[mid],
            mail_raw=lambda inbox, mid: self.raw[mid],
            mail_done=lambda inbox, mid: self.done.append(mid),
            mail_send=lambda inbox, to, subj, text: self.sent.append((inbox, to, subj, text)) or {},
            mail_reply=lambda inbox, mid, text: self.replies.append((inbox, mid, text)) or {},
            inspect=lambda url, canary=None: self.visits.append((url, canary)) or
            dict(self.trap_record, input_url=url),
            report=lambda url, reason, reporter: self.reports.append((url, reporter)) or {"uuid": "u1"},
            family_inbox=FAMILY, doris_inbox=DORIS, secret=b"s", now=lambda: self.now)

    def forward(self, mid, raw):
        self.inbox[FAMILY].append({"message_id": mid})
        self.raw[mid] = raw.encode()

    def to_doris(self, mid, sender, text, subject="Re: Account suspended"):
        self.inbox[DORIS].append({"message_id": mid})
        self.full[mid] = {"from": sender, "text": text, "subject": subject}


@pytest.fixture
def env(tmp_path):
    return brain.State(tmp_path / "state.json"), Ledger(tmp_path / "ledger.jsonl")


def run(w, env):
    st, lg = env
    return brain.cycle(w.deps(), st, lg)


def test_forwarded_scam_full_path(env):
    w = World()
    w.forward("m1", PHISH)
    assert run(w, env) == {"family": 1, "doris": 0, "errors": 0}
    st, lg = env
    # family told it's a scam, in reply to their forward
    assert w.replies[0][0] == FAMILY and "SCAM" in w.replies[0][2]
    # Doris wrote to the scammer from HER inbox, never the family's
    assert w.sent == [(DORIS, "alerts@secure-bank-verify.test", "Re: Account suspended",
                       "Oh hello dear, which bank was that? Love, Doris")]
    # trap opened the link with a canary; page asked for a password -> reported under Doris's address
    assert w.visits[0][0] == "https://secure-bank-verify.test/login" and w.visits[0][1][0].startswith("doris.pemberton+")
    assert w.reports == [("https://secure-bank-verify.test/login", DORIS)]
    assert st.d["stats"]["reported"] == 1 and st.d["stats"]["doris_letters"] == 1
    assert "m1" in w.done and lg.verify() == (True, None)


def test_family_identity_never_reaches_scammer_or_diary(env):
    w = World()
    w.forward("m1", PHISH)
    run(w, env)
    st, _ = env
    blob = json.dumps(st.d["diary"]) + json.dumps(w.sent)
    assert "mum@example.com" not in blob and "Mum Smith" not in json.dumps(w.sent)


def test_genuine_forward_gets_reassurance_and_no_contact(env):
    w = World(verdict=SAFE_JSON)
    w.forward("m1", GENUINE)
    run(w, env)
    assert w.sent == [] and w.visits == [] and w.reports == []
    assert "looks safe" in w.replies[0][2]


def test_unparseable_forward_asks_again(env):
    w = World()
    w.forward("m1", "From: mum@example.com\nTo: ask-doris@agentmail.to\nSubject: hi\n\nhelp")
    run(w, env)
    assert "couldn't find the original sender" in w.replies[0][2] and w.sent == []


def test_scam_from_protected_domain_gets_no_letter(env):
    w = World()
    w.forward("m1", PHISH.replace("alerts@secure-bank-verify.test", "help@irs.gov"))
    run(w, env)
    assert w.sent == [] and "SCAM" in w.replies[0][2]


def test_scammer_reply_continues_thread_with_reply_endpoint(env):
    w = World()
    w.forward("m1", PHISH)
    run(w, env)
    w.now = T0 + timedelta(hours=5)
    w.to_doris("m2", "Bank <alerts@secure-bank-verify.test>", "Madam please send your login now")
    run(w, env)
    st, _ = env
    assert w.replies[-1][0] == DORIS and w.replies[-1][1] == "m2"
    t = st.d["threads"]["alerts@secure-bank-verify.test"]
    assert [h["who"] for h in t["history"]] == ["scammer", "doris", "scammer", "doris"]
    assert st.d["stats"]["scammer_replies"] == 1 and st.d["stats"]["scammer_minutes"] == 300


def test_reply_gap_holds_doris_back(env):
    w = World()
    w.forward("m1", PHISH)
    run(w, env)
    w.now = T0 + timedelta(minutes=30)
    w.to_doris("m2", "alerts@secure-bank-verify.test", "hurry up")
    run(w, env)
    assert len([r for r in w.replies if r[0] == DORIS]) == 0  # held: too soon


def test_direct_scam_to_doris_opens_case(env):
    """A judge emails Doris directly pretending to be a scammer."""
    w = World()
    w.to_doris("m1", "Prince <prince@inheritance.test>", "Send 250 in gift cards for your millions",
               subject="Inheritance")
    run(w, env)
    st, _ = env
    assert "prince@inheritance.test" in st.d["threads"]
    assert w.replies[0][:2] == (DORIS, "m1")


def test_direct_non_scam_to_doris_is_ignored(env):
    w = World(verdict=SAFE_JSON)
    w.to_doris("m1", "friend@example.com", "Hello Doris, lovely to meet you")
    run(w, env)
    st, _ = env
    assert w.replies == [] and st.d["threads"] == {}


def test_canary_coming_back_is_noticed(env):
    w = World()
    w.forward("m1", PHISH)
    run(w, env)
    st, _ = env
    c = st.d["threads"]["alerts@secure-bank-verify.test"]["canary"]
    w.now = T0 + timedelta(days=1)
    w.to_doris("m2", "other@thief.test", f"login with {c['password']} failed, send code")
    run(w, env)
    assert st.d["stats"]["canaries_tripped"] == 1
    assert any(e["kind"] == "canary" for e in st.d["diary"])


def test_cloaked_page_is_not_reported(env):
    w = World(trap_record={"final_url": "https://www.facebook.com/", "asks_for": ["password"]})
    w.forward("m1", PHISH)
    run(w, env)
    st, _ = env
    assert w.reports == [] and st.d["stats"]["cloaked"] == 1
    assert "real facebook.com" in json.dumps(st.d["diary"])


def test_one_bad_message_does_not_stop_the_rest(env):
    w = World()
    w.inbox[FAMILY].append({"message_id": "broken"})  # no raw -> KeyError
    w.forward("m2", PHISH)
    assert run(w, env) == {"family": 1, "doris": 0, "errors": 1}
    assert {"broken", "m2"} <= set(w.done)


def test_diary_links_are_defanged(env):
    w = World()
    w.forward("m1", PHISH)
    run(w, env)
    st, _ = env
    trap_entries = [e["text"] for e in st.d["diary"] if e["kind"] in ("trap", "report")]
    assert trap_entries and all("https://" not in t for t in trap_entries)


def test_state_survives_reload(env, tmp_path):
    w = World()
    w.forward("m1", PHISH)
    run(w, env)
    again = brain.State(tmp_path / "state.json")
    assert again.d["stats"]["doris_letters"] == 1


# --- trapdoor client ---

def test_trapdoor_refuses_unsafe_links_without_calling():
    calls = []
    r = trapdoor.inspect("http://169.254.169.254/", call=lambda *a, **k: calls.append(a))
    assert "skipped" in r and calls == []


def test_trapdoor_retries_while_trap_rewinds():
    n = {"i": 0}

    def call(service, method, path, *a, **k):
        if path == "/health":
            return {"dirty": False, "busy": False}
        n["i"] += 1
        if n["i"] < 3:
            raise gateway.GatewayError(503, "rewinding")
        return {"final_url": "https://x.test/"}
    r = trapdoor.inspect("https://x.test/", call=call, wait=0)
    assert r == {"final_url": "https://x.test/"} and n["i"] == 3


def test_trapdoor_gives_up_on_auth_error():
    def call(service, method, path, *a, **k):
        if path == "/health":
            return {"dirty": False, "busy": False}
        raise gateway.GatewayError(401, "no")
    r = trapdoor.inspect("https://x.test/", call=call, wait=0)
    assert "error" in r


# --- takedown ---

@pytest.mark.parametrize("rec,ok", [
    ({"final_url": "https://scam.test/login", "asks_for": ["password"]}, True),
    ({"final_url": "https://scam.test/pay", "asks_for": ["card"]}, True),
    ({"final_url": "https://www.facebook.com/", "asks_for": ["password"]}, False),
    ({"final_url": "https://scam.test/", "asks_for": ["email"]}, False),
    ({"final_url": "https://scam.test/", "asks_for": ["password"], "error": "timeout"}, False),
    ({"skipped": "file download"}, False),
])
def test_worth_reporting(rec, ok):
    assert takedown.worth_reporting(rec)[0] is ok


def test_report_payload_shape():
    seen = {}
    takedown.report("https://scam.test/login", "asks for password", DORIS,
                    post=lambda path, body: seen.update(path=path, body=body) or {"uuid": "x"})
    assert seen["path"] == "/report/urls"
    assert seen["body"] == {"email": DORIS, "urls": [{"url": "https://scam.test/login",
                                                      "reason": "asks for password"}]}


def test_trapdoor_unconfigured_fails_fast():
    n = {"i": 0}

    def call(service, method, path, *a, **k):
        n["i"] += 1
        raise gateway.GatewayError(0, "connector for trapdoor not configured")
    import doris.trapdoor as td
    orig = td.wait_until_clean
    td.wait_until_clean = lambda call: True  # trap is clean; the connector itself is missing
    try:
        r = trapdoor.inspect("https://x.test/", call=call, wait=5)
    finally:
        td.wait_until_clean = orig
    assert "error" in r and n["i"] == 1


def test_diary_grammar_an_before_vowel(env):
    w = World(verdict='{"label":"scam","p_scam":0.99,"kind":"advance_fee","reasons":["gift cards"]}')
    w.to_doris("m1", "prince@inheritance.test", "send gift cards", subject="Inheritance")
    run(w, env)
    st, _ = env
    assert any(e["text"].startswith("New case: an advance fee scam") for e in st.d["diary"])


def test_wait_until_clean_polls_health_until_rewound():
    states = iter([gateway.GatewayError(502, "waking"), {"dirty": True, "busy": True},
                   {"dirty": False, "busy": False}])

    def call(service, method, path, *a, **k):
        x = next(states)
        if isinstance(x, Exception):
            raise x
        return x
    slept = []
    assert trapdoor.wait_until_clean(call, every=10, sleep=slept.append)
    assert slept == [10, 10]


def test_wait_until_clean_gives_up():
    assert not trapdoor.wait_until_clean(lambda *a, **k: {"dirty": True}, every=10, limit=30,
                                         sleep=lambda s: None)


def test_stuck_trap_is_skipped_not_waited_on():
    import doris.trapdoor as td
    orig = td.wait_until_clean
    td.wait_until_clean = lambda call: False
    calls = []
    try:
        r = td.inspect("https://x.test/", call=lambda *a, **k: calls.append(a))
    finally:
        td.wait_until_clean = orig
    assert "error" in r and "rewinding" in r["error"] and calls == []
