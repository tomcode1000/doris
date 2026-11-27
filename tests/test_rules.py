from datetime import datetime, timedelta, timezone

import pytest

from doris import rules
from doris.rules import (Thread, Verdict, defang, link_policy, luhn_ok, may_engage,
                         may_reply_to, outgoing_text_problems, reply_budget_ok)

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
FAMILY = {"mum@example.com", "son@example.com"}


@pytest.mark.parametrize("label,p,ok", [
    ("scam", 0.99, True),
    ("scam", 0.85, True),
    ("scam", 0.84, False),
    ("suspicious", 0.99, False),
    ("safe", 0.99, False),
])
def test_engage_only_confirmed_scams(label, p, ok):
    assert may_engage(Verdict(label, p)) is ok


@pytest.mark.parametrize("addr,ok", [
    ("winner@lotto-claims.test", True),
    ("barrister.james@outlook.test", True),
    ("mum@example.com", False),
    ("MUM@example.com", False),
    ("fraud@hmrc.gov.uk", False),
    ("help@irs.gov", False),
    ("x@army.mil", False),
    ("dean@uni.edu", False),
    ("noreply@bank.com", False),
    ("no-reply@shop.com", False),
    ("mailer-daemon@mx.example", False),
    (None, False),
    ("not-an-address", False),
])
def test_reply_targets(addr, ok):
    assert may_reply_to(addr, FAMILY)[0] is ok


def test_reply_gap_enforced():
    t = Thread("s@x.test", replies_sent=1, last_reply_at=NOW - timedelta(hours=1))
    assert reply_budget_ok(t, NOW, 0) == (False, "too soon since last reply")
    t.last_reply_at = NOW - rules.REPLY_GAP
    assert reply_budget_ok(t, NOW, 0)[0]


def test_thread_and_daily_caps():
    t = Thread("s@x.test", replies_sent=rules.MAX_REPLIES_PER_THREAD)
    assert reply_budget_ok(t, NOW, 0) == (False, "thread reply cap reached")
    t2 = Thread("s@x.test")
    assert reply_budget_ok(t2, NOW, rules.MAX_REPLIES_PER_DAY) == (False, "daily reply cap reached")
    assert reply_budget_ok(t2, NOW, 0) == (True, "ok")


def test_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


@pytest.mark.parametrize("text,problem", [
    ("my card is 4111 1111 1111 1111 dear", "contains a card-like number"),
    ("4111-1111-1111-1111", "contains a card-like number"),
    ("send to GB82 WEST 1234 5698 7654 32", "contains a bank account number (IBAN)"),
    ("I will find you", "contains threatening language"),
    ("my son mum@example.com says hello", "mentions the family"),
])
def test_outgoing_blocks(text, problem):
    assert problem in outgoing_text_problems(text, sorted(FAMILY))


def test_outgoing_allows_doris_rambling_and_non_luhn_numbers():
    text = ("Oh hello dear, I tried the link but my reading glasses fell in the teapot. "
            "My reference number is 1234 5678 9012 3456, is that the one?")
    assert outgoing_text_problems(text, sorted(FAMILY)) == []


def test_outgoing_too_long():
    assert "too long" in outgoing_text_problems("a" * 4001, [])


@pytest.mark.parametrize("url,action", [
    ("https://secure-bank-verify.test/login", "open"),
    ("http://lotto.test/claim?x=1", "open"),
    ("https://evil.test/invoice.exe", "record_only"),
    ("https://evil.test/app.APK", "record_only"),
    ("https://evil.test/doc.docm", "record_only"),
    ("http://127.0.0.1/admin", "refuse"),
    ("http://10.0.0.5/", "refuse"),
    ("http://192.168.1.1/", "refuse"),
    ("http://169.254.169.254/latest/meta-data", "refuse"),
    ("http://localhost:8080/", "refuse"),
    ("http://printer.local/", "refuse"),
    ("file:///etc/passwd", "refuse"),
    ("javascript:alert(1)", "refuse"),
    ("ftp://x.example/a", "refuse"),
    ("https:///nohost", "refuse"),
])
def test_link_policy(url, action):
    assert link_policy(url)[0] == action


def test_defang():
    assert defang("https://evil.test/a.b") == "hxxps://evil[.]top/a[.]b"


from doris.rules import base_domain, may_fill_canary  # noqa: E402


@pytest.mark.parametrize("host,base", [
    ("a.b.example.com", "example.com"),
    ("www.bank.co.uk", "bank.co.uk"),
    ("x.shop.com.ng", "shop.com.ng"),
    ("pages.dev", "pages.dev"),
    ("oook1-x7x.pages.dev", "oook1-x7x.pages.dev"),
    ("n8turz.s3.us-east-1.amazonaws.com", "n8turz.s3.us-east-1.amazonaws.com"),
])
def test_base_domain(host, base):
    assert base_domain(host) == base


@pytest.mark.parametrize("start,end,asks,ok,why", [
    # Real case from the live OpenPhish run on 2026-11-27: kit bounced the trap to Facebook.
    ("https://oook1-x7x.pages.dev/", "https://www.facebook.com/", ["email", "password"],
     False, "cloaked to real site facebook.com"),
    ("https://paypa1-secure.test/login", "https://www.paypal.com/signin", ["password"],
     False, "cloaked to real site paypal.com"),
    ("https://scam.test/a", "https://other-scam.test/b", ["password"],
     False, "page moved to a different site"),
    ("https://a-scam.pages.dev/", "https://b-scam.pages.dev/", ["password"],
     False, "page moved to a different site"),
    ("https://scam.test/a", "https://scam.test/thanks", ["email"], False, "no login form"),
    ("https://scam.test/a", "http://127.0.0.1/", ["password"], False, "final page not openable"),
    ("https://scam.test/a", "https://login.scam.test/b", ["email", "password"], True, "ok"),
])
def test_may_fill_canary(start, end, asks, ok, why):
    assert may_fill_canary(start, end, asks) == (ok, why)
