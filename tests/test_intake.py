from email.message import EmailMessage

from doris.intake import extract_urls, parse_forward

GMAIL_FORWARD = """\
From: Ada Mum <ada.mum@example.com>
To: doris@agentmail.to
Subject: Fwd: Your account has been suspended

is this real?

---------- Forwarded message ---------
From: Secure Bank <alerts@secure-bank-verify.test>
Date: Mon, Nov 23, 2026 at 9:14 AM
Subject: Your account has been suspended
To: <ada.mum@example.com>

Dear customer, verify now at https://secure-bank-verify.test/login?id=88.
Or call us. Regards, Ada Mum's bank.
"""


def test_gmail_forward_finds_scammer_subject_and_link():
    c = parse_forward(GMAIL_FORWARD)
    assert c.is_forward
    assert c.forwarder == "ada.mum@example.com"
    assert c.scammer == "alerts@secure-bank-verify.test"
    assert c.subject == "Your account has been suspended"
    assert c.urls == ["https://secure-bank-verify.test/login?id=88"]


def test_family_identity_is_scrubbed_from_scam_text():
    c = parse_forward(GMAIL_FORWARD)
    assert "ada.mum@example.com" not in c.text
    assert "Ada Mum" not in c.text
    assert "[family]" in c.text


def test_reply_to_wins_over_from():
    raw = GMAIL_FORWARD.replace(
        "Date: Mon", "Reply-To: claims.dept@gmail.test\nDate: Mon")
    assert parse_forward(raw).scammer == "claims.dept@gmail.test"


def test_outlook_original_message_marker():
    raw = """\
From: son@example.com
To: doris@agentmail.to
Subject: FW: prize

-----Original Message-----
From: Lottery Board <winner@lotto-claims.test>
Subject: You won 850,000 GBP

Claim at http://lotto-claims.test/claim.
"""
    c = parse_forward(raw)
    assert c.scammer == "winner@lotto-claims.test"
    assert c.subject == "You won 850,000 GBP"
    assert c.urls == ["http://lotto-claims.test/claim"]


def test_apple_mail_begin_forwarded_message():
    raw = """\
From: dad@example.com
To: doris@agentmail.to
Subject: Fwd: parcel

Begin forwarded message:

From: Courier <track@parcel-fee.test>
Subject: Parcel held

Pay 1.99 at https://parcel-fee.test/pay
"""
    assert parse_forward(raw).scammer == "track@parcel-fee.test"


def test_attached_original_rfc822_is_preferred():
    inner = EmailMessage()
    inner["From"] = "Prince <prince@inheritance.test>"
    inner["Reply-To"] = "barrister.james@outlook.test"
    inner["Subject"] = "Urgent inheritance"
    inner.set_content("Send your details to claim. https://inheritance.test/form")
    outer = EmailMessage()
    outer["From"] = "mum@example.com"
    outer["To"] = "doris@agentmail.to"
    outer["Subject"] = "Fwd: Urgent inheritance"
    outer.set_content("look at this")
    outer.add_attachment(inner)
    c = parse_forward(outer.as_bytes())
    assert c.scammer == "barrister.james@outlook.test"
    assert c.subject == "Urgent inheritance"


def test_forwarder_is_never_the_scammer():
    raw = """\
From: mum@example.com
To: doris@agentmail.to
Subject: Fwd: weird

---------- Forwarded message ---------
From: mum@example.com
Subject: weird

hello
"""
    assert parse_forward(raw).scammer is None


def test_direct_message_not_a_forward():
    raw = "From: judge@example.com\nTo: doris@agentmail.to\nSubject: Hi Doris\n\nSend me 500 now."
    c = parse_forward(raw)
    assert not c.is_forward
    assert c.scammer is None


def test_html_only_links_are_collected():
    msg = EmailMessage()
    msg["From"] = "mum@example.com"
    msg["To"] = "doris@agentmail.to"
    msg["Subject"] = "Fwd: invoice"
    msg.set_content('<p>---------- Forwarded message ---------</p>'
                    '<p>From: Billing &lt;bill@pay-invoice.test&gt;</p>'
                    '<a href="https://pay-invoice.test/x">View invoice</a>', subtype="html")
    c = parse_forward(msg.as_bytes())
    assert "https://pay-invoice.test/x" in c.urls


def test_extract_urls_strips_trailing_punctuation_and_dedupes():
    t = "go to https://a.example/x. then (https://b.example/y) and https://a.example/x!"
    assert extract_urls(t) == ["https://a.example/x", "https://b.example/y"]


def test_non_http_schemes_ignored():
    assert extract_urls("mailto:x@y.com ftp://files.example javascript:alert(1)") == []
