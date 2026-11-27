"""AgentMail through the Sprites gateway (key held by the connector)."""

from __future__ import annotations

import os
import urllib.parse

from . import gateway

FAMILY_INBOX = os.environ.get("DORIS_FAMILY_INBOX", "ask-doris@agentmail.to")
DORIS_INBOX = os.environ.get("DORIS_INBOX", "doris.pemberton@agentmail.to")
DONE_LABEL = "doris-done"


def _q(inbox: str) -> str:
    return urllib.parse.quote(inbox, safe="")


def new_messages(inbox: str, limit: int = 20) -> list[dict]:
    """Received messages Doris hasn't handled yet, oldest first."""
    r = gateway.call("agentmail", "GET", f"/v0/inboxes/{_q(inbox)}/messages?limit={limit}")
    msgs = [m for m in r.get("messages", [])
            if "received" in (m.get("labels") or []) and DONE_LABEL not in (m.get("labels") or [])]
    return list(reversed(msgs))


def get_message(inbox: str, message_id: str) -> dict:
    return gateway.call("agentmail", "GET",
                        f"/v0/inboxes/{_q(inbox)}/messages/{urllib.parse.quote(message_id, safe='')}")


def get_raw(inbox: str, message_id: str) -> bytes:
    """The original RFC 822 message (AgentMail returns it or a download link)."""
    path = f"/v0/inboxes/{_q(inbox)}/messages/{urllib.parse.quote(message_id, safe='')}/raw"
    data = gateway.call("agentmail", "GET", path, raw=True)
    if data[:1] == b"{":
        import json
        import urllib.request
        url = json.loads(data).get("download_url") or json.loads(data).get("url")
        if url:
            with urllib.request.urlopen(url, timeout=30) as r:
                return r.read()
    return data


def mark_done(inbox: str, message_id: str) -> None:
    gateway.call("agentmail", "PATCH",
                 f"/v0/inboxes/{_q(inbox)}/messages/{urllib.parse.quote(message_id, safe='')}",
                 {"add_labels": [DONE_LABEL]})


def send(inbox: str, to: str, subject: str, text: str) -> dict:
    return gateway.call("agentmail", "POST", f"/v0/inboxes/{_q(inbox)}/messages/send",
                        {"to": [to], "subject": subject[:200], "text": text})


def reply(inbox: str, message_id: str, text: str) -> dict:
    return gateway.call("agentmail", "POST",
                        f"/v0/inboxes/{_q(inbox)}/messages/{urllib.parse.quote(message_id, safe='')}/reply",
                        {"text": text})
