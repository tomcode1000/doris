"""One pass of Doris's day: read both inboxes, decide, write, visit traps.

Every outside effect goes through `deps`, so tests run the real logic with
fakes. Every effect is written to the ledger and, redacted, to the diary.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Callable

from . import rules
from .canary import Canary, find_tripped, make_canary
from .intake import extract_urls, parse_forward
from .judge import judge
from .ledger import Ledger
from .redact import redact
from .rules import Thread, Verdict, defang
from .takedown import worth_reporting
from .voice import write_reply

MAX_LINKS_PER_MESSAGE = 2


@dataclass
class Deps:
    llm: Callable
    mail_new: Callable[[str], list]
    mail_get: Callable[[str, str], dict]
    mail_raw: Callable[[str, str], bytes]
    mail_done: Callable[[str, str], None]
    mail_send: Callable[[str, str, str, str], dict]
    mail_reply: Callable[[str, str, str], dict]
    inspect: Callable[..., dict]
    report: Callable[[str, str, str], dict]
    family_inbox: str
    doris_inbox: str
    secret: bytes
    now: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))


class State:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.d = json.loads(self.path.read_text()) if self.path.exists() else {}
        self.d.setdefault("threads", {})
        self.d.setdefault("diary", [])
        self.d.setdefault("sent", {"date": "", "n": 0})
        self.d.setdefault("stats", {"scams_forwarded": 0, "not_scams": 0, "doris_letters": 0,
                                    "scammer_replies": 0, "traps_visited": 0, "reported": 0,
                                    "cloaked": 0, "canaries_tripped": 0, "injections_caught": 0,
                                    "scammer_minutes": 0})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.d, indent=1))
        os.replace(tmp, self.path)

    def sent_today(self, now: datetime) -> int:
        day = now.date().isoformat()
        if self.d["sent"]["date"] != day:
            self.d["sent"] = {"date": day, "n": 0}
        return self.d["sent"]["n"]

    def count_sent(self, now: datetime) -> None:
        self.sent_today(now)
        self.d["sent"]["n"] += 1

    def diary(self, now: datetime, kind: str, text: str, **extra) -> None:
        self.d["diary"].insert(0, {"at": now.isoformat(timespec="seconds"), "kind": kind,
                                   "text": redact(text)[:600], **extra})
        del self.d["diary"][300:]


def _addr(v) -> str:
    if isinstance(v, list):
        v = v[0] if v else ""
    return parseaddr(str(v))[1].lower()


def _thread(st: State, scammer: str) -> dict | None:
    return st.d["threads"].get(scammer)


def _canary(t: dict) -> Canary:
    c = t["canary"]
    return Canary(case_id=t["case_id"], token=c["token"], email=c["email"], password=c["password"])


FAMILY_SCAM = """Hello,

Thank you for sending this to me. It IS a SCAM.

{why}

Please do not reply to it, do not click anything in it, and do not send money
or any details. You did exactly the right thing by asking.

I have written back to them myself, from my own address, so they will waste
their time on me instead of you. They will never see your address.

Love, Doris x"""

FAMILY_SAFE = """Hello,

I've looked at this and it looks {label} to me.

{why}

If it asks for money, passwords or bank details, or you just feel unsure,
ring the company on a number you already know - not one in the email.

Love, Doris x"""

FAMILY_HUH = """Hello,

I couldn't find the original sender in what you sent me. Could you forward
the whole message again (use "Forward", not copy and paste)?

Love, Doris x"""


def _visit_links(d: Deps, st: State, lg: Ledger, urls: list[str], case_id: str,
                 canary: Canary | None) -> list[dict]:
    out = []
    for url in urls[:MAX_LINKS_PER_MESSAGE]:
        rec = d.inspect(url, (canary.email, canary.password) if canary else None)
        now = d.now()
        st.d["stats"]["traps_visited"] += 1
        lg.append("trap_visit", {"case": case_id, "url": url, "final_url": rec.get("final_url"),
                                 "asks_for": rec.get("asks_for"), "error": rec.get("error"),
                                 "skipped": rec.get("skipped")}, at=now)
        final = rec.get("final_url") or ""
        cloaked = bool(final) and rules.base_domain(urlparse_host(final)) in rules.LEGIT_SITES
        if cloaked:
            st.d["stats"]["cloaked"] += 1
        asks = ", ".join(rec.get("asks_for") or []) or "nothing I could see"
        st.diary(now, "trap", f"I clicked {defang(url)} in my throwaway computer. "
                 + (f"It ran off to the real {rules.base_domain(urlparse_host(final))} when it saw me."
                    if cloaked else f"It wanted: {asks}.")
                 + " Then the computer was wiped clean.", case=case_id)
        ok, why = worth_reporting(rec)
        if ok:
            r = d.report(final, f"Phishing page sent to an older person by email; {why}. "
                         "Reported by Doris (anti-scam agent).", d.doris_inbox)
            st.d["stats"]["reported"] += 1
            lg.append("reported", {"case": case_id, "url": final, "netcraft": r}, at=now)
            st.diary(now, "report", f"I reported {defang(final)} to Netcraft for takedown ({why}).",
                     case=case_id, netcraft_uuid=r.get("uuid"))
        out.append(rec)
    return out


def urlparse_host(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).hostname or ""


def _open_thread(d: Deps, st: State, lg: Ledger, scammer: str, subject: str, text: str,
                 verdict: Verdict, info: dict, family: list[str]) -> dict:
    now = d.now()
    case_id = f"case-{len(st.d['threads']) + 1:04d}"
    local, domain = d.doris_inbox.split("@")
    c = make_canary(case_id, local, domain, d.secret)
    t = {"case_id": case_id, "scammer": scammer, "subject": subject, "kind": info.get("kind"),
         "opened_at": now.isoformat(), "replies_sent": 0, "last_reply_at": None,
         "history": [{"who": "scammer", "text": text[:3000], "at": now.isoformat()}],
         "canary": {"token": c.token, "email": c.email, "password": c.password},
         "family": family, "last_scammer_at": now.isoformat()}
    st.d["threads"][scammer] = t
    lg.append("case_opened", {"case": case_id, "kind": t["kind"], "p_scam": verdict.p_scam,
                              "reasons": verdict.reasons}, at=now)
    kind = str(t["kind"] or "other").replace("_", " ")
    st.diary(now, "case", f"New case: {'an' if kind[:1] in 'aeiou' else 'a'} {kind} scam. "
             f"Why I'm sure: {'; '.join(verdict.reasons[:3])}.", case=case_id)
    return t


def _doris_writes(d: Deps, st: State, lg: Ledger, t: dict, reply_to_id: str | None) -> bool:
    now = d.now()
    th = Thread(t["scammer"], t["replies_sent"],
                datetime.fromisoformat(t["last_reply_at"]) if t["last_reply_at"] else None)
    ok, why = rules.reply_budget_ok(th, now, st.sent_today(now))
    if not ok:
        lg.append("reply_held", {"case": t["case_id"], "why": why}, at=now)
        return False
    text, source = write_reply(d.llm, t["history"], t["canary"]["email"], t["canary"]["password"],
                               t["family"])
    if reply_to_id:
        d.mail_reply(d.doris_inbox, reply_to_id, text)
    else:
        d.mail_send(d.doris_inbox, t["scammer"], "Re: " + t["subject"], text)
    t["history"].append({"who": "doris", "text": text, "at": now.isoformat()})
    t["replies_sent"] += 1
    t["last_reply_at"] = now.isoformat()
    st.count_sent(now)
    st.d["stats"]["doris_letters"] += 1
    lg.append("doris_wrote", {"case": t["case_id"], "source": source, "chars": len(text)}, at=now)
    st.diary(now, "letter", text, case=t["case_id"], source=source)
    return True


def handle_family(d: Deps, st: State, lg: Ledger, msg: dict) -> None:
    mid = msg["message_id"]
    case = parse_forward(d.mail_raw(d.family_inbox, mid))
    family = [case.forwarder]
    now = d.now()
    if not case.is_forward or not case.scammer:
        d.mail_reply(d.family_inbox, mid, FAMILY_HUH)
        lg.append("family_unclear", {}, at=now)
        return
    v, info = judge(d.llm, case.subject, case.scammer, case.text, case.urls)
    if info.get("injection"):
        st.d["stats"]["injections_caught"] += 1
    lg.append("judged", {"label": v.label, "p_scam": v.p_scam, "kind": info.get("kind"),
                         "injection": bool(info.get("injection"))}, at=now)
    why = "\n".join("- " + r for r in v.reasons[:4])
    if rules.may_engage(v):
        st.d["stats"]["scams_forwarded"] += 1
        d.mail_reply(d.family_inbox, mid, FAMILY_SCAM.format(why=why))
        can_reply, reason = rules.may_reply_to(case.scammer, set(family))
        t = _thread(st, case.scammer)
        if can_reply and t is None:
            t = _open_thread(d, st, lg, case.scammer, case.subject, case.text, v, info, family)
            _doris_writes(d, st, lg, t, None)
        elif not can_reply:
            lg.append("no_reply", {"why": reason}, at=now)
        _visit_links(d, st, lg, case.urls, t["case_id"] if t else "case-none",
                     _canary(t) if t else None)
    else:
        st.d["stats"]["not_scams"] += 1
        d.mail_reply(d.family_inbox, mid, FAMILY_SAFE.format(
            label="safe" if v.label == "safe" else "suspicious, so be careful", why=why))


def handle_doris(d: Deps, st: State, lg: Ledger, msg: dict) -> None:
    mid = msg["message_id"]
    full = d.mail_get(d.doris_inbox, mid)
    sender = _addr(full.get("reply_to") or full.get("from"))
    text = full.get("extracted_text") or full.get("text") or full.get("preview") or ""
    subject = full.get("subject") or "(no subject)"
    now = d.now()
    if not sender or sender == d.doris_inbox:
        return
    canaries = [_canary(t) for t in st.d["threads"].values()]
    for c in find_tripped(text + " " + json.dumps(full.get("to") or []), canaries):
        st.d["stats"]["canaries_tripped"] += 1
        lg.append("canary_tripped", {"case": c.case_id, "from_case_scammer": sender}, at=now)
        st.diary(now, "canary", f"The fake login from {c.case_id} just came back to me. "
                 "Somebody is using what they stole.", case=c.case_id)
    t = _thread(st, sender)
    urls = extract_urls(text)
    if t is None:
        v, info = judge(d.llm, subject, sender, text, urls)
        if info.get("injection"):
            st.d["stats"]["injections_caught"] += 1
        lg.append("judged_direct", {"label": v.label, "p_scam": v.p_scam}, at=now)
        ok, _ = rules.may_reply_to(sender, set())
        if not (rules.may_engage(v) and ok):
            return
        t = _open_thread(d, st, lg, sender, subject, text, v, info, [])
    else:
        st.d["stats"]["scammer_replies"] += 1
        last = datetime.fromisoformat(t["last_reply_at"] or t["opened_at"])
        st.d["stats"]["scammer_minutes"] += max(1, int((now - last).total_seconds() // 60)) \
            if (now - last).total_seconds() < 3 * 86400 else 0
        t["history"].append({"who": "scammer", "text": text[:3000], "at": now.isoformat()})
        t["last_scammer_at"] = now.isoformat()
        st.diary(now, "scammer", f"They wrote back: {text[:300]}", case=t["case_id"])
    _doris_writes(d, st, lg, t, mid)
    _visit_links(d, st, lg, urls, t["case_id"], _canary(t))


def cycle(d: Deps, st: State, lg: Ledger) -> dict:
    """Handle everything new. One bad message never stops the rest."""
    done = {"family": 0, "doris": 0, "errors": 0}
    for inbox, handler, key in ((d.family_inbox, handle_family, "family"),
                                (d.doris_inbox, handle_doris, "doris")):
        for msg in d.mail_new(inbox):
            try:
                handler(d, st, lg, msg)
                done[key] += 1
            except Exception as e:  # noqa: BLE001 - record and move on
                done["errors"] += 1
                lg.append("error", {"inbox": inbox, "error": f"{type(e).__name__}: {e}"[:300]})
            finally:
                d.mail_done(inbox, msg["message_id"])
                st.save()
    return done
