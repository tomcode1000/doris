# Doris — the grandma scammers can't rob

[![CI](https://github.com/tomcode1000/doris/actions/workflows/ci.yml/badge.svg)](https://github.com/tomcode1000/doris/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tomcode1000/doris/actions/workflows/codeql.yml/badge.svg)](https://github.com/tomcode1000/doris/actions/workflows/codeql.yml)
[![tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/tomcode1000/doris/main/docs/assets/test-summary.json)](docs/assets/test-summary.json)
![Fly.io Sprites](https://img.shields.io/badge/Fly.io-Sprites-7c3aed)
![connectors](https://img.shields.io/badge/connectors-AgentMail%20%C2%B7%20DeepSeek%20%C2%B7%20Pinecone%20%C2%B7%20Box-2563eb)

A personal agent on a [Fly.io Sprite](https://fly.io/sprites) for
[Hacksgiving 2026](https://fly.io/hacksgiving/). Families forward the scams their
parents receive to Doris, an 81-year-old AI who plays along: she writes back to
the scammer from her own inbox, clicks their links inside a throwaway computer
that is rewound after every visit, and records the trap.

> O2's Daisy (2024) talked to phone scammers. **Doris clicks**, and keeps the evidence.

**Status (Nov 27):** judge, hard rules, trap and connectors are working on real
Sprites. Email replies and the public diary page are being wired up now. Demo video and
live page links will be added here when they exist. Nothing below is claimed
before it is linked.

## For judges: every claim, with its evidence

| Claim | Evidence |
|---|---|
| Runs on Fly.io Sprites; uses four Sprites connectors | `doris-home` and `doris-trap`; [connector run](docs/runs/2026-11-27-connector-isolation.json) |
| No API key exists inside any Sprite or in the code | [`doris/gateway.py`](doris/gateway.py) sends no `Authorization` header; test `test_gateway_builds_url_without_any_auth_header`; test `test_no_secrets_in_source` |
| The trap, which visits scam pages, can reach none of Doris's services | Trap gets **403** from all four connectors, home gets **200**: [run record](docs/runs/2026-11-27-connector-isolation.json) |
| The trap is rewound to a clean checkpoint after every link | [`doris/trap.py`](doris/trap.py) (`finally: restore()`); tests in [`tests/test_trap.py`](tests/test_trap.py); measured: checkpoint 1.3 s, restore and back up 7 s |
| Doris engages only with scams: 29/29 scams, 0/19 genuine emails | [Evaluation](docs/EVAL.md), [raw run](docs/runs/2026-11-27-judge-eval.json) |
| An email that gives orders to the AI is never judged safe: 0/4 | [Evaluation](docs/EVAL.md); tests `test_injection_can_never_produce_safe` |
| Doris can never send card or bank numbers, threats or family details, whatever the model writes | [`doris/rules.py`](doris/rules.py) `outgoing_text_problems`; [`tests/test_rules.py`](tests/test_rules.py), [`tests/test_judge_voice.py`](tests/test_judge_voice.py) |
| Fake logins go only into the scam's own page, never a real site it bounces to | `may_fill_canary`; found live when a phishing kit redirected the trap to facebook.com |
| Everything Doris does is in a tamper-evident log | [`doris/ledger.py`](doris/ledger.py), tests for edits and deletions |
| Tests run on every push, with CodeQL scanning | [CI](.github/workflows/ci.yml), [CodeQL](.github/workflows/codeql.yml) |

All sources: [docs/REFERENCES.md](docs/REFERENCES.md).

## How it works

```
 family forwards a scam ─► ask-doris inbox (AgentMail)
                                 │
                          doris-home Sprite ── wakes on email, sleeps (free) otherwise
                           │  judge: DeepSeek via connector ─► hard rules (code, not model)
                           │  voice: Doris writes back to the scammer from her own inbox
                           │  links ─► doris-trap Sprite: headless Chrome opens the page,
                           │           records redirects, hosting and what it asks for,
                           │           then is restored to a clean checkpoint
                           │  evidence ─► Box · campaign links ─► Pinecone
                           ▼
                    public diary page (redacted, links defanged)
```

## What Doris will never do

- Send money, or any card, bank or identity number (blocked in code, tested).
- Reply to government, military, university or no-reply addresses.
- Mention the family, or reveal who forwarded the scam.
- Threaten anyone, or attack anything. She clicks links like a victim would; she
  never runs downloaded files.
- Type fake details into any page that is not the scam's own.

## Run the tests

```
python -m pip install pytest
python -m pytest -q
```

## Layout

| Path | What |
|---|---|
| `doris/intake.py` | Parse a forwarded email: scammer address, links, family identity removed |
| `doris/judge.py` | Scam verdict from the model, made safe by parsing and injection guards |
| `doris/voice.py` | Doris's replies, checked by the rules, with safe fallbacks |
| `doris/rules.py` | Every hard rule |
| `doris/trap.py`, `trap/inspect_link.py` | Drive the trap Sprite; the inspector that runs inside it |
| `doris/ledger.py`, `doris/canary.py`, `doris/redact.py` | Tamper-evident log, fake logins, redaction |
| `eval/` | Labelled set and the live evaluation runner |
| `docs/runs/` | Saved results from real runs |
