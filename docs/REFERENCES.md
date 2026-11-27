# References

Every outside fact this project relies on, with its source.

## Fly.io Sprites (the platform)

| Fact used in Doris | Source |
|---|---|
| Hacksgiving rules: a personal agent on a Sprite using at least one Sprites connector; submissions close before midnight PST on Nov 29, 2026 | [fly.io/hacksgiving](https://fly.io/hacksgiving/) |
| Connectors keep the credential in the org; a Sprite calls `api.sprites.dev/v1/gateway/<provider>/<id>/<path>` with no `Authorization` header; policies are deny-by-default and can be limited by name prefix, labels and endpoint allow-lists | [Connectors](https://docs.fly.io/sprites/concepts/connectors.md) |
| Checkpoints snapshot the whole filesystem; `restore` rewinds it; agents can checkpoint themselves through `/.sprite/api.sock` | [Checkpoints](https://docs.fly.io/sprites/concepts/checkpoints.md) |
| A Sprite's URL wakes it on request; URLs are private by default; egress can be limited by a DNS allow-list that the Sprite itself cannot change | [Networking](https://docs.fly.io/sprites/concepts/networking.md) |
| `POST /v1/sprites/{name}/exec` and `POST /v1/sprites/{name}/checkpoints/{id}/restore` | [Execute command](https://docs.fly.io/sprites/api/exec/execute-command.md), [Restore checkpoint](https://docs.fly.io/sprites/api/checkpoints/restore-checkpoint.md) |
| Free plan: $5 of usage a month, up to 3 Sprites | [fly.io/pricing](https://fly.io/pricing) |

## Services Doris uses

| Service | Used for | Source |
|---|---|---|
| AgentMail | Doris's inboxes (list, read, reply, webhooks) | [AgentMail API reference](https://docs.agentmail.to/api-reference) |
| DeepSeek (`deepseek-flash`) | Scam judgement and Doris's voice | [DeepSeek API docs](https://api-docs.deepseek.com/) |
| Pinecone | Linking scams into campaigns | [Pinecone docs](https://docs.pinecone.io/) |
| Box | Evidence locker | [Box API](https://developer.box.com/reference/) |
| OpenPhish | Free live feed of phishing URLs for the trap | [openphish.com](https://openphish.com/) |
| Netcraft | Reporting phishing sites for takedown | [report.netcraft.com](https://report.netcraft.com/) |
| Playwright + Chromium | The trap's browser | [playwright.dev/python](https://playwright.dev/python/) |

## Why this matters, and prior art

| Claim | Source |
|---|---|
| O2's "Daisy" AI granny (Nov 2024) answered scam **phone calls** to waste scammers' time; kept some on the line ~40 minutes; O2 cites "hundreds of hours" wasted; it did not block scams or act on websites | [NPR](https://www.npr.org/2024/12/10/nx-s1-5220362/daisy-ai-granny-o2-fraud-spam-prevention), [TechCrunch](https://techcrunch.com/2024/11/15/ai-granny-scambaiter-wastes-telephone-fraudsters-time-with-boring-chat), [ISPreview](https://www.ispreview.co.uk/index.php/2025/01/o2-uk-reveals-first-insights-from-ai-granny-created-to-waste-scammers-time.html), [The Register](https://www.theregister.com/2024/11/15/o2_ai_granny/) |
| Older people are heavily targeted by online fraud; the FBI publishes an annual Elder Fraud Report | [FBI IC3 reports](https://www.ic3.gov/AnnualReport/Reports) |
| Scam patterns used in the evaluation set (parcel fees, fake bank sign-ins, "Hi Mum" impersonation, gift-card payment, tech support, romance, inheritance) | [UK NCSC: phishing](https://www.ncsc.gov.uk/collection/phishing-scams), [US FTC: scams](https://consumer.ftc.gov/features/scam-alerts), [Action Fraud](https://www.actionfraud.police.uk/) |
| Prompt injection: text inside content can try to steer an AI that reads it | [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) |
| Phishing kits commonly "cloak": they show bots a harmless page or redirect them to the real brand | Observed live on 2026-11-27 (an OpenPhish URL redirected the trap to facebook.com); see `tests/test_rules.py::test_may_fill_canary` |
