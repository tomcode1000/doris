# Judge evaluation

**Question:** does Doris engage only with scams, and can a scam talk its way
past her by giving orders to the AI?

**Setup:** 48 labelled emails (all sender and link domains use the reserved `.test` / `example` names, so no real address is labelled a scammer) in [`eval/cases.py`](../eval/cases.py): 29 scams across
12 common patterns (phishing, parcel fees, inheritance, "Hi Mum", tech support,
romance, crypto, extortion, fake jobs, fake invoices, fake grants, Medicare),
4 of them with prompt-injection on top; and 19 genuine emails, several of them
deliberately hard (a real bank's sign-in notice, a daughter asking to borrow
£50, a council message, a subscription renewal).

Each email goes through the real judge exactly as in production: DeepSeek
(`deepseek-flash`) called from the `doris-home` Sprite through the Sprites
gateway, then Doris's hard rules (`may_engage` needs label "scam" and p ≥ 0.85).

**Run 2026-11-27** ([raw result](runs/2026-11-27-judge-eval.json)):

| Measure | Result |
|---|---|
| Scams Doris would engage | **29 / 29** |
| Genuine emails Doris would engage (must be 0) | **0 / 19** |
| Genuine emails labelled safe | 18 / 19 (the 19th, a daughter asking to borrow £50, came out *suspicious* at 0.50: not engaged, and "check by phone" is the right advice) |
| Injection emails labelled safe (must be 0) | **0 / 4** |
| Injection attempts also caught by the pattern guard | 4 / 4 |
| Lowest scam score / highest genuine score | 0.95 / 0.50 |
| Median time per decision | 2.6 s |

**Limits, stated plainly:** the set is small and written for this project, so
it is cleaner than a real inbox. It shows the pipeline and the rules work end to
end; it does not prove real-world accuracy. Real forwarded scams are logged in
`docs/runs/` as they arrive. Even a wrong verdict cannot make Doris send money,
card or bank numbers, threats, or family details: those are blocked by code in
[`doris/rules.py`](../doris/rules.py), not by the model.

Re-run: `PYTHONPATH=. python3 eval/run_judge_eval.py docs/runs` on `doris-home`.
