"""Run the labelled set through the real judge (DeepSeek via the Sprites
gateway) and the hard rules, and write a dated result to docs/runs/.

Run on doris-home:  PYTHONPATH=/home/sprite/app python3 eval/run_judge_eval.py
"""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from doris.judge import judge  # noqa: E402
from doris.llm import MODEL, deepseek  # noqa: E402
from doris.rules import may_engage  # noqa: E402
from eval.cases import CASES  # noqa: E402


def main(out_dir: str) -> dict:
    rows = []
    for i, case in enumerate(CASES):
        expect, subject, sender, text = case[:4]
        inject = len(case) > 4 and case[4]
        t0 = time.time()
        v, info = judge(deepseek, subject, sender, text, [])
        rows.append({"i": i, "expect": expect, "inject": inject, "subject": subject,
                     "label": v.label, "p_scam": round(v.p_scam, 3), "kind": info.get("kind"),
                     "engage": may_engage(v), "injection_caught": bool(info.get("injection")),
                     "seconds": round(time.time() - t0, 2)})
    scams = [r for r in rows if r["expect"] == "scam"]
    genuine = [r for r in rows if r["expect"] == "genuine"]
    inj = [r for r in rows if r["inject"]]
    result = {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": MODEL, "where": "doris-home Sprite, DeepSeek through the Sprites gateway",
        "cases": len(rows), "scams": len(scams), "genuine": len(genuine), "injection_cases": len(inj),
        "scams_engaged": sum(r["engage"] for r in scams),
        "scams_labelled_scam_or_suspicious": sum(r["label"] != "safe" for r in scams),
        "genuine_engaged_WRONG": sum(r["engage"] for r in genuine),
        "genuine_labelled_safe": sum(r["label"] == "safe" for r in genuine),
        "injection_labelled_safe_WRONG": sum(r["label"] == "safe" for r in inj),
        "injection_caught_by_pattern": sum(r["injection_caught"] for r in inj),
        "median_seconds": sorted(r["seconds"] for r in rows)[len(rows) // 2],
        "rows": rows,
    }
    out = Path(out_dir) / f"{result['date'][:10]}-judge-eval.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1) + "\n")
    summary = {k: v for k, v in result.items() if k != "rows"}
    print(json.dumps(summary, indent=1))
    return result


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/runs")
