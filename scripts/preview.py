"""Local preview of the diary page with sample data (no real mail, model or trap).

python scripts/preview.py   ->  http://127.0.0.1:8765
"""

import os
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
tmp = Path(tempfile.mkdtemp(prefix="doris-preview-"))
os.environ["DORIS_HOME"] = str(tmp)
(tmp / "web").mkdir()
(tmp / "web" / "index.html").write_bytes((ROOT / "web" / "index.html").read_bytes())

from doris import brain, web  # noqa: E402
from doris.ledger import Ledger  # noqa: E402
from tests.test_brain import PHISH, T0, World  # noqa: E402

w = World()
st, lg = brain.State(tmp / "state" / "state.json"), Ledger(tmp / "state" / "ledger.jsonl")
w.forward("m1", PHISH)
brain.cycle(w.deps(), st, lg)
w.now = T0 + timedelta(hours=5)
w.to_doris("m2", "alerts@secure-bank-verify.test", "Madam you must verify TODAY or account closed")
brain.cycle(w.deps(), st, lg)
w.trap_record = {"final_url": "https://www.facebook.com/", "asks_for": ["password"]}
w.now = T0 + timedelta(hours=10)
w.to_doris("m3", "prince@inheritance.test", "Send 250 in gift cards https://inheritance.test/form",
           subject="Inheritance")
brain.cycle(w.deps(), st, lg)

web.STATE, web.WEB = tmp / "state", tmp / "web"
web.LAST["at"] = 9e18  # never trigger real cycles in preview
print("preview on http://127.0.0.1:8765")
web.ThreadingHTTPServer(("127.0.0.1", 8765), web.Home).serve_forever()
