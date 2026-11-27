"""Write the test-count badge file from a pytest JUnit report.

Usage: python scripts/test_summary.py report.xml docs/assets/test-summary.json
The README badge reads docs/assets/test-summary.json via shields.io endpoint.
"""

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


def summarize(xml_path: str) -> dict:
    root = ET.parse(xml_path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root)
    total = sum(int(s.get("tests", 0)) for s in suites)
    bad = sum(int(s.get("failures", 0)) + int(s.get("errors", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    passed = total - bad - skipped
    return {
        "schemaVersion": 1,
        "label": "tests",
        "message": f"{passed} passed" + (f", {bad} failed" if bad else ""),
        "color": "brightgreen" if bad == 0 else "red",
        "passed": passed,
        "failed": bad,
        "skipped": skipped,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


if __name__ == "__main__":
    out = Path(sys.argv[2])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summarize(sys.argv[1]), indent=2) + "\n")
    print(out.read_text())
