import json

import pytest

from doris import gateway, trap


def recorder(output="", fail=False):
    calls = {"run": [], "restore": 0}

    def run(cmd):
        calls["run"].append(cmd)
        if fail:
            raise gateway.GatewayError(500, "trap crashed")
        return output

    def restore():
        calls["restore"] += 1
    return run, restore, calls


def test_inspect_runs_inspector_then_rewinds():
    out = "noise\n" + json.dumps({"input_url": "https://x.test/a", "final_url": "https://x.test/a"})
    run, restore, calls = recorder(out)
    r = trap.inspect("https://x.test/a", run=run, restore=restore)
    assert calls["run"] == [[trap.PY, trap.INSPECTOR, "https://x.test/a"]]
    assert calls["restore"] == 1 and r["rewound"] is True
    assert r["final_url"] == "https://x.test/a"


def test_canary_passed_to_inspector():
    run, restore, calls = recorder("{}")
    trap.inspect("https://x.test/a", canary=("d+t@agentmail.to", "Pw1!"), run=run, restore=restore)
    assert calls["run"][0][-3:] == ["--fill-canary", "d+t@agentmail.to", "Pw1!"]


def test_trap_is_rewound_even_when_inspection_fails():
    run, restore, calls = recorder(fail=True)
    r = trap.inspect("https://x.test/a", run=run, restore=restore)
    assert calls["restore"] == 1 and "error" in r


@pytest.mark.parametrize("url,key", [
    ("http://169.254.169.254/latest", "skipped"),
    ("file:///etc/passwd", "skipped"),
    ("https://evil.test/setup.exe", "download"),
])
def test_unsafe_links_never_reach_the_trap(url, key):
    run, restore, calls = recorder("{}")
    r = trap.inspect(url, run=run, restore=restore)
    assert key in r and calls["run"] == [] and calls["restore"] == 0


def test_parse_output_takes_last_json_line():
    out = '{"a": 1}\nwarning\n{"b": 2}\n'
    assert trap.parse_inspector_output(out) == {"b": 2}


def test_parse_output_without_json():
    assert "error" in trap.parse_inspector_output("Traceback: boom")
