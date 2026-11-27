import hashlib
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "door", Path(__file__).resolve().parents[1] / "trap" / "door.py")
door = importlib.util.module_from_spec(spec)
spec.loader.exec_module(door)

SECRET = "correct horse battery staple"
HASH = hashlib.sha256(SECRET.encode()).hexdigest()


def test_right_secret_opens():
    assert door.secret_ok(f"Bearer {SECRET}", HASH)
    assert door.secret_ok(f"Bearer {SECRET}  ", HASH.upper() + "\n")


def test_wrong_or_missing_secret_refused():
    assert not door.secret_ok("Bearer nope", HASH)
    assert not door.secret_ok(SECRET, HASH)  # no Bearer prefix
    assert not door.secret_ok(None, HASH)
    assert not door.secret_ok("", HASH)


def test_no_stored_hash_means_closed():
    assert not door.secret_ok(f"Bearer {SECRET}", "")


def test_trap_stores_no_secret():
    src = (Path(door.__file__)).read_text(encoding="utf-8")
    assert SECRET not in src and "door.sha256" in src


LISTING = """\
ID   CREATED              COMMENT
v0   2026-11-27 14:00     (auto)
v2   2026-11-27 14:20     clean trap: chromium + inspector, never touched a scam
v3   2026-11-27 16:00     Clean trap: door service + hash
v4   2026-11-27 16:05     scratch
"""


def test_rewinds_to_newest_clean_checkpoint():
    assert door.clean_checkpoint_id(LISTING) == "v3"


def test_no_clean_checkpoint():
    assert door.clean_checkpoint_id("v0 auto\nv1 scratch") is None


REAL_JSON = ('[{"id":"Current","create_time":"2026-11-27T14:52:45Z","is_auto":false},'
             '{"id":"v3","comment":"pre-restore 2026-11-27 14:04:27","is_auto":false},'
             '{"id":"v2","comment":"clean trap: chromium + inspector, never touched a scam","is_auto":false},'
             '{"id":"v1","comment":"initial checkpoint","is_auto":false}]')


def test_real_json_listing_skips_pre_restore_snapshots():
    # Captured from `sprite-env checkpoints list` on doris-trap, 2026-11-27.
    assert door.clean_checkpoint_id(REAL_JSON) == "v2"


def test_json_listing_without_clean():
    assert door.clean_checkpoint_id('[{"id":"v1","comment":"initial checkpoint"}]') is None


def test_rewind_uses_socket_and_picks_clean_checkpoint():
    calls = []

    def sock(method, path, timeout=30):
        calls.append((method, path))
        return REAL_JSON if method == "GET" else '{"status":"accepted"}'
    assert door.rewind(sock) == "v2"
    assert calls == [("GET", "/v1/checkpoints"), ("POST", "/v1/checkpoints/v2/restore")]


def test_rewind_without_clean_checkpoint_does_nothing():
    calls = []
    door.rewind(lambda m, p, t=30: calls.append(m) or "[]")
    assert calls == ["GET"]


def test_socket_call_never_waits_on_stdin():
    import inspect
    assert "stdin=subprocess.DEVNULL" in inspect.getsource(door._sock)


def test_rewind_retries_until_accepted():
    n = {"post": 0}

    def sock(method, path, timeout=30):
        if method == "GET":
            return REAL_JSON
        n["post"] += 1
        if n["post"] < 3:
            raise door.subprocess.TimeoutExpired("curl", 60)  # Fly's restore call hung
        return '{"status":"accepted"}'
    assert door.rewind_until_clean(sock, attempts=5, sleep=lambda s: None)
    assert n["post"] == 3


def test_rewind_gives_up_after_attempts():
    def sock(method, path, timeout=30):
        if method == "GET":
            return REAL_JSON
        raise door.subprocess.TimeoutExpired("curl", 60)
    assert not door.rewind_until_clean(sock, attempts=2, sleep=lambda s: None)


def test_dirty_marker_is_outside_the_secret_and_checked_before_work():
    import inspect
    src = inspect.getsource(door.Door.do_POST)
    assert src.index("DIRTY.exists()") < src.index("subprocess.run")
    assert src.index("DIRTY.write_text") < src.index("subprocess.run")


def test_rewind_runs_even_if_reply_fails():
    import inspect
    src = inspect.getsource(door.Door.do_POST)
    assert "finally:" in src and src.index("finally:") < src.index("rewind_until_clean()")


def test_watchdog_rewinds_a_dirty_trap(tmp_path, monkeypatch):
    monkeypatch.setattr(door, "DIRTY", tmp_path / "DIRTY")
    (tmp_path / "DIRTY").write_text("x")
    calls = []
    monkeypatch.setattr(door, "rewind_until_clean", lambda attempts=6: calls.append(attempts) or True)
    door.watchdog(sleep=lambda s: None, rounds=2)
    assert calls == [1, 1]


def test_watchdog_leaves_a_clean_trap_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(door, "DIRTY", tmp_path / "DIRTY")
    calls = []
    monkeypatch.setattr(door, "rewind_until_clean", lambda attempts=6: calls.append(attempts))
    door.watchdog(sleep=lambda s: None, rounds=3)
    assert calls == []
