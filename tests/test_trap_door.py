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
