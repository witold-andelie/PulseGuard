import json
import re
import shutil

import pytest

from pulseguard.paths import replay_dir
from pulseguard.replay.store import InvalidRunId, RunStore
from pulseguard.replay.verify import MANIFEST_NAME, verify_manifest, write_manifest


def test_committed_bundle_is_verified():
    result = verify_manifest()
    assert result.ok, result
    assert result.checked >= 1
    assert len(result.manifest_sha256) == 64


def test_committed_bundle_is_lf_only():
    # .gitattributes stores replay files with eol=lf; CRLF on disk would break the
    # manifest hashes on any Linux checkout (Render).
    crlf = [p.relative_to(replay_dir()).as_posix() for p in replay_dir().rglob("*")
            if p.is_file() and b"\r\n" in p.read_bytes()]
    assert crlf == []


def test_committed_bundle_has_no_host_paths():
    # A drive letter not preceded by a letter, so code such as `None:\n` does not match.
    host_path = re.compile(rb"(?<![A-Za-z])[A-Za-z]:(?:\\\\|/)[A-Za-z_]|/home/|/Users/|/tmp/")
    leaks = [p.relative_to(replay_dir()).as_posix() for p in replay_dir().rglob("*")
             if p.is_file() and host_path.search(p.read_bytes())]
    assert leaks == []


@pytest.mark.parametrize("change", ["tamper", "missing", "unlisted"])
def test_bundle_detects_changes(tmp_path, change):
    root = tmp_path / "replay"
    shutil.copytree(replay_dir(), root)
    case = next((root / "runs").rglob("run.json"))
    if change == "tamper":
        case.write_text("{}")
    elif change == "missing":
        case.unlink()
    else:
        (root / ".unlisted").write_text("extra")
    result = verify_manifest(root)
    assert not result.ok
    assert getattr(result, {"tamper": "mismatched"}.get(change, change))


@pytest.mark.parametrize("manifest", [
    [], {}, {"algorithm": "sha256", "files": []},
    {"algorithm": "sha256", "files": {}},
    {"algorithm": "sha256", "files": {"../outside.json": "a" * 64}},
    {"algorithm": "sha256", "files": {"run.json": 123}},
    {"algorithm": "md5", "files": {"run.json": "a" * 64}},
])
def test_invalid_manifest_is_rejected(tmp_path, manifest):
    (tmp_path / MANIFEST_NAME).write_text(json.dumps(manifest))
    assert not verify_manifest(tmp_path).ok


def test_missing_manifest(tmp_path):
    assert not verify_manifest(tmp_path).ok


def test_runstore_atomic_save_and_verify(tmp_path):
    store = RunStore(tmp_path)
    store.save("test-run", {"run_id": "test-run", "cases": []})
    assert store.latest()["run_id"] == "test-run"
    write_manifest(tmp_path)
    assert verify_manifest(tmp_path).ok
    for bad_id in ("../outside", "bad/path", "..", "bad\n"):
        with pytest.raises(InvalidRunId):
            store.path_for(bad_id)
