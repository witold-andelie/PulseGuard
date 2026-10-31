import pytest

from pulseguard.patching.history import FixHistoryStore


def test_snapshot_and_restore(tmp_path):
    root = tmp_path / "applied"
    root.mkdir()
    (root / "routes.py").write_text("safe()\n", encoding="utf-8")
    snaps = FixHistoryStore().snapshot_files("PG-1", root, ["routes.py"])
    (root / "routes.py").write_text("patched()\n", encoding="utf-8")
    FixHistoryStore.restore(root, snaps)
    assert (root / "routes.py").read_text(encoding="utf-8") == "safe()\n"
    with pytest.raises(ValueError):
        FixHistoryStore.restore(root, [{"path": "../etc/passwd", "content": "x"}])
