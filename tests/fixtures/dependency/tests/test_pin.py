"""SYNTHETIC fixture: sandbox pytest gate for the deterministic bump."""

from pathlib import Path


def test_vulnerable_pin_replaced():
    text = Path("requirements.txt").read_text(encoding="utf-8")
    assert "demo-lib==2.0.0" in text
    assert "demo-lib==1.2.3" not in text
