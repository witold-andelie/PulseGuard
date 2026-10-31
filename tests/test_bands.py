import pytest

from pulseguard.agents.bands import Bands, band_for, finding_state_for


@pytest.mark.parametrize(("score", "expected"), [
    (0.0, "false_positive"), (0.299999, "false_positive"), (0.3, "uncertain"),
    (0.699999, "uncertain"), (0.7, "confirmed"), (1.0, "confirmed"),
])
def test_band_boundaries(score, expected):
    assert band_for(score) == expected
    assert finding_state_for(score).value == expected


@pytest.mark.parametrize("score", [-0.1, 1.1, float("nan"), float("inf"), None, True])
def test_reject_invalid_scores(score):
    with pytest.raises(ValueError):
        band_for(score)


def test_custom_thresholds():
    assert Bands(confirmed_at=0.8, uncertain_at=0.4).band_for(0.7) == "uncertain"
    with pytest.raises(ValueError):
        Bands(confirmed_at=0.2, uncertain_at=0.4)
