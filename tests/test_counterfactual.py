from pulseguard.falsify.counterfactual import consistent


def test_counterfactual_pass_and_fail():
    ok = consistent(0.95, 0.1)
    assert ok.ok
    assert ok.original_score == 0.95
    assert ok.patched_score == 0.1
    fail = consistent(0.95, 0.4)
    assert not fail.ok
    assert "failed" in fail.detail
    assert not consistent(0.5, 0.1).ok
