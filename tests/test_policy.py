from pulseguard.governance.policy import decide


def test_policy_tiers():
    auto = decide("P2", verified=True, bus_health="fresh")
    assert auto.tier == "auto" and auto.actor == "policy:auto"
    assert decide("P3", verified=True, bus_health="fresh").tier == "auto"
    assert decide("P0", verified=True, bus_health="fresh").tier == "human"
    assert decide("P1", verified=True, bus_health="fresh").tier == "human"
    assert decide("P2", verified=False, bus_health="fresh").tier == "human"
    stale = decide("P3", verified=True, bus_health="stale")
    assert stale.tier == "advise-only" and stale.actor is None
    stalled = decide("P2", verified=True, bus_health="stalled")
    assert stalled.tier == "advise-only"
    assert "human" in stalled.reason
