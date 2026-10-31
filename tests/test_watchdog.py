from pulseguard.bus.watchdog import BusWatchdog


def test_fresh_stale_stalled_and_never_raises():
    dog = BusWatchdog(max_lag_s=10, stall_after_s=10)
    assert dog.health(now=0) == "fresh"
    dog.observe_publish(0, ts=0)
    dog.observe_processed(0, ts=1)
    assert dog.health(now=100) == "fresh"  # caught up; idle is not stale
    behind = BusWatchdog(max_lag_s=10, stall_after_s=100)
    behind.observe_publish(5, ts=0)
    behind.observe_processed(0, ts=1)
    assert behind.health(now=20) == "stale"
    stalled = BusWatchdog(max_lag_s=100, stall_after_s=10)
    stalled.observe_publish(5, ts=0)
    stalled.observe_processed(1, ts=1)
    assert stalled.health(now=20) == "stalled"
    dog.health(now=-1)  # degrade instead of fail
