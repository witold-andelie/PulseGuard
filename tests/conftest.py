import pytest

from pulseguard.paths import replay_dir
from pulseguard.replay.store import RunStore

# Scenario sandbox suites live here; they are not part of the PulseGuard test run.
collect_ignore = ["fixtures"]


@pytest.fixture
def sample_run():
    return RunStore(replay_dir()).load("s1-placeholder")


@pytest.fixture
def sample_finding(sample_run):
    return sample_run["cases"][0]["finding"]
