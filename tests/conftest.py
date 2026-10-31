import pytest

from pulseguard.paths import replay_dir
from pulseguard.replay.store import RunStore


@pytest.fixture
def sample_run():
    return RunStore(replay_dir()).load("s1-placeholder")


@pytest.fixture
def sample_finding(sample_run):
    return sample_run["cases"][0]["finding"]
