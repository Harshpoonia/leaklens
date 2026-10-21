"""Guards for the benchmark itself.

The benchmark once built a different repo every run and counted a never-committed
key as ground truth. These tests make sure that can't silently come back.
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
from benchmark import make_synthetic, run_diff  # noqa: E402

from leaklens.scanner import scan_repo  # noqa: E402


def _head(repo):
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def synth(tmp_path):
    truth = make_synthetic(str(tmp_path / "a"), 400, 40, 10)
    return tmp_path / "a", truth


def test_generator_is_deterministic(tmp_path, synth):
    repo_a, _ = synth
    make_synthetic(str(tmp_path / "b"), 400, 40, 10)
    assert _head(repo_a) == _head(tmp_path / "b")


def test_ground_truth_is_really_in_history(synth):
    repo, truth = synth
    assert len(truth) == 10
    history = subprocess.run(["git", "-C", str(repo), "log", "--all", "-p"],
                             capture_output=True, check=True).stdout
    assert all(secret in history for _, secret in truth)


def test_blob_and_diff_find_everything(synth):
    repo, truth = synth
    found_blob = {(f.rule_id, f.secret) for f in scan_repo(str(repo)).findings}
    found_diff, _, _ = run_diff(str(repo))
    assert truth <= found_blob
    assert truth <= found_diff
