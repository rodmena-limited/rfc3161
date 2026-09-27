from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from fuzz import run  # noqa: E402


def test_a_short_fuzz_run_only_ever_raises_our_error() -> None:
    report = run(1500, seed=7)
    assert set(report.outcomes) <= {"rejected", "accepted, openssl agrees"}, report
    assert report.outcomes.get("rejected", 0) > 1000
