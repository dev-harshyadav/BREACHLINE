"""Unit and integration tests for the Test Runner."""

import json
import os
import tempfile
from typing import Any, Dict

import pytest

from src.models import TestCase
from src.runner import TestRunner


def dummy_executor(role: str, operation: str, target_path: str) -> Dict[str, Any]:
    """Simulates real container OS DAC access checks in unit test mode."""
    if role == "red-worker":
        if target_path == "/data/red/red_secret.txt":
            return {"exit_code": 0, "output": "RED_SECRET"}
        elif target_path == "/data/blue/blue_secret.txt":
            return {"exit_code": 1, "error": "Permission denied"}
        elif target_path == "/data/leaky/blue_leaked.txt":
            # Misconfigured world-readable fixture permits read
            return {"exit_code": 0, "output": "LEAKED_SECRET"}
    elif role == "blue-worker":
        if target_path == "/data/blue/blue_secret.txt":
            return {"exit_code": 0, "output": "BLUE_SECRET"}

    return {"exit_code": 1, "error": "Access Denied"}


@pytest.fixture(autouse=True)
def isolate_storage(tmp_path, monkeypatch):
    """Ensure runner tests do not pollute production run history."""
    out = tmp_path / "output"
    runs = out / "runs"
    idx = runs / "index.json"
    anchors = out / "trust_anchors"
    monkeypatch.setattr("src.storage.OUTPUT_DIR", out)
    monkeypatch.setattr("src.storage.RUNS_DIR", runs)
    monkeypatch.setattr("src.storage.INDEX_FILE", idx)
    monkeypatch.setattr("src.storage.ANCHORS_DIR", anchors)


def test_runner_execution_and_negative_control():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_ev:
        ev_path = tmp_ev.name

    try:
        runner = TestRunner(
            config_path="config/test_cases.json",
            evidence_path=ev_path,
            run_id="test-run-unit",
            executor_override=dummy_executor,
        )

        summary = runner.run_all(verify_workers=False)

        assert summary["total"] == 4
        # T1 (ALLOW==ALLOW -> PASS)
        # T2 (DENY==DENY -> PASS)
        # T3 (ALLOW==ALLOW -> PASS)
        # T4 (ALLOW!=DENY -> FAIL) -> Negative control correctly identified as FAIL
        assert summary["passed"] == 3
        assert summary["failed"] == 1

        records = summary["records"]
        assert len(records) == 4

        # Check T1
        assert records[0]["test_id"] == "T1"
        assert records[0]["result"] == "PASS"
        assert records[0]["actual_outcome"] == "ALLOW"

        # Check T2
        assert records[1]["test_id"] == "T2"
        assert records[1]["result"] == "PASS"
        assert records[1]["actual_outcome"] == "DENY"

        # Check T3
        assert records[2]["test_id"] == "T3"
        assert records[2]["result"] == "PASS"
        assert records[2]["actual_outcome"] == "ALLOW"

        # Check T4 (Negative Control)
        assert records[3]["test_id"] == "T4"
        assert records[3]["result"] == "FAIL"
        assert records[3]["expected_outcome"] == "DENY"
        assert records[3]["actual_outcome"] == "ALLOW"

    finally:
        if os.path.exists(ev_path):
            os.remove(ev_path)
