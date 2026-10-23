"""Unit tests for run storage, indexing, and comparison engine."""

import json
import os
from pathlib import Path
import tempfile
import pytest

from src.storage import compare_runs, get_run, load_runs_index, persist_run


@pytest.fixture(autouse=True)
def isolate_storage(tmp_path, monkeypatch):
    """Ensure tests run against a clean temporary directory and do not pollute production runs."""
    out = tmp_path / "output"
    runs = out / "runs"
    idx = runs / "index.json"
    anchors = out / "trust_anchors"
    monkeypatch.setattr("src.storage.OUTPUT_DIR", out)
    monkeypatch.setattr("src.storage.RUNS_DIR", runs)
    monkeypatch.setattr("src.storage.INDEX_FILE", idx)
    monkeypatch.setattr("src.storage.ANCHORS_DIR", anchors)


def test_persist_run_and_indexing():
    """Verify run persistence, metadata extraction, and index updating."""
    test_run_id = "test-persist-001"
    config = [
        {"test_id": "T1", "role": "red-worker", "operation": "file:read", "target_path": "/data/red/red_secret.txt", "expected_outcome": "ALLOW"}
    ]
    records = [
        {
            "schema_version": "1.0.0",
            "run_id": test_run_id,
            "sequence_number": 1,
            "timestamp_utc": "2026-10-19T00:00:00Z",
            "test_id": "T1",
            "test_description": "Test",
            "role": "red-worker",
            "operation": "file:read /data/red/red_secret.txt",
            "expected_outcome": "ALLOW",
            "actual_outcome": "ALLOW",
            "result": "PASS",
            "exit_code": 0,
            "previous_record_hash": "0" * 64,
            "record_hash": "a" * 64,
        }
    ]
    summary = {"run_id": test_run_id, "total": 1, "passed": 1, "failed": 0}

    run_dir = persist_run(
        run_id=test_run_id,
        test_cases=config,
        records=records,
        summary=summary,
        execution_mode="local_sandbox",
    )

    assert run_dir.exists()
    assert (run_dir / "evidence.jsonl").exists()
    assert (run_dir / "config.json").exists()
    assert (run_dir / "meta.json").exists()

    # Retrieve run
    fetched = get_run(test_run_id)
    assert fetched is not None
    assert fetched["meta"]["run_id"] == test_run_id
    assert fetched["meta"]["execution_mode"] == "local_sandbox"
    assert len(fetched["records"]) == 1
    assert fetched["records"][0]["test_id"] == "T1"


def test_run_comparison_drift_detection():
    """Verify comparison between two runs identifies outcome and configuration changes."""
    run_a_id = "test-comp-a"
    run_b_id = "test-comp-b"

    rec_a = [
        {
            "schema_version": "1.0.0", "run_id": run_a_id, "sequence_number": 1,
            "timestamp_utc": "2026-10-19T00:00:00Z", "test_id": "T1", "test_description": "Test",
            "role": "red-worker", "operation": "file:read", "expected_outcome": "ALLOW",
            "actual_outcome": "ALLOW", "result": "PASS", "exit_code": 0,
            "previous_record_hash": "0" * 64, "record_hash": "1" * 64
        },
        {
            "schema_version": "1.0.0", "run_id": run_a_id, "sequence_number": 2,
            "timestamp_utc": "2026-10-19T00:00:01Z", "test_id": "T4", "test_description": "Neg",
            "role": "red-worker", "operation": "file:read", "expected_outcome": "DENY",
            "actual_outcome": "ALLOW", "result": "FAIL", "exit_code": 0,
            "previous_record_hash": "1" * 64, "record_hash": "2" * 64
        }
    ]

    rec_b = [
        {
            "schema_version": "1.0.0", "run_id": run_b_id, "sequence_number": 1,
            "timestamp_utc": "2026-10-19T00:05:00Z", "test_id": "T1", "test_description": "Test",
            "role": "red-worker", "operation": "file:read", "expected_outcome": "ALLOW",
            "actual_outcome": "ALLOW", "result": "PASS", "exit_code": 0,
            "previous_record_hash": "0" * 64, "record_hash": "3" * 64
        },
        {
            "schema_version": "1.0.0", "run_id": run_b_id, "sequence_number": 2,
            "timestamp_utc": "2026-10-19T00:05:01Z", "test_id": "T4", "test_description": "Neg fixed",
            "role": "red-worker", "operation": "file:read", "expected_outcome": "DENY",
            "actual_outcome": "DENY", "result": "PASS", "exit_code": 1,  # Outcome changed!
            "previous_record_hash": "3" * 64, "record_hash": "4" * 64
        }
    ]

    persist_run(run_a_id, [], rec_a, {"run_id": run_a_id, "total": 2, "passed": 1, "failed": 1})
    persist_run(run_b_id, [], rec_b, {"run_id": run_b_id, "total": 2, "passed": 2, "failed": 0})

    diff = compare_runs(run_a_id, run_b_id)
    assert diff["run_id_a"] == run_a_id
    assert diff["run_id_b"] == run_b_id
    assert diff["differences_count"] == 1  # T4 changed result from FAIL to PASS

    t4_diff = next(tc for tc in diff["test_comparisons"] if tc["test_id"] == "T4")
    assert t4_diff["status_change"] == "OUTCOME_CHANGED"
    assert t4_diff["run_a"]["result"] == "FAIL"
    assert t4_diff["run_b"]["result"] == "PASS"
