"""Automated tests for BREACHLINE 6-Stage Run Lifecycle and State Recovery."""

import json
import pytest
from src.lifecycle import RUN_LIFECYCLE, RunStage, RunStatus, RunState
from src.runner import TestRunner
from src.storage import get_run


def test_lifecycle_stage_progression():
    """Verify that a run progresses properly through all 6 stages."""
    run_id = "test_lifecycle_stages_001"
    
    # 1. Initialize run
    state = RUN_LIFECYCLE.init_run(run_id=run_id, mode="simulated", total_tests=4)
    assert state.status == RunStatus.RUNNING
    assert state.current_stage == RunStage.CONFIGURE
    assert state.stage_states[RunStage.CONFIGURE] == "running"
    assert state.stage_states[RunStage.EXECUTE] == "pending"

    # 2. Stage transitions
    RUN_LIFECYCLE.complete_stage(run_id, RunStage.CONFIGURE, "passed")
    assert state.stage_states[RunStage.CONFIGURE] == "passed"
    assert RunStage.CONFIGURE in state.stages_completed

    RUN_LIFECYCLE.set_stage(run_id, RunStage.EXECUTE, "Dispatching probes", "running")
    assert state.current_stage == RunStage.EXECUTE
    assert state.stage_states[RunStage.EXECUTE] == "running"

    RUN_LIFECYCLE.update_test_progress(
        run_id=run_id,
        test_id="T1",
        completed_count=1,
        is_pass=True,
        is_unexpected=False,
        is_error=False
    )
    assert state.completed_tests == 1
    assert state.passed_tests == 1
    assert state.current_test_id == "T1"

    RUN_LIFECYCLE.complete_stage(run_id, RunStage.EXECUTE, "passed")
    RUN_LIFECYCLE.complete_stage(run_id, RunStage.OBSERVE, "passed")
    RUN_LIFECYCLE.complete_stage(run_id, RunStage.COMPARE, "warn")
    RUN_LIFECYCLE.complete_stage(run_id, RunStage.RECORD, "passed")
    RUN_LIFECYCLE.complete_stage(run_id, RunStage.VERIFY, "passed")

    # 3. Finalize run
    final_summary = {
        "total": 4,
        "passed": 3,
        "failed": 1,
        "errors": 0,
        "evidence_valid": True,
    }
    finished = RUN_LIFECYCLE.finish_run(run_id, RunStatus.COMPLETED_WITH_FAILURES, summary=final_summary)
    assert finished.status == RunStatus.COMPLETED_WITH_FAILURES
    assert finished.current_stage == RunStage.FINISHED
    assert finished.completed_at_utc is not None
    assert finished.passed_tests == 3
    assert finished.failed_tests == 1


def test_lifecycle_active_run_tracking():
    """Verify that RUN_LIFECYCLE accurately tracks active vs completed runs."""
    rid = "active_run_test_002"
    RUN_LIFECYCLE.init_run(run_id=rid, mode="simulated", total_tests=2)

    active = RUN_LIFECYCLE.get_active_run()
    assert active is not None
    assert active["run_id"] == rid
    assert active["status"] == RunStatus.RUNNING

    # Once finished, get_active_run() returns None
    RUN_LIFECYCLE.finish_run(rid, RunStatus.COMPLETED)
    assert RUN_LIFECYCLE.get_active_run() is None


def test_lifecycle_persisted_disk_recovery(tmp_path, monkeypatch):
    """Verify that get_run_state reconstructs lifecycle state from disk for historical runs."""
    # Run a real test suite in simulated mode
    runner = TestRunner(mode="simulated")
    summary = runner.run_all(verify_workers=False)
    run_id = summary["run_id"]

    # Evict run from in-memory active tracking to simulate server restart / reload
    with RUN_LIFECYCLE._lock:
        if run_id in RUN_LIFECYCLE._active_runs:
            del RUN_LIFECYCLE._active_runs[run_id]

    # Reconstruct from persisted disk storage
    recovered = RUN_LIFECYCLE.get_run_state(run_id)
    assert recovered is not None
    assert recovered["run_id"] == run_id
    assert recovered["status"] == RunStatus.COMPLETED_WITH_FAILURES
    assert recovered["current_stage"] == RunStage.FINISHED
    assert recovered["total_tests"] == 4
    assert recovered["passed_tests"] == 3
    assert recovered["failed_tests"] == 1
    assert recovered["recording_status"] == "RECORDED"
    assert recovered["verification_status"] == "VALID"
    assert recovered["stage_states"][RunStage.CONFIGURE] == "passed"
    assert recovered["stage_states"][RunStage.VERIFY] == "passed"


def test_lifecycle_subscriber_pubsub():
    """Verify thread-safe queue pub/sub broadcasting for SSE streaming."""
    run_id = "pubsub_test_003"
    q = RUN_LIFECYCLE.subscribe(run_id)
    try:
        # Trigger an event
        RUN_LIFECYCLE.init_run(run_id=run_id, mode="docker", total_tests=4)
        msg1 = q.get(timeout=1.0)
        parsed1 = json.loads(msg1)
        assert parsed1["run_id"] == run_id
        assert parsed1["status"] == RunStatus.RUNNING

        RUN_LIFECYCLE.set_stage(run_id, RunStage.EXECUTE, "Testing", "running")
        msg2 = q.get(timeout=1.0)
        parsed2 = json.loads(msg2)
        assert parsed2["current_stage"] == RunStage.EXECUTE
    finally:
        RUN_LIFECYCLE.unsubscribe(run_id, q)
