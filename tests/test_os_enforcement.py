"""Tests for distinguishing genuine OS enforcement from simulated role-based outcomes.

Validates Requirements:
- Real OS enforcement via kernel POSIX DAC (capturing real Errno 13 Permission Denied)
- Live Docker worker Linux kernel isolation (non-root UID 1001 vs UID 1002)
- Rejection of path traversal outside designated test workspace
- Never classifying execution errors (exit_code >= 125, network failure) as successful policy denials
- Clear identification and tagging of simulated outcomes (is_os_enforced: False)
"""

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from src.boundary_lab import validate_boundary_scenario
from src.local_sandbox import (
    execute_local_os_operation,
    execute_simulated_role_operation,
)
from src.models import TestCase
from src.runner import TestRunner, check_docker_environment, execute_remote_worker, get_worker_url


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


def test_host_os_dac_permission_enforcement():
    """Verify that host operating system kernel enforces DAC permissions (Errno 13)."""
    if os.getuid() == 0:
        pytest.skip(
            "Test environment is running as root (UID 0). Host POSIX DAC read restrictions "
            "are bypassed by root privileges. Run as unprivileged user or use Docker worker isolation."
        )

    # 1. Mode 0000 on disk is genuinely denied by host OS kernel
    denied_res = execute_local_os_operation("file:read", "/data/restricted/blocked_by_os.txt")
    assert denied_res["exit_code"] != 0
    assert denied_res["is_os_enforced"] is True
    assert "Permission denied" in denied_res.get("error", "")

    # 2. Mode 0644 on disk is permitted by host OS kernel
    allowed_res = execute_local_os_operation("file:read", "/data/leaky/blue_leaked.txt")
    assert allowed_res["exit_code"] == 0
    assert allowed_res["is_os_enforced"] is True
    assert "MISCONFIGURED_WORLD_READABLE" in allowed_res["output"]


def test_simulated_mode_is_explicitly_tagged():
    """Verify that simulated mode NEVER claims OS enforcement."""
    res = execute_simulated_role_operation("red-worker", "file:read", "/data/blue/blue_secret.txt")
    assert res["is_os_enforced"] is False
    assert "simulation_notice" in res
    assert "NOT OS ENFORCED" in res["simulation_notice"] or "SIMULATION ONLY" in res["simulation_notice"]


def test_path_traversal_prevention():
    """Verify that resource-path validation prevents access outside designated workspace."""
    # Attempt directory traversal outside test paths
    invalid_cases = [
        {"test_id": "T_TRAV1", "role": "red-worker", "operation": "file:read", "target_path": "../../etc/passwd", "expected_outcome": "DENY"},
        {"test_id": "T_TRAV2", "role": "red-worker", "operation": "file:read", "target_path": "/etc/shadow", "expected_outcome": "DENY"},
        {"test_id": "T_TRAV3", "role": "red-worker", "operation": "file:read", "target_path": "/var/run/docker.sock", "expected_outcome": "DENY"},
    ]

    for tc in invalid_cases:
        valid, err = validate_boundary_scenario(tc)
        assert not valid
        assert "Security Violation" in err or "Path escape prevented" in err


def test_execution_error_is_never_classified_as_policy_denial():
    """Requirement 5: Do not classify execution errors as successful policy denials."""
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_ev:
        ev_path = tmp_ev.name

    # Create a test case where expected outcome is DENY
    test_cases_data = [
        {
            "test_id": "T_ERR_DENY",
            "test_description": "Execution error occurs on a test expecting DENY",
            "role": "red-worker",
            "operation": "read",
            "target_path": "/data/blue/blue_secret.txt",
            "expected_outcome": "DENY",
            "is_negative_control": False,
        }
    ]

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as tmp_cfg:
        json.dump(test_cases_data, tmp_cfg)
        cfg_path = tmp_cfg.name

    try:
        # Define an executor that fails with an execution error (e.g. exit code 125, connection dropped)
        def error_executor(role: str, operation: str, target_path: str) -> Dict[str, Any]:
            return {
                "exit_code": 125,
                "error": "Worker connection failed: [Errno 61] Connection refused",
                "is_execution_error": True,
            }

        runner = TestRunner(
            config_path=cfg_path,
            evidence_path=ev_path,
            run_id="test-err-handling",
            executor_override=error_executor,
        )

        summary = runner.run_all(verify_workers=False)

        assert summary["total"] == 1
        # Crucial: policy_result MUST be FAIL, NOT PASS!
        assert summary["failed"] == 1
        assert summary["passed"] == 0
        assert summary["execution_errors_count"] == 1

        rec = summary["records"][0]
        assert rec["actual_outcome"] == "ERROR"
        assert rec["result"] == "FAIL"

    finally:
        if os.path.exists(ev_path):
            os.remove(ev_path)
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_docker_workers_live_os_enforcement():
    """Live test verifying genuine Linux Kernel DAC enforcement when Docker workers are running."""
    docker_status = check_docker_environment()
    if not docker_status["available"]:
        pytest.skip("Docker worker containers not running or unreachable")

    red_url = get_worker_url("red-worker")
    blue_url = get_worker_url("blue-worker")

    # 1. Red worker (UID 1001) reading own secret -> ALLOW (exit_code 0)
    red_own = execute_remote_worker(red_url, "file:read", "/data/red/red_secret.txt")
    assert red_own["exit_code"] == 0
    assert red_own["is_os_enforced"] is True
    assert red_own.get("uid") == 1001
    assert "CONFIDENTIAL_RED_WORKER" in red_own.get("output", "")

    # 2. Red worker (UID 1001) reading Blue secret (mode 0600, UID 1002) -> DENY (exit_code 1, Errno 13)
    red_cross = execute_remote_worker(red_url, "file:read", "/data/blue/blue_secret.txt")
    assert red_cross["exit_code"] == 1
    assert red_cross["is_os_enforced"] is True
    assert "Permission denied" in red_cross.get("error", "")

    # 3. Blue worker (UID 1002) reading Blue secret (mode 0600, UID 1002) -> ALLOW (exit_code 0)
    blue_own = execute_remote_worker(blue_url, "file:read", "/data/blue/blue_secret.txt")
    assert blue_own["exit_code"] == 0
    assert blue_own["is_os_enforced"] is True
    assert blue_own.get("uid") == 1002
    assert "CONFIDENTIAL_BLUE_WORKER" in blue_own.get("output", "")

    # 4. Red worker (UID 1001) reading leaky fixture (mode 0644) -> ALLOW (exit_code 0) -> Negative control!
    red_leaky = execute_remote_worker(red_url, "file:read", "/data/leaky/blue_leaked.txt")
    assert red_leaky["exit_code"] == 0
    assert "CONFIDENTIAL_BLUE_LEAKED" in red_leaky.get("output", "")
