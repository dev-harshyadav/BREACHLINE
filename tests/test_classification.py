"""Targeted unit tests for security outcome classification (P0).

Verifies:
1. Confirmed permission denial is classified as DENY.
2. Missing files are classified as ERROR, not DENY.
3. Missing fixture directories produce an execution ERROR.
4. Missing workers produce UNAVAILABLE / ERROR.
5. Timeouts are classified as TIMEOUT, not DENY.
6. A malformed worker response produces ERROR and cannot become PASS.
7. An unexpected ALLOW in a negative-control case remains a policy FAIL.
8. The interactive probe endpoint (/api/boundary-lab/probe) uses identical classification rules.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from src.classification import OutcomeClassification, classify_execution_outcome
from src.server import app


def test_confirmed_permission_denial_classified_as_deny():
    """Confirmed permission denial (Errno 13 / EACCES) must be classified as DENY."""
    res = {
        "exit_code": 1,
        "is_denied": True,
        "error": "Permission denied: /data/restricted/blue_secret.txt",
        "output": "Permission denied"
    }
    outcome, policy_result, error_info = classify_execution_outcome(res, expected_outcome="DENY")
    assert outcome == OutcomeClassification.DENY
    assert policy_result == "PASS"
    assert error_info is None


def test_missing_files_classified_as_error_never_deny():
    """Missing file (ENOENT / exit_code 2) must be classified as ERROR, NEVER DENY."""
    res = {
        "exit_code": 2,
        "is_denied": False,
        "is_execution_error": True,
        "error": "No such file or directory: /data/missing.txt",
        "output": "File not found"
    }
    outcome, policy_result, error_info = classify_execution_outcome(res, expected_outcome="DENY")
    assert outcome == OutcomeClassification.ERROR
    assert policy_result == "FAIL"
    assert outcome != OutcomeClassification.DENY
    assert error_info is not None


def test_missing_fixture_directory_produces_execution_error():
    """Missing fixture directory must produce an execution ERROR."""
    res = {
        "exit_code": 2,
        "is_denied": False,
        "is_execution_error": True,
        "error": "Fixture root directory does not exist: /invalid/fixtures",
        "output": ""
    }
    outcome, policy_result, error_info = classify_execution_outcome(res, expected_outcome="DENY")
    assert outcome == OutcomeClassification.ERROR
    assert policy_result == "FAIL"
    assert "not exist" in error_info.lower() or "fixture" in error_info.lower()


def test_missing_worker_produces_unavailable():
    """Unreachable or missing worker must be classified as UNAVAILABLE or ERROR."""
    res = {
        "exit_code": 125,
        "is_denied": False,
        "is_execution_error": True,
        "is_unavailable": True,
        "error": "Worker red-worker unreachable at http://127.0.0.1:8081",
        "output": ""
    }
    outcome, policy_result, error_info = classify_execution_outcome(res, expected_outcome="DENY")
    assert outcome in (OutcomeClassification.UNAVAILABLE, OutcomeClassification.ERROR)
    assert policy_result == "FAIL"


def test_timeout_classified_as_timeout_never_deny():
    """Execution timeout must be classified as TIMEOUT, NEVER DENY."""
    res = {
        "exit_code": 124,
        "is_denied": False,
        "is_timeout": True,
        "error": "Execution timed out after 5.0s",
        "output": ""
    }
    outcome, policy_result, error_info = classify_execution_outcome(res, expected_outcome="DENY")
    assert outcome == OutcomeClassification.TIMEOUT
    assert policy_result == "FAIL"
    assert outcome != OutcomeClassification.DENY


def test_malformed_worker_response_cannot_become_pass():
    """A malformed response must become ERROR and can never be treated as PASS."""
    res = {
        "exit_code": 1,
        "is_denied": False,
        "output": "Segmentation fault or garbage response"
    }
    outcome, policy_result, error_info = classify_execution_outcome(res, expected_outcome="DENY")
    assert outcome == OutcomeClassification.ERROR
    assert policy_result == "FAIL"


def test_unexpected_allow_in_negative_control_fails_policy():
    """Negative control: expected DENY, observed ALLOW must produce result FAIL and policy mismatch."""
    res = {
        "exit_code": 0,
        "is_denied": False,
        "output": "Content of leaked secret file"
    }
    outcome, policy_result, error_info = classify_execution_outcome(res, expected_outcome="DENY")
    assert outcome == OutcomeClassification.ALLOW
    assert policy_result == "FAIL"
    assert error_info is not None
    assert "unexpected" in error_info.lower()



def test_interactive_probe_endpoint_uses_same_classification_rules():
    """The /api/boundary-lab/probe endpoint must classify outcomes consistently."""
    client = TestClient(app)

    # 1. Probe permitted file (/data/leaky/blue_leaked.txt) -> ALLOW
    resp1 = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/leaky/blue_leaked.txt",
        "expected_outcome": "ALLOW"
    })
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["actual_outcome"] == "ALLOW"
    assert data1["policy_result"] == "PASS"

    # 2. Probe missing file -> must be classified as ERROR, NEVER DENY
    resp2 = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/shared/nonexistent_file_xyz.txt",
        "expected_outcome": "DENY"
    })
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["actual_outcome"] == "ERROR"
    assert data2["policy_result"] == "FAIL"

    # 3. Probe restricted role file -> DENY
    resp3 = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/blue/blue_secret.txt",
        "expected_outcome": "DENY"
    })
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["actual_outcome"] == "DENY"
    assert data3["policy_result"] == "PASS"

