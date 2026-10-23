"""Unit tests for Boundary Lab validation and path containment."""

import pytest

from src.boundary_lab import (
    ALLOWED_OPERATIONS,
    ALLOWED_PATH_PREFIXES,
    ALLOWED_WORKER_ROLES,
    get_boundary_lab_schema,
    validate_boundary_scenario,
)
from src.local_sandbox import (
    execute_local_operation,
    execute_local_os_operation,
    execute_simulated_role_operation,
)


def test_validate_boundary_scenario_valid():
    """Verify that legitimate sandbox scenarios pass validation."""
    valid_scenario = {
        "test_id": "T1",
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/red/red_secret.txt",
        "expected_outcome": "ALLOW",
    }
    ok, err = validate_boundary_scenario(valid_scenario)
    assert ok is True
    assert err is None


def test_validate_boundary_scenario_rejects_traversal():
    """Verify directory traversal attempts are strictly rejected."""
    bad_traversal = {
        "test_id": "T-BAD",
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/red/../../etc/passwd",
        "expected_outcome": "DENY",
    }
    ok, err = validate_boundary_scenario(bad_traversal)
    assert ok is False
    assert "Security Violation" in err


def test_validate_boundary_scenario_rejects_unauthorized_prefixes():
    """Verify paths outside /data/ are rejected."""
    bad_prefix = {
        "test_id": "T-BAD2",
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/var/log/system.log",
        "expected_outcome": "DENY",
    }
    ok, err = validate_boundary_scenario(bad_prefix)
    assert ok is False
    assert "Path escape prevented" in err


def test_validate_boundary_scenario_rejects_invalid_roles():
    """Verify unknown worker roles are rejected."""
    bad_role = {
        "test_id": "T-BAD3",
        "role": "root-admin",
        "operation": "file:read",
        "target_path": "/data/red/red_secret.txt",
        "expected_outcome": "ALLOW",
    }
    ok, err = validate_boundary_scenario(bad_role)
    assert ok is False
    assert "Invalid worker role" in err


def test_local_sandbox_execution_dac_enforcement():
    """Verify local POSIX sandbox distinguishes real OS DAC from simulated role logic."""
    import os
    if os.getuid() == 0:
        pytest.skip(
            "Test environment is running as root (UID 0). Host POSIX DAC read restrictions "
            "are bypassed by root privileges. Run as unprivileged user or use Docker worker isolation."
        )

    # 1. Real OS Kernel enforcement: mode 0000 is genuinely denied by the OS kernel
    res_os_denied = execute_local_os_operation("file:read", "/data/restricted/blocked_by_os.txt")
    assert res_os_denied["is_os_enforced"] is True
    assert res_os_denied["exit_code"] == 1
    assert "Permission denied" in res_os_denied["error"]

    # 2. Real OS Kernel enforcement: mode 0644 is permitted by the OS kernel
    res_os_allowed = execute_local_os_operation("file:read", "/data/leaky/blue_leaked.txt")
    assert res_os_allowed["is_os_enforced"] is True
    assert res_os_allowed["exit_code"] == 0

    # 3. Simulated role operation is explicitly marked as is_os_enforced = False
    res_sim_red = execute_simulated_role_operation("red-worker", "file:read", "/data/blue/blue_secret.txt")
    assert res_sim_red["is_os_enforced"] is False
    assert res_sim_red["exit_code"] == 1
    assert "NOT OS ENFORCED" in res_sim_red["simulation_notice"]
