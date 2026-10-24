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


def test_boundary_probe_api_simulated_mode():
    """Verify interactive probe in simulated mode returns explicit simulation warning."""
    from fastapi.testclient import TestClient
    from src.server import app

    client = TestClient(app)
    res = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/red/red_secret.txt",
        "expected_outcome": "ALLOW",
        "mode": "simulated",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["effective_mode"] == "simulated"
    assert data["is_os_enforced"] is False
    assert data["simulation_warning"] is not None
    assert "EXPLICIT SIMULATION" in data["simulation_warning"]
    assert data["actual_outcome"] == "ALLOW"
    assert data["policy_result"] == "PASS"


def test_boundary_probe_missing_file_classified_as_error():
    """Verify that a missing file is classified as ERROR, never DENY or PASS."""
    from fastapi.testclient import TestClient
    from src.server import app

    client = TestClient(app)
    res = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/red/non_existent_fixture.txt",
        "expected_outcome": "DENY",
        "mode": "auto",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["actual_outcome"] == "ERROR"
    assert data["policy_result"] == "FAIL"


def test_boundary_probe_unexpected_access_is_fail():
    """Verify unauthorized access is recorded as policy FAIL even if the syscall succeeds."""
    from fastapi.testclient import TestClient
    from src.server import app

    client = TestClient(app)
    res = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/leaky/blue_leaked.txt",
        "expected_outcome": "DENY",
        "mode": "auto",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["actual_outcome"] == "ALLOW"
    assert data["policy_result"] == "FAIL"
    assert data["is_unexpected_access"] is True


def test_boundary_probe_docker_routing():
    """Verify Docker worker routing and genuine UID reporting when workers are active."""
    from fastapi.testclient import TestClient
    from src.runner import check_docker_environment
    from src.server import app

    docker_env = check_docker_environment()
    if not docker_env["available"]:
        pytest.skip("Docker worker containers are offline; skipping live Docker probe test.")

    client = TestClient(app)

    # 1. Red worker accessing own secret
    red_res = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/red/red_secret.txt",
        "expected_outcome": "ALLOW",
        "mode": "docker",
    })
    assert red_res.status_code == 200
    red_data = red_res.json()
    assert red_data["observed_uid"] == 1001
    assert red_data["observed_gid"] == 1001
    assert red_data["is_os_enforced"] is True
    assert red_data["actual_outcome"] == "ALLOW"
    assert red_data["policy_result"] == "PASS"

    # 2. Red worker accessing blue secret -> OS DAC denial
    cross_res = client.post("/api/boundary-lab/probe", json={
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/blue/blue_secret.txt",
        "expected_outcome": "DENY",
        "mode": "docker",
    })
    assert cross_res.status_code == 200
    cross_data = cross_res.json()
    assert cross_data["observed_uid"] == 1001
    assert cross_data["is_os_enforced"] is True
    assert cross_data["actual_outcome"] == "DENY"
    assert cross_data["policy_result"] == "PASS"
    assert "Permission denied" in cross_data["execution"]["error"]

