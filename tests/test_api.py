"""Integration tests for BREACHLINE FastAPI REST server."""

import pytest
from fastapi.testclient import TestClient

from src.server import app

client = TestClient(app)


def test_api_status_endpoint():
    """Verify /api/status returns valid system diagnostics and metrics."""
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "system_info" in data
    assert "metrics" in data
    assert "docker_environment" in data


def test_api_runs_and_execution_flow():
    """Verify triggering a test run and retrieving run details via API."""
    # Execute a run
    exec_res = client.post("/api/runs/execute", json={"mode": "local_sandbox"})
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["success"] is True
    run_id = exec_data["run_id"]

    # Verify run appears in /api/runs
    list_res = client.get("/api/runs")
    assert list_res.status_code == 200
    runs = list_res.json()["runs"]
    assert any(r["run_id"] == run_id for r in runs)

    # Fetch run details
    detail_res = client.get(f"/api/runs/{run_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["meta"]["run_id"] == run_id
    assert len(detail["records"]) == 4

    # Verify evidence chain
    verif_res = client.get(f"/api/runs/{run_id}/verify")
    assert verif_res.status_code == 200
    verif_data = verif_res.json()
    assert verif_data["is_valid"] is True
    assert len(verif_data["chain"]) == 4


def test_api_tamper_demo_endpoint():
    """Verify /api/tamper/execute runs disposable simulations."""
    res = client.post("/api/tamper/execute", json={"attack_id": "ATTACK_1"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    experiments = data["experiments"]
    assert len(experiments) == 1
    assert experiments[0]["attack_id"] == "ATTACK_1"
    assert experiments[0]["detected_as_tampered"] is True


def test_api_boundary_probe_endpoint():
    """Verify /api/boundary-lab/probe executes safe interactive probes."""
    probe_payload = {
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/red/red_secret.txt",
        "expected_outcome": "ALLOW",
        "test_description": "API Probe Test",
    }
    res = client.post("/api/boundary-lab/probe", json=probe_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["actual_outcome"] == "ALLOW"
    assert data["policy_result"] == "PASS"

    # Test rejection of directory traversal
    bad_probe = {
        "role": "red-worker",
        "operation": "file:read",
        "target_path": "/data/red/../../etc/passwd",
        "expected_outcome": "DENY",
        "test_description": "Bad probe",
    }
    bad_res = client.post("/api/boundary-lab/probe", json=bad_probe)
    assert bad_res.status_code == 400


def test_api_run_id_path_traversal_rejection():
    """Verify that path traversal in run_id parameter is rejected."""
    traversal_res = client.get("/api/runs/../../etc/passwd")
    assert traversal_res.status_code in (400, 404)

    traversal_verify = client.get("/api/runs/../../etc/passwd/verify")
    assert traversal_verify.status_code in (400, 404)


def test_api_execute_rejects_malformed_scenario():
    """Verify that /api/runs/execute validates scenario parameters."""
    bad_payload = {
        "mode": "simulated",
        "test_cases": [
            {
                "test_id": "T_MAL",
                "role": "invalid-role",
                "operation": "file:read",
                "target_path": "/data/red/red_secret.txt",
                "expected_outcome": "ALLOW",
            }
        ],
    }
    res = client.post("/api/runs/execute", json=bad_payload)
    assert res.status_code == 400
    assert "Invalid worker role" in res.json().get("detail", "")


def test_api_status_empty_runs_handling(monkeypatch):
    """Verify /api/status handles empty run index gracefully without dividing by zero."""
    monkeypatch.setattr("src.server.load_runs_index", lambda: [])
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["metrics"]["total_runs"] == 0
    assert data["metrics"]["total_cases_executed"] == 0
    assert data["latest_run"] is None


def test_api_status_cumulative_metrics():
    """Verify /api/status returns structured cumulative metrics."""
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "cumulative" in data["metrics"]
    cum = data["metrics"]["cumulative"]
    assert "total_runs" in cum
    assert "total_cases_executed" in cum
    assert "policy_matches" in cum
    assert "policy_mismatches" in cum


def test_api_report_formats_and_evidence():
    """Verify HTML, JSON, TXT report endpoints and raw evidence download."""
    # Execute a run
    exec_res = client.post("/api/runs/execute", json={"mode": "local_sandbox"})
    assert exec_res.status_code == 200
    run_id = exec_res.json()["run_id"]

    # 1. HTML report
    html_res = client.get(f"/api/runs/{run_id}/report?format=html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers.get("content-type", "")
    assert run_id[:8] in html_res.text

    # 2. JSON report
    json_res = client.get(f"/api/runs/{run_id}/report?format=json")
    assert json_res.status_code == 200
    report_data = json_res.json()
    assert report_data["run_id"] == run_id
    assert "trust_anchor" in report_data

    # 3. TXT report
    txt_res = client.get(f"/api/runs/{run_id}/report?format=txt")
    assert txt_res.status_code == 200
    assert "BREACHLINE TEST EVALUATION REPORT" in txt_res.text

    # 4. Evidence download
    ev_res = client.get(f"/api/runs/{run_id}/evidence")
    assert ev_res.status_code == 200
    lines = ev_res.text.strip().split("\n")
    assert len(lines) == 4

    # 5. Anchor retrieval
    anchor_res = client.get(f"/api/runs/{run_id}/anchor")
    assert anchor_res.status_code == 200
    assert anchor_res.json()["run_id"] == run_id


