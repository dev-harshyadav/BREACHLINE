"""Regression tests for persistent history isolation (P0).

Verifies that running tests never contaminates or alters the real project
output directory (output/runs, output/trust_anchors, output/runs/index.json).
"""

import hashlib
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from src.server import app
from src.runner import TestRunner


def snapshot_dir(dir_path: Path) -> dict:
    """Compute recursive fingerprint of directory."""
    if not dir_path.exists():
        return {}
    fingerprint = {}
    for p in sorted(dir_path.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(dir_path))
            try:
                content_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                fingerprint[rel] = content_hash
            except Exception:
                pass
    return fingerprint


def test_test_suite_leaves_production_history_unchanged(tmp_path):
    """Verify that running test scenarios does not alter the real production output directory."""
    prod_output = Path(__file__).resolve().parent.parent / "output"
    
    # 1. Snapshot real output directory
    snapshot_before = snapshot_dir(prod_output)

    # 2. Execute boundary test run via TestRunner
    ev_path = str(tmp_path / "test_runner_ev.jsonl")
    runner = TestRunner(
        config_path="config/test_cases.json",
        evidence_path=ev_path,
        run_id="test-isolation-run",
        mode="simulated"
    )
    summary = runner.run_all(verify_workers=False)
    assert summary["total"] >= 4

    # 3. Trigger API run
    client = TestClient(app)
    resp = client.post("/api/runs/execute", json={"mode": "simulated"})
    assert resp.status_code == 200

    # 4. Snapshot real output directory again
    snapshot_after = snapshot_dir(prod_output)

    # 5. Must be 100% identical: no new files, no modified files in real output/
    assert snapshot_before == snapshot_after, "Test execution leaked files into production output directory!"

