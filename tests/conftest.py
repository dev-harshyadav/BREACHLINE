"""Global pytest configuration and test environment isolation fixtures.

Guarantees Requirement P0: Tests must NOT contaminate real project history.
- Every test runs against a clean, isolated pytest temporary directory.
- BREACHLINE_OUTPUT_DIR, storage paths, tamper scratch, and local sandboxes are redirected.
- Production index.json, runs, and trust anchors are left 100% untouched.
"""

from pathlib import Path
import pytest

import src.storage
import src.tamper
import src.local_sandbox
import src.runner
import src.report


@pytest.fixture(autouse=True)
def isolate_test_environment(tmp_path, monkeypatch):
    """Isolate all persistent storage, tamper scratch, and sandbox directories per test."""
    test_out = tmp_path / "test_output"
    runs_dir = test_out / "runs"
    idx_file = runs_dir / "index.json"
    anchors_dir = test_out / "trust_anchors"
    tamper_dir = test_out / "tamper_scratch"
    sandbox_root = test_out / "local_sandbox"
    sandbox_data = sandbox_root / "data"

    test_out.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)
    anchors_dir.mkdir(parents=True, exist_ok=True)
    tamper_dir.mkdir(parents=True, exist_ok=True)
    sandbox_data.mkdir(parents=True, exist_ok=True)

    # Environment variables
    monkeypatch.setenv("BREACHLINE_OUTPUT_DIR", str(test_out))

    # Storage module redirection
    monkeypatch.setattr(src.storage, "OUTPUT_DIR", test_out)
    monkeypatch.setattr(src.storage, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(src.storage, "INDEX_FILE", idx_file)
    monkeypatch.setattr(src.storage, "ANCHORS_DIR", anchors_dir)

    # Runner and report default path redirection
    monkeypatch.setattr(src.runner, "DEFAULT_EVIDENCE_PATH", str(test_out / "evidence.jsonl"))
    monkeypatch.setattr(src.report, "DEFAULT_EVIDENCE_PATH", str(test_out / "evidence.jsonl"))
    monkeypatch.setattr(src.report, "DEFAULT_REPORT_JSON_PATH", str(test_out / "report.json"))
    monkeypatch.setattr(src.report, "DEFAULT_REPORT_TXT_PATH", str(test_out / "report.txt"))
    monkeypatch.setattr(src.report, "DEFAULT_REPORT_HTML_PATH", str(test_out / "report.html"))

    # Tamper lab scratch redirection
    monkeypatch.setattr(src.tamper, "TAMPER_SCRATCH_DIR", tamper_dir)

    # Local sandbox redirection
    monkeypatch.setattr(src.local_sandbox, "SANDBOX_ROOT", sandbox_root)
    monkeypatch.setattr(src.local_sandbox, "SANDBOX_DATA", sandbox_data)

    yield test_out
