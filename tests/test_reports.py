"""Unit tests for the Report Generator."""

import json
import os
import tempfile

import pytest

from src.evidence import EvidenceRecorder
from src.report import generate_report


@pytest.fixture
def sample_evidence():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        path = tmp.name

    recorder = EvidenceRecorder(path, run_id="rep-run-99")
    recorder.record_test("T1", "Red reads own", "red-worker", "file:read /data/red.txt", "ALLOW", "ALLOW", "PASS", 0)
    recorder.record_test("T2", "Red reads blue", "red-worker", "file:read /data/blue.txt", "DENY", "DENY", "PASS", 1)
    recorder.record_test("T3", "Blue reads own", "blue-worker", "file:read /data/blue.txt", "ALLOW", "ALLOW", "PASS", 0)
    recorder.record_test("T4", "Negative control", "red-worker", "file:read /data/leaky.txt", "DENY", "ALLOW", "FAIL", 0)

    yield path

    if os.path.exists(path):
        os.remove(path)


def test_report_generation(sample_evidence):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_json, \
         tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp_txt:
        json_path = tmp_json.name
        txt_path = tmp_txt.name

    try:
        data = generate_report(
            evidence_path=sample_evidence,
            report_json_path=json_path,
            report_txt_path=txt_path,
        )

        assert data["run_id"] == "rep-run-99"
        assert data["total_tests"] == 4
        assert data["passed_tests"] == 3
        assert data["failed_tests"] == 1
        assert data["evidence_verification"]["status"] == "VALID"
        assert len(data["known_limitations"]) >= 3

        # Verify JSON file on disk
        with open(json_path, "r", encoding="utf-8") as f:
            disk_json = json.load(f)
        assert disk_json["run_id"] == "rep-run-99"

        # Verify TXT file on disk
        with open(txt_path, "r", encoding="utf-8") as f:
            txt_content = f.read()

        assert "BREACHLINE TEST EVALUATION REPORT" in txt_content
        assert "NEGATIVE CONTROL ANALYSIS" in txt_content
        assert "KNOWN LIMITATIONS & SECURITY SCOPE" in txt_content
        assert "VALID (Tamper-evidence checks PASSED)" in txt_content

    finally:
        if os.path.exists(json_path):
            os.remove(json_path)
        if os.path.exists(txt_path):
            os.remove(txt_path)
