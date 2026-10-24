"""Unit tests for the Evidence Tampering Laboratory."""

import os
from pathlib import Path
import pytest

from src.tamper import EvidenceTamperLab


def test_tamper_lab_all_attacks():
    """Verify that tamper lab runs all 6 attacks safely on disposable copies."""
    lab = EvidenceTamperLab()
    results = lab.run_all_attacks()

    assert len(results) == 6

    # Attacks 1-4 must be mathematically detected by the independent verifier
    for r in results[:4]:
        assert r.detected_as_tampered is True
        assert r.verifier_result["is_valid"] is False

    # Attack 5 (Full-Chain Rewrite) confirms documented limitation:
    # Internal verifier alone passes because all downstream hashes were recomputed.
    attack5 = results[4]
    assert attack5.attack_id == "ATTACK_5"
    assert attack5.verifier_result["is_valid"] is True
    assert "anchor" in attack5.architectural_note.lower()

    # Attack 6 (Tail Truncation) confirms the record count check against the anchor:
    # Internal chain passes prefix, but anchor detects truncation.
    attack6 = results[5]
    assert attack6.attack_id == "ATTACK_6"
    assert attack6.detected_as_tampered is True
    assert attack6.verifier_result["is_valid"] is True  # remaining prefix is valid chain
    assert attack6.trust_anchor_check["anchor_detected_tampering"] is True
    assert "count" in attack6.trust_anchor_check["anchor_error_message"].lower()


def test_tamper_lab_operates_on_disposable_copy_and_preserves_original(tmp_path):
    """Verify that tamper experiments never modify the original evidence."""
    from src.storage import persist_run, RUNS_DIR
    from src.evidence import EvidenceRecorder
    import json

    run_id = "test-tamper-isolation"
    ev_file = tmp_path / "scratch_ev.jsonl"
    recorder = EvidenceRecorder(output_path=ev_file, run_id=run_id)
    r1 = recorder.record_test(
        test_id="T1",
        test_description="Test T1",
        role="red-worker",
        operation="file:read /data/shared/doc.txt",
        expected_outcome="ALLOW",
        actual_outcome="ALLOW",
        result="PASS",
        exit_code=0
    )
    r2 = recorder.record_test(
        test_id="T2",
        test_description="Test T2",
        role="blue-worker",
        operation="file:read /data/restricted/secret.txt",
        expected_outcome="DENY",
        actual_outcome="DENY",
        result="PASS",
        exit_code=1
    )
    records = [r1.to_dict(), r2.to_dict()]
    test_cases = [
        {"test_id": "T1", "role": "red-worker", "operation": "file:read /data/shared/doc.txt", "expected_outcome": "ALLOW"},
        {"test_id": "T2", "role": "blue-worker", "operation": "file:read /data/restricted/secret.txt", "expected_outcome": "DENY"}
    ]
    summary = {"total": 2, "passed": 2, "failed": 0, "errors": 0}
    persist_run(run_id=run_id, test_cases=test_cases, records=records, summary=summary, execution_mode="local_sandbox")

    orig_evidence_path = RUNS_DIR / run_id / "evidence.jsonl"
    orig_content = orig_evidence_path.read_text(encoding="utf-8")

    lab = EvidenceTamperLab(run_id=run_id)
    results = lab.run_all_attacks()

    # Original evidence must remain completely unchanged
    assert orig_evidence_path.read_text(encoding="utf-8") == orig_content
    # Each tampered file must be a separate file in scratch dir
    for r in results:
        assert r.tampered_file != str(orig_evidence_path)
        assert Path(r.tampered_file).exists()


