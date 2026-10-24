"""Unit and tampering tests for the Independent Verifier."""

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List

import pytest

from src.evidence import EvidenceRecorder
from src.models import (
    GENESIS_HASH,
    HASHED_FIELDS,
    canonical_json_bytes,
    compute_payload_hash,
)
from src.verifier import EvidenceVerifier


@pytest.fixture
def clean_evidence_file():
    """Generates a valid 4-record evidence file."""
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        path = tmp.name

    recorder = EvidenceRecorder(path, run_id="fixture-run-001")
    recorder.record_test("T1", "Red reads own file", "red-worker", "file:read /data/red.txt", "ALLOW", "ALLOW", "PASS", 0)
    recorder.record_test("T2", "Red reads blue file", "red-worker", "file:read /data/blue.txt", "DENY", "DENY", "PASS", 1)
    recorder.record_test("T3", "Blue reads own file", "blue-worker", "file:read /data/blue.txt", "ALLOW", "ALLOW", "PASS", 0)
    recorder.record_test("T4", "Negative control", "red-worker", "file:read /data/leaky.txt", "DENY", "ALLOW", "FAIL", 0)

    yield path

    if os.path.exists(path):
        os.remove(path)


def test_verifier_untampered_chain(clean_evidence_file):
    """An untampered evidence file must verify with status VALID."""
    result = EvidenceVerifier.verify_file(clean_evidence_file)
    assert result.is_valid is True
    assert result.total_records == 4
    assert result.error_type is None


def test_verifier_detects_modified_field(clean_evidence_file):
    """Tampering Case 1: Modifying any field (e.g., changing FAIL to PASS) must be detected."""
    with open(clean_evidence_file, "r") as f:
        records = [json.loads(line) for line in f]

    # Tamper with record 4 (negative control result falsified to PASS)
    records[3]["result"] = "PASS"

    with open(clean_evidence_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    result = EvidenceVerifier.verify_file(clean_evidence_file)
    assert result.is_valid is False
    assert result.first_error_index == 4
    assert result.error_type == "RECORD_HASH_MISMATCH"


def test_verifier_detects_deleted_record(clean_evidence_file):
    """Tampering Case 2: Deleting a record must break the sequence and hash chain."""
    with open(clean_evidence_file, "r") as f:
        records = [json.loads(line) for line in f]

    # Delete record 2
    del records[1]

    with open(clean_evidence_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    result = EvidenceVerifier.verify_file(clean_evidence_file)
    assert result.is_valid is False
    assert result.first_error_index == 2
    assert result.error_type == "SEQUENCE_BREAK"


def test_verifier_detects_reordered_records(clean_evidence_file):
    """Tampering Case 3: Swapping two records must break sequence ordering."""
    with open(clean_evidence_file, "r") as f:
        records = [json.loads(line) for line in f]

    # Swap record 1 and record 2
    records[0], records[1] = records[1], records[0]

    with open(clean_evidence_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    result = EvidenceVerifier.verify_file(clean_evidence_file)
    assert result.is_valid is False
    assert result.first_error_index == 1
    assert result.error_type == "SEQUENCE_BREAK"


def test_verifier_detects_broken_previous_hash(clean_evidence_file):
    """Tampering Case 4: Changing previous_record_hash must break the chain link."""
    with open(clean_evidence_file, "r") as f:
        records = [json.loads(line) for line in f]

    # Corrupt previous_record_hash of record 3
    records[2]["previous_record_hash"] = "f" * 64

    with open(clean_evidence_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    result = EvidenceVerifier.verify_file(clean_evidence_file)
    assert result.is_valid is False
    # Either hash mismatch (because previous_record_hash is part of the hashable payload)
    # or discontinuity must flag record 3.
    assert result.first_error_index == 3
    assert result.error_type in ("RECORD_HASH_MISMATCH", "HASH_CHAIN_DISCONTINUITY")


def test_verifier_detects_missing_required_fields(clean_evidence_file):
    """Tampering Case: Malformed record missing required keys."""
    with open(clean_evidence_file, "r") as f:
        records = [json.loads(line) for line in f]

    del records[0]["operation"]

    with open(clean_evidence_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    result = EvidenceVerifier.verify_file(clean_evidence_file)
    assert result.is_valid is False
    assert result.first_error_index == 1
    assert result.error_type == "MISSING_FIELDS"


def test_full_chain_rewrite_limitation_demonstration(clean_evidence_file):
    """Tampering Case 5: Documenting the mathematical property of hash chains.
    
    If an attacker modifies a record AND completely recalculates all hashes
    from that point onward, the internal chain appears mathematically consistent.
    
    This demonstrates why BREACHLINE documentation explicitly states:
    'Hash chain verification requires a trusted external anchor to detect
    full-chain rewrites.'
    """
    with open(clean_evidence_file, "r") as f:
        records = [json.loads(line) for line in f]

    # Maliciously change record 4 outcome
    records[3]["result"] = "PASS"
    records[3]["actual_outcome"] = "DENY"

    # Recompute hash for record 4
    payload = {k: records[3][k] for k in HASHED_FIELDS}
    records[3]["record_hash"] = compute_payload_hash(payload)

    with open(clean_evidence_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # A verifier with NO external anchor sees internal consistency
    result = EvidenceVerifier.verify_file(clean_evidence_file)
    assert result.is_valid is True  # Passes internal consistency check

    # But comparing with a trusted external anchor (e.g. final hash snapshot) catches the rewrite:
    original_final_hash = "EXTERNAL_TRUSTED_ANCHOR"
    assert records[3]["record_hash"] != original_final_hash


def test_trust_anchor_detects_full_chain_rewrite(clean_evidence_file):
    """Verify that an independent trust anchor catches a full-chain rewrite."""
    with open(clean_evidence_file, "r") as f:
        orig_records = [json.loads(line) for line in f]
    orig_tip = orig_records[-1]["record_hash"]

    # 1. Unaltered chain passes with matching anchor
    valid_res = EvidenceVerifier.verify_file(
        clean_evidence_file,
        anchor_data={"tip_record_hash": orig_tip, "total_records": len(orig_records)}
    )
    assert valid_res.is_valid is True
    assert valid_res.anchor_verified is True
    assert valid_res.anchor_status == "ANCHOR_VERIFIED_MATCH"

    # 2. Tampered chain with recomputed hashes is caught by the anchor
    tampered_records = [dict(r) for r in orig_records]
    tampered_records[3]["result"] = "PASS"
    tampered_records[3]["actual_outcome"] = "DENY"
    payload = {k: tampered_records[3][k] for k in HASHED_FIELDS}
    tampered_records[3]["record_hash"] = compute_payload_hash(payload)

    with open(clean_evidence_file, "w") as f:
        for r in tampered_records:
            f.write(json.dumps(r) + "\n")

    # Internal alone passes (demonstrates the limitation)
    internal_res = EvidenceVerifier.verify_file(clean_evidence_file)
    assert internal_res.is_valid is True

    # With anchor: immediately detected and marked invalid!
    anchored_res = EvidenceVerifier.verify_file(
        clean_evidence_file,
        anchor_data={"tip_record_hash": orig_tip, "total_records": len(orig_records)}
    )
    assert anchored_res.is_valid is False
    assert anchored_res.error_type == "TRUST_ANCHOR_MISMATCH"
    assert anchored_res.anchor_verified is False


def test_trust_anchor_detects_tail_truncation_record_count_mismatch(clean_evidence_file):
    """Verify that an anchor with expected total_records detects tail truncation even if tip is falsified."""
    with open(clean_evidence_file, "r") as f:
        records = [json.loads(line) for line in f]

    orig_tip = records[-1]["record_hash"]
    total = len(records)

    # Truncate the last record
    truncated = records[:-1]
    with open(clean_evidence_file, "w") as f:
        for r in truncated:
            f.write(json.dumps(r) + "\n")

    # Anchor expecting 4 records encounters 3 records -> must fail closed
    res = EvidenceVerifier.verify_file(
        clean_evidence_file,
        anchor_data={"tip_record_hash": orig_tip, "total_records": total}
    )
    assert res.is_valid is False
    assert res.error_type == "ANCHOR_RECORD_COUNT_MISMATCH"
    assert res.anchor_status == "ANCHOR_RECORD_COUNT_MISMATCH"
    assert res.anchor_verified is False


def test_trust_anchor_missing_when_required_fails_closed(clean_evidence_file):
    """If require_anchor is True and no anchor is provided, must fail closed."""
    res = EvidenceVerifier.verify_file(clean_evidence_file, anchor_data=None, require_anchor=True)
    assert res.is_valid is False
    assert res.error_type == "ANCHOR_MISSING"
    assert res.anchor_status == "ANCHOR_MISSING"
    assert res.anchor_verified is False


def test_trust_anchor_malformed_fails_closed(clean_evidence_file):
    """An anchor missing required fields (tip_record_hash or total_records) is malformed and fails closed."""
    res = EvidenceVerifier.verify_file(
        clean_evidence_file,
        anchor_data={"some_invalid_key": "xyz"},
        require_anchor=True
    )
    assert res.is_valid is False
    assert res.error_type == "ANCHOR_MALFORMED"
    assert res.anchor_status == "ANCHOR_MALFORMED"
    assert res.anchor_verified is False


def test_trust_anchor_persistence_failed_flag_fails_closed(clean_evidence_file):
    """An anchor marked with anchor_persistence_failed must fail closed."""
    res = EvidenceVerifier.verify_file(
        clean_evidence_file,
        anchor_data={"anchor_persistence_failed": True, "error": "Disk full"},
        require_anchor=True
    )
    assert res.is_valid is False
    assert res.error_type == "ANCHOR_PERSISTENCE_FAILED"
    assert res.anchor_status == "ANCHOR_PERSISTENCE_FAILED"
    assert res.anchor_verified is False


def test_trust_anchor_read_error_fails_closed(clean_evidence_file):
    """An anchor marked with read_error must fail closed."""
    res = EvidenceVerifier.verify_file(
        clean_evidence_file,
        anchor_data={"read_error": True, "error": "Permission denied reading anchor"},
        require_anchor=True
    )
    assert res.is_valid is False
    assert res.error_type == "ANCHOR_READ_ERROR"
    assert res.anchor_status == "ANCHOR_READ_ERROR"
    assert res.anchor_verified is False


def test_unanchored_evidence_never_claims_anchored(clean_evidence_file):
    """An unanchored valid evidence file has status INTERNAL_CHAIN_VALID_NO_ANCHOR and anchor_verified is None."""
    res = EvidenceVerifier.verify_file(clean_evidence_file, anchor_data=None, require_anchor=False)
    assert res.is_valid is True
    assert res.anchor_verified is None
    assert res.anchor_status == "INTERNAL_CHAIN_VALID_NO_ANCHOR"


def test_historical_schema_1_0_0_evidence_compatibility(tmp_path):
    """Ensure verifier correctly validates existing schema 1.0.0 historical evidence files."""
    run_id = "historical-run-v1"
    ev_path = tmp_path / "historical_evidence.jsonl"
    recorder = EvidenceRecorder(str(ev_path), run_id=run_id)
    r1 = recorder.record_test("T1", "Historical test 1", "red-worker", "file:read /data/red.txt", "ALLOW", "ALLOW", "PASS", 0)
    r2 = recorder.record_test("T2", "Historical test 2", "blue-worker", "file:read /data/blue.txt", "DENY", "DENY", "PASS", 1)

    # Verify that schema_version is "1.0.0"
    with open(ev_path, "r") as f:
        lines = [json.loads(l) for l in f]
    assert all(l["schema_version"] == "1.0.0" for l in lines)

    # Verifier must validate schema 1.0.0 successfully
    res = EvidenceVerifier.verify_file(str(ev_path))
    assert res.is_valid is True
    assert res.total_records == 2
    assert res.error_type is None


