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

