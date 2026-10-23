"""Unit tests for Evidence Recorder and canonical serialization."""

import hashlib
import json
import os
import tempfile

import pytest

from src.evidence import EvidenceRecorder
from src.models import (
    GENESIS_HASH,
    HASHED_FIELDS,
    SCHEMA_VERSION,
    EvidenceRecord,
    canonical_json_bytes,
    compute_payload_hash,
)


def test_canonical_json_bytes_determinism():
    """Verify that dictionary key insertion order does not affect canonical bytes."""
    d1 = {"b": 2, "a": 1, "c": {"y": "yes", "x": "no"}}
    d2 = {"a": 1, "c": {"x": "no", "y": "yes"}, "b": 2}

    b1 = canonical_json_bytes(d1)
    b2 = canonical_json_bytes(d2)

    assert b1 == b2
    assert b1 == b'{"a":1,"b":2,"c":{"x":"no","y":"yes"}}'
    assert b" " not in b1  # No whitespace separators


def test_compute_payload_hash():
    """Verify SHA-256 hash computation over canonical payload."""
    payload = {"k": "v", "num": 100}
    expected_bytes = b'{"k":"v","num":100}'
    expected_hash = hashlib.sha256(expected_bytes).hexdigest()

    assert compute_payload_hash(payload) == expected_hash


def test_record_hash_excludes_itself():
    """Verify that record_hash is strictly excluded from its own hash calculation."""
    record = EvidenceRecord(
        schema_version=SCHEMA_VERSION,
        run_id="run-001",
        sequence_number=1,
        timestamp_utc="2026-10-15T00:00:00Z",
        test_id="T1",
        test_description="Test 1",
        role="red-worker",
        operation="file:read /data/red.txt",
        expected_outcome="ALLOW",
        actual_outcome="ALLOW",
        result="PASS",
        exit_code=0,
        previous_record_hash=GENESIS_HASH,
        record_hash="SHOULD_NOT_BE_IN_PAYLOAD",
    )

    payload = record.get_hashable_payload()
    assert "record_hash" not in payload
    assert len(payload) == len(HASHED_FIELDS)


def test_evidence_recorder_chaining():
    """Verify that EvidenceRecorder creates a properly chained sequence of records."""
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        recorder = EvidenceRecorder(tmp_path, run_id="test-run-123")
        r1 = recorder.record_test("T1", "Desc 1", "red-worker", "op1", "ALLOW", "ALLOW", "PASS", 0)
        r2 = recorder.record_test("T2", "Desc 2", "red-worker", "op2", "DENY", "DENY", "PASS", 1)
        r3 = recorder.record_test("T3", "Desc 3", "blue-worker", "op3", "ALLOW", "ALLOW", "PASS", 0)

        # Check sequence numbers
        assert r1.sequence_number == 1
        assert r2.sequence_number == 2
        assert r3.sequence_number == 3

        # Check genesis link
        assert r1.previous_record_hash == GENESIS_HASH

        # Check subsequent hash links
        assert r2.previous_record_hash == r1.record_hash
        assert r3.previous_record_hash == r2.record_hash

        # Verify disk file format
        with open(tmp_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        assert len(lines) == 3
        assert lines[0]["record_hash"] == r1.record_hash
        assert lines[1]["record_hash"] == r2.record_hash
        assert lines[2]["record_hash"] == r3.record_hash
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
