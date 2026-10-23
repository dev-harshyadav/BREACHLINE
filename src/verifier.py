"""Independent Evidence Verifier for BREACHLINE.

Independently inspects an evidence JSONL file, validates schemas,
checks sequential ordering, recomputes canonical hashes, and validates
the cryptographic hash chain link by link.

NOTICE:
A hash chain provides tamper-evidence relative to a trusted genesis
or anchor point. It detects field alterations, deletions, and reordering.
However, it cannot prevent a complete chain rewrite if an adversary possesses
the authority to replace the entire log and anchor point.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

from src.models import (
    GENESIS_HASH,
    HASHED_FIELDS,
    SCHEMA_VERSION,
    canonical_json_bytes,
    compute_payload_hash,
)

REQUIRED_FIELDS = [
    "schema_version",
    "run_id",
    "sequence_number",
    "timestamp_utc",
    "test_id",
    "test_description",
    "role",
    "operation",
    "expected_outcome",
    "actual_outcome",
    "result",
    "exit_code",
    "previous_record_hash",
    "record_hash",
]


@dataclass
class VerificationResult:
    is_valid: bool
    total_records: int
    first_error_index: Optional[int] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    anchor_verified: Optional[bool] = None
    anchor_status: Optional[str] = None


class EvidenceVerifier:
    """Independent validator for BREACHLINE hash-chained evidence logs."""

    @staticmethod
    def verify_file(
        file_path: str,
        anchor_data: Optional[Dict[str, Any]] = None,
        anchor_path: Optional[str] = None,
    ) -> VerificationResult:
        path = Path(file_path)
        if not path.exists():
            return VerificationResult(
                is_valid=False,
                total_records=0,
                error_type="FILE_NOT_FOUND",
                error_message=f"Evidence file not found: {file_path}",
            )

        records: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                clean = line.strip()
                if not clean:
                    continue
                try:
                    record = json.loads(clean)
                    records.append(record)
                except json.JSONDecodeError as e:
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(records),
                        first_error_index=line_no,
                        error_type="CORRUPT_JSON",
                        error_message=f"JSON decoding error at line {line_no}: {e}",
                    )

        if not records:
            return VerificationResult(
                is_valid=False,
                total_records=0,
                error_type="EMPTY_FILE",
                error_message="Evidence file contains zero records.",
            )

        expected_prev_hash = GENESIS_HASH
        expected_seq = 1
        run_id: Optional[str] = None

        for idx, rec in enumerate(records, start=1):
            # 1. Check all required fields are present
            missing = [f for f in REQUIRED_FIELDS if f not in rec]
            if missing:
                return VerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    first_error_index=idx,
                    error_type="MISSING_FIELDS",
                    error_message=f"Record {idx} missing required fields: {missing}",
                )

            # 2. Check schema version
            if rec["schema_version"] != SCHEMA_VERSION:
                return VerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    first_error_index=idx,
                    error_type="INVALID_SCHEMA_VERSION",
                    error_message=f"Record {idx} has invalid schema_version '{rec['schema_version']}', expected '{SCHEMA_VERSION}'",
                )

            # 3. Check consistent run_id
            if run_id is None:
                run_id = rec["run_id"]
            elif rec["run_id"] != run_id:
                return VerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    first_error_index=idx,
                    error_type="INCONSISTENT_RUN_ID",
                    error_message=f"Record {idx} run_id '{rec['run_id']}' does not match initial run_id '{run_id}'",
                )

            # 4. Check sequence number ordering
            if rec["sequence_number"] != expected_seq:
                return VerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    first_error_index=idx,
                    error_type="SEQUENCE_BREAK",
                    error_message=(
                        f"Record {idx} has sequence_number {rec['sequence_number']}, "
                        f"expected {expected_seq} (indicates missing or reordered records)"
                    ),
                    details={"expected_sequence": expected_seq, "found_sequence": rec["sequence_number"]},
                )

            # 5. Check previous_record_hash link
            if rec["previous_record_hash"] != expected_prev_hash:
                return VerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    first_error_index=idx,
                    error_type="HASH_CHAIN_DISCONTINUITY",
                    error_message=(
                        f"Record {idx} previous_record_hash mismatch. "
                        f"Expected '{expected_prev_hash[:16]}...', found '{rec['previous_record_hash'][:16]}...'"
                    ),
                    details={
                        "expected_previous_hash": expected_prev_hash,
                        "found_previous_hash": rec["previous_record_hash"],
                    },
                )

            # 6. Recompute hash of canonical payload and compare
            payload = {k: rec[k] for k in HASHED_FIELDS}
            computed_hash = compute_payload_hash(payload)
            recorded_hash = rec["record_hash"]

            if computed_hash != recorded_hash:
                return VerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    first_error_index=idx,
                    error_type="RECORD_HASH_MISMATCH",
                    error_message=(
                        f"Record {idx} content has been modified! "
                        f"Computed '{computed_hash[:16]}...', recorded '{recorded_hash[:16]}...'"
                    ),
                    details={
                        "test_id": rec.get("test_id"),
                        "computed_hash": computed_hash,
                        "recorded_hash": recorded_hash,
                    },
                )

            # Advance expected chain pointer
            expected_prev_hash = recorded_hash
            expected_seq += 1

        # 7. Check against independent trust anchor if provided
        target_anchor = anchor_data
        if not target_anchor and anchor_path and Path(anchor_path).exists():
            try:
                with open(anchor_path, "r", encoding="utf-8") as f:
                    target_anchor = json.load(f)
            except Exception:
                target_anchor = None

        if target_anchor:
            expected_tip = target_anchor.get("tip_record_hash")
            actual_tip = records[-1].get("record_hash") if records else ""
            if expected_tip and actual_tip != expected_tip:
                return VerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    first_error_index=len(records),
                    error_type="TRUST_ANCHOR_MISMATCH",
                    error_message=(
                        f"Full-chain divergence detected! Computed tip record hash '{actual_tip[:16]}...' "
                        f"does not match independently committed trust anchor '{expected_tip[:16]}...'."
                    ),
                    details={
                        "expected_tip_record_hash": expected_tip,
                        "found_tip_record_hash": actual_tip,
                        "anchor_type": target_anchor.get("anchor_type", "INDEPENDENT_COMMITMENT"),
                    },
                    anchor_verified=False,
                    anchor_status="ANCHOR_MISMATCH",
                )

            expected_file_hash = target_anchor.get("evidence_sha256")
            if expected_file_hash:
                actual_file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual_file_hash != expected_file_hash:
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(records),
                        first_error_index=len(records),
                        error_type="TRUST_ANCHOR_FILE_HASH_MISMATCH",
                        error_message="Evidence file SHA-256 does not match independently anchored file digest.",
                        details={
                            "expected_evidence_sha256": expected_file_hash,
                            "found_evidence_sha256": actual_file_hash,
                        },
                        anchor_verified=False,
                        anchor_status="ANCHOR_FILE_HASH_MISMATCH",
                    )

            return VerificationResult(
                is_valid=True,
                total_records=len(records),
                error_type=None,
                error_message=None,
                anchor_verified=True,
                anchor_status="ANCHOR_VERIFIED_MATCH",
            )

        return VerificationResult(
            is_valid=True,
            total_records=len(records),
            error_type=None,
            error_message=None,
            anchor_verified=None,
            anchor_status="INTERNAL_CHAIN_VALID_NO_ANCHOR",
        )


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m src.verifier <path_to_evidence.jsonl>")
        sys.exit(2)

    file_path = sys.argv[1]
    print(f"[BREACHLINE VERIFIER] Inspecting evidence file: {file_path}")
    result = EvidenceVerifier.verify_file(file_path)

    if result.is_valid:
        print(f"[BREACHLINE VERIFIER] PASS: Cryptographic chain verified ({result.total_records} records).")
        print("[BREACHLINE VERIFIER] All record hashes match their canonical payloads.")
        print("[BREACHLINE VERIFIER] Sequence ordering and genesis links intact.")
        sys.exit(0)
    else:
        print(f"[BREACHLINE VERIFIER] FAIL: Verification failed at record {result.first_error_index}!")
        print(f"  Error Type: {result.error_type}")
        print(f"  Reason:     {result.error_message}")
        if result.details:
            print(f"  Details:    {result.details}")
        sys.exit(1)


if __name__ == "__main__":
    main()
