"""Evidence recorder for BREACHLINE.

Records structured test execution records into a tamper-evident,
hash-chained JSON Lines (JSONL) file.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import List, Optional
import uuid

from src.models import (
    GENESIS_HASH,
    HASHED_FIELDS,
    SCHEMA_VERSION,
    EvidenceRecord,
    canonical_json_bytes,
    compute_payload_hash,
)


class EvidenceRecorder:
    """Manages the creation and writing of hash-chained evidence records."""

    def __init__(self, output_path: str, run_id: Optional[str] = None):
        self.output_path = Path(output_path)
        self.run_id = run_id or str(uuid.uuid4())
        self.sequence_number = 0
        self.last_record_hash = GENESIS_HASH
        self.records: List[EvidenceRecord] = []

        # Ensure parent directory exists
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        # Clear or initialize the evidence file
        if self.output_path.exists():
            self.output_path.unlink()

    def record_test(
        self,
        test_id: str,
        test_description: str,
        role: str,
        operation: str,
        expected_outcome: str,
        actual_outcome: str,
        result: str,
        exit_code: int,
        timestamp_utc: Optional[str] = None,
    ) -> EvidenceRecord:
        """Create, hash, chain, and write a new evidence record.
        
        Fields covered by the record_hash:
        - schema_version
        - run_id
        - sequence_number
        - timestamp_utc
        - test_id
        - test_description
        - role
        - operation
        - expected_outcome
        - actual_outcome
        - result
        - exit_code
        - previous_record_hash
        
        The field 'record_hash' is intentionally EXCLUDED from its own payload.
        """
        self.sequence_number += 1
        if timestamp_utc is None:
            timestamp_utc = datetime.now(timezone.utc).isoformat()

        record = EvidenceRecord(
            schema_version=SCHEMA_VERSION,
            run_id=self.run_id,
            sequence_number=self.sequence_number,
            timestamp_utc=timestamp_utc,
            test_id=test_id,
            test_description=test_description,
            role=role,
            operation=operation,
            expected_outcome=expected_outcome,
            actual_outcome=actual_outcome,
            result=result,
            exit_code=exit_code,
            previous_record_hash=self.last_record_hash,
        )

        # Compute hash deterministically
        record.record_hash = record.compute_hash()

        # Update last hash for next chained record
        self.last_record_hash = record.record_hash
        self.records.append(record)

        # Append to JSONL file
        record_dict = record.to_dict()
        with open(self.output_path, "a", encoding="utf-8") as f:
            # Write single line JSON
            line = json.dumps(record_dict, sort_keys=True, separators=(",", ":"))
            f.write(line + "\n")

        return record
