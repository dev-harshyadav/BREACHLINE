"""Data models and canonical serialization for BREACHLINE."""

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Dict, List, Optional

SCHEMA_VERSION: str = "1.0.0"
GENESIS_HASH: str = "0" * 64  # Documented 64-zero SHA-256 genesis hash

# Exact list of payload keys covered by record_hash in canonical serialization
HASHED_FIELDS: List[str] = [
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
]


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """Serialize a dictionary into deterministic canonical JSON bytes.
    
    Rules:
    - Keys sorted lexicographically
    - Compact separators (no trailing spaces: comma and colon only)
    - UTF-8 encoded
    - ASCII safe
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    ).encode("utf-8")


def compute_payload_hash(payload: Dict[str, Any]) -> str:
    """Calculate the SHA-256 hex digest for a canonical dictionary payload."""
    data = canonical_json_bytes(payload)
    return hashlib.sha256(data).hexdigest()


@dataclass
class EvidenceRecord:
    schema_version: str
    run_id: str
    sequence_number: int
    timestamp_utc: str
    test_id: str
    test_description: str
    role: str
    operation: str
    expected_outcome: str  # "ALLOW" or "DENY"
    actual_outcome: str    # "ALLOW" or "DENY"
    result: str            # "PASS" or "FAIL"
    exit_code: int
    previous_record_hash: str
    record_hash: str = ""

    def get_hashable_payload(self) -> Dict[str, Any]:
        """Return the dictionary of fields covered by record_hash (excluding record_hash)."""
        d = asdict(self)
        return {k: d[k] for k in HASHED_FIELDS if k in d}

    def compute_hash(self) -> str:
        """Compute the canonical SHA-256 hash of this record's hashable payload."""
        return compute_payload_hash(self.get_hashable_payload())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary suitable for JSON serialization."""
        d = asdict(self)
        if not self.record_hash:
            d["record_hash"] = self.compute_hash()
        return d


@dataclass
class TestCase:
    __test__ = False
    test_id: str
    test_description: str
    role: str
    operation: str
    target_path: str
    expected_outcome: str
    is_negative_control: bool = False
