"""Evidence Tampering Laboratory for BREACHLINE.

Executes controlled, disposable evidence-tampering simulations without
modifying original evidence files, demonstrating both the detection
capabilities and the documented cryptographic boundaries of hash-chained audit logs.
"""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from src.models import (
    GENESIS_HASH,
    HASHED_FIELDS,
    EvidenceRecord,
    canonical_json_bytes,
    compute_payload_hash,
)
from src.verifier import EvidenceVerifier, VerificationResult

TAMPER_SCRATCH_DIR = Path("output/tamper_scratch")


@dataclass
class TamperExperimentResult:
    attack_id: str
    attack_name: str
    attack_description: str
    tampered_file: str
    transformation_applied: str
    original_snippet: str
    tampered_snippet: str
    verifier_result: Dict[str, Any]
    detected_as_tampered: bool
    is_expected_outcome: bool
    explanation: str
    architectural_note: str
    trust_anchor_check: Optional[Dict[str, Any]] = None


class EvidenceTamperLab:
    """Manages disposable tampering experiments for demonstration and evaluation."""

    def __init__(self, base_evidence_path: str = "output/evidence.jsonl"):
        self.base_evidence_path = Path(base_evidence_path)
        TAMPER_SCRATCH_DIR.mkdir(parents=True, exist_ok=True)

    def _ensure_base_evidence(self) -> List[Dict[str, Any]]:
        """Read original evidence or generate synthetic records if none exists."""
        if self.base_evidence_path.exists():
            records = []
            with open(self.base_evidence_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        records.append(json.loads(clean))
            if len(records) >= 4:
                return records

        # Generate standard synthetic 4-record baseline if no evidence file is found
        from src.evidence import EvidenceRecorder
        scratch_file = TAMPER_SCRATCH_DIR / "synthetic_base.jsonl"
        recorder = EvidenceRecorder(str(scratch_file), run_id="synthetic-tamper-demo-001")
        recorder.record_test("T1", "Red worker reads own secret", "red-worker", "file:read /data/red/red_secret.txt", "ALLOW", "ALLOW", "PASS", 0)
        recorder.record_test("T2", "Red worker cross-reads blue secret", "red-worker", "file:read /data/blue/blue_secret.txt", "DENY", "DENY", "PASS", 1)
        recorder.record_test("T3", "Blue worker reads own secret", "blue-worker", "file:read /data/blue/blue_secret.txt", "ALLOW", "ALLOW", "PASS", 0)
        recorder.record_test("T4", "Negative Control: Red reads leaky fixture", "red-worker", "file:read /data/leaky/blue_leaked.txt", "DENY", "ALLOW", "FAIL", 0)
        return [r.to_dict() for r in recorder.records]

    def run_all_attacks(self) -> List[TamperExperimentResult]:
        """Run all 5 standard tampering attacks and return their results."""
        return [
            self.attack_1_field_modification(),
            self.attack_2_record_deletion(),
            self.attack_3_record_reordering(),
            self.attack_4_broken_hash_link(),
            self.attack_5_full_chain_rewrite(),
        ]

    def attack_1_field_modification(self) -> TamperExperimentResult:
        """Attack 1: Modify a field (e.g., change FAIL to PASS on test T4)."""
        recs = self._ensure_base_evidence()
        target_idx = min(3, len(recs) - 1)
        orig_rec = dict(recs[target_idx])

        # Apply mutation
        tampered_recs = [dict(r) for r in recs]
        tampered_recs[target_idx]["result"] = "PASS"
        tampered_recs[target_idx]["actual_outcome"] = "DENY"

        output_path = TAMPER_SCRATCH_DIR / "attack_1_field_modification.jsonl"
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        detected = not v_res.is_valid and v_res.error_type == "RECORD_HASH_MISMATCH"

        return TamperExperimentResult(
            attack_id="ATTACK_1",
            attack_name="Field Modification (Cover-up)",
            attack_description="Attacker modifies the recorded test outcome from FAIL to PASS without recomputing the SHA-256 hash.",
            tampered_file=str(output_path),
            transformation_applied=f"Modified Record {target_idx + 1} ({orig_rec.get('test_id')}): result 'FAIL' -> 'PASS', actual_outcome 'ALLOW' -> 'DENY'",
            original_snippet=json.dumps(orig_rec, indent=2),
            tampered_snippet=json.dumps(tampered_recs[target_idx], indent=2),
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation=(
                f"The verifier recomputes the SHA-256 hash over the canonical JSON payload. "
                f"Because the fields 'result' and 'actual_outcome' changed, the computed hash "
                f"no longer matches the sealed 'record_hash' stored in the record."
            ),
            architectural_note="Canonical payload serialization prevents whitespace or key ordering evasion.",
        )

    def attack_2_record_deletion(self) -> TamperExperimentResult:
        """Attack 2: Delete a record to conceal a policy evaluation."""
        recs = self._ensure_base_evidence()
        target_idx = 1  # Record T2
        orig_rec = dict(recs[target_idx])

        tampered_recs = [dict(r) for idx, r in enumerate(recs) if idx != target_idx]

        output_path = TAMPER_SCRATCH_DIR / "attack_2_record_deletion.jsonl"
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        detected = not v_res.is_valid and v_res.error_type in ("SEQUENCE_BREAK", "HASH_CHAIN_DISCONTINUITY")

        return TamperExperimentResult(
            attack_id="ATTACK_2",
            attack_name="Record Deletion (Selective Erasure)",
            attack_description="Attacker deletes record 2 (T2) entirely from the log file to conceal the test.",
            tampered_file=str(output_path),
            transformation_applied=f"Removed record index {target_idx} (test_id: {orig_rec.get('test_id')})",
            original_snippet=f"Total records: {len(recs)} (Records 1, 2, 3, 4)",
            tampered_snippet=f"Total records: {len(tampered_recs)} (Record 2 missing)",
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation=(
                f"Record deletion causes two immediate cryptographic failures: "
                f"1) Sequence number jump (Record 3 follows Record 1, expected sequence 2). "
                f"2) Hash chain discontinuity (Record 3's previous_record_hash still points to the deleted record)."
            ),
            architectural_note="Dual sequence numbering and previous-record hash linking prevents undetected deletions.",
        )

    def attack_3_record_reordering(self) -> TamperExperimentResult:
        """Attack 3: Swap two records to alter timeline or causation."""
        recs = self._ensure_base_evidence()
        tampered_recs = [dict(r) for r in recs]
        tampered_recs[0], tampered_recs[1] = tampered_recs[1], tampered_recs[0]

        output_path = TAMPER_SCRATCH_DIR / "attack_3_record_reordering.jsonl"
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        detected = not v_res.is_valid and v_res.error_type in ("SEQUENCE_BREAK", "HASH_CHAIN_DISCONTINUITY")

        return TamperExperimentResult(
            attack_id="ATTACK_3",
            attack_name="Record Reordering (Timeline Shuffling)",
            attack_description="Attacker swaps records 1 and 2 to falsify chronological execution order.",
            tampered_file=str(output_path),
            transformation_applied="Swapped record 1 (T1) and record 2 (T2)",
            original_snippet=f"Order: {recs[0]['test_id']}, {recs[1]['test_id']}",
            tampered_snippet=f"Order: {tampered_recs[0]['test_id']}, {tampered_recs[1]['test_id']}",
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation=(
                f"Swapping records breaks the sequence number expectation (found sequence 2 at line 1, expected 1), "
                f"and breaks the previous_record_hash link (Record 1 must point to GENESIS_HASH)."
            ),
            architectural_note="Genesis requirement and sequential ordering enforce strict chronological immutability.",
        )

    def attack_4_broken_hash_link(self) -> TamperExperimentResult:
        """Attack 4: Corrupt previous_record_hash pointer."""
        recs = self._ensure_base_evidence()
        tampered_recs = [dict(r) for r in recs]
        tampered_recs[2]["previous_record_hash"] = "f" * 64

        output_path = TAMPER_SCRATCH_DIR / "attack_4_broken_hash_link.jsonl"
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        detected = not v_res.is_valid and v_res.error_type in ("HASH_CHAIN_DISCONTINUITY", "RECORD_HASH_MISMATCH")

        return TamperExperimentResult(
            attack_id="ATTACK_4",
            attack_name="Broken Hash Link (Chain Splice)",
            attack_description="Attacker alters previous_record_hash pointer in record 3 to arbitrary hex digits.",
            tampered_file=str(output_path),
            transformation_applied=f"Replaced previous_record_hash in record 3 with {'f'*64}",
            original_snippet=f"previous_record_hash: {recs[2]['previous_record_hash'][:24]}...",
            tampered_snippet=f"previous_record_hash: {'f'*24}...",
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation="The verifier detects that record 3's previous_record_hash does not match the actual hash of record 2.",
            architectural_note="Ensures unbroken cryptographic continuity between all chronological events.",
        )

    def attack_5_full_chain_rewrite(self) -> TamperExperimentResult:
        """Attack 5: Full chain rewrite (Demonstrates documented limitation)."""
        recs = self._ensure_base_evidence()
        tampered_recs = [dict(r) for r in recs]

        # Maliciously falsify record 4 and recompute its hash
        target_idx = min(3, len(tampered_recs) - 1)
        tampered_recs[target_idx]["result"] = "PASS"
        tampered_recs[target_idx]["actual_outcome"] = "DENY"
        tampered_recs[target_idx]["test_description"] = "Falsified outcome with recomputed hash"

        payload = {k: tampered_recs[target_idx][k] for k in HASHED_FIELDS}
        tampered_recs[target_idx]["record_hash"] = compute_payload_hash(payload)

        # If there were further records, attacker would recompute previous_record_hash and record_hash down the chain
        prev_hash = tampered_recs[target_idx]["record_hash"]
        for i in range(target_idx + 1, len(tampered_recs)):
            tampered_recs[i]["previous_record_hash"] = prev_hash
            p = {k: tampered_recs[i][k] for k in HASHED_FIELDS}
            tampered_recs[i]["record_hash"] = compute_payload_hash(p)
            prev_hash = tampered_recs[i]["record_hash"]

        output_path = TAMPER_SCRATCH_DIR / "attack_5_full_chain_rewrite.jsonl"
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        # Note: Internal verification PASSES because all hashes are mathematically recalculated!
        passes_internally = v_res.is_valid

        # Demonstrate trust anchor defense:
        original_tip = recs[-1]["record_hash"]
        anchor_check_res = EvidenceVerifier.verify_file(
            str(output_path),
            anchor_data={"tip_record_hash": original_tip, "total_records": len(recs)}
        )
        anchor_detected = not anchor_check_res.is_valid

        return TamperExperimentResult(
            attack_id="ATTACK_5",
            attack_name="Full-Chain Rewrite (Documented Cryptographic Boundary)",
            attack_description=(
                "Attacker with full write access rewrites record 4 AND recalculates all downstream "
                "SHA-256 hashes, leaving the local file mathematically self-consistent."
            ),
            tampered_file=str(output_path),
            transformation_applied="Rewrote test outcome and recalculated canonical SHA-256 hashes",
            original_snippet=f"Hash: {recs[target_idx]['record_hash'][:24]}... (Result: FAIL)",
            tampered_snippet=f"Hash: {tampered_recs[target_idx]['record_hash'][:24]}... (Result: PASS, recalculated)",
            verifier_result=asdict(v_res),
            detected_as_tampered=not passes_internally,  # False: internal verifier alone cannot detect full rewrite
            is_expected_outcome=passes_internally,        # True: expected limitation behavior!
            explanation=(
                "1. Internal chain verification PASSES because every record correctly references its "
                "predecessor and matches its own recomputed payload hash. This empirically proves the fundamental "
                "security limitation: hash chains provide tamper-evidence relative to an anchor, NOT absolute "
                "proof of history against an attacker who can rewrite the whole file.\n"
                "2. Independent Trust Anchor verification FAILS: When compared against the separately committed run "
                "commitment, the divergence is immediately caught because the tip hash does not match."
            ),
            architectural_note=(
                "To detect full chain rewrites in production, the tip hash or Merkle root must be anchored to "
                "an independent trust anchor (such as BREACHLINE's trust commitment store, RFC 3161 timestamping, or Sigstore/Rekor)."
            ),
            trust_anchor_check={
                "anchor_tested": True,
                "anchor_expected_tip": original_tip,
                "tampered_chain_tip": tampered_recs[-1]["record_hash"],
                "anchor_detected_tampering": anchor_detected,
                "anchor_error_message": anchor_check_res.error_message,
            },
        )


def main():
    lab = EvidenceTamperLab()
    results = lab.run_all_attacks()
    print("=" * 70)
    print("  BREACHLINE EVIDENCE TAMPERING LABORATORY")
    print("=" * 70)
    for r in results:
        status_badge = "[\033[92mDETECTED\033[0m]" if r.detected_as_tampered else "[\033[93mLIMITATION CONFIRMED\033[0m]"
        print(f"\n{r.attack_id}: {r.attack_name} -> {status_badge}")
        print(f"  Description:    {r.attack_description}")
        print(f"  Transformation: {r.transformation_applied}")
        print(f"  Verifier Valid: {r.verifier_result['is_valid']}")
        print(f"  Explanation:    {r.explanation}")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
