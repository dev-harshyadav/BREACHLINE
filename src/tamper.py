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
import uuid

from src.models import (
    GENESIS_HASH,
    HASHED_FIELDS,
    EvidenceRecord,
    canonical_json_bytes,
    compute_payload_hash,
)
from src.storage import ANCHORS_DIR, OUTPUT_DIR, RUNS_DIR, get_run, get_run_anchor, is_safe_run_id
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
    anchor_provenance: str = "GENUINE_COMMITTED_ANCHOR"
    trust_anchor_check: Optional[Dict[str, Any]] = None


class EvidenceTamperLab:
    """Manages disposable tampering experiments for demonstration and evaluation."""

    def __init__(
        self,
        base_evidence_path: Optional[str] = None,
        run_id: Optional[str] = None,
    ):
        self.run_id = run_id if (run_id and is_safe_run_id(run_id)) else None
        TAMPER_SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
        self.anchor_data: Optional[Dict[str, Any]] = None
        self.anchor_provenance = "MISSING"

        if self.run_id:
            run_info = get_run(self.run_id)
            if run_info and "evidence_file" in run_info and Path(run_info["evidence_file"]).exists():
                self.base_evidence_path = Path(run_info["evidence_file"])
            else:
                self.base_evidence_path = RUNS_DIR / self.run_id / "evidence.jsonl"
            self.anchor_data = get_run_anchor(self.run_id)
            if self.anchor_data:
                self.anchor_provenance = "GENUINE_COMMITTED_ANCHOR"
        elif base_evidence_path:
            self.base_evidence_path = Path(base_evidence_path)
        else:
            self.base_evidence_path = OUTPUT_DIR / "evidence.jsonl"

    def _ensure_base_evidence(self) -> List[Dict[str, Any]]:
        """Read original evidence or generate explicitly labeled synthetic records if none exists."""
        if self.base_evidence_path and self.base_evidence_path.exists():
            records = []
            with open(self.base_evidence_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        records.append(json.loads(clean))
            if len(records) >= 3:
                if not self.anchor_data:
                    # Look up anchor by run_id in the evidence records
                    rec_run_id = records[0].get("run_id")
                    if rec_run_id and is_safe_run_id(rec_run_id):
                        self.anchor_data = get_run_anchor(rec_run_id)
                        if self.anchor_data:
                            self.anchor_provenance = "GENUINE_COMMITTED_ANCHOR"
                return records

        # Generate standard labeled synthetic baseline if no evidence file is found
        self.anchor_provenance = "SYNTHETIC"
        from src.evidence import EvidenceRecorder
        scratch_file = TAMPER_SCRATCH_DIR / f"synthetic_base_{uuid.uuid4().hex[:8]}.jsonl"
        recorder = EvidenceRecorder(str(scratch_file), run_id="synthetic-tamper-demo-001")
        recorder.record_test("T1", "Red worker reads own secret", "red-worker", "file:read /data/red/red_secret.txt", "ALLOW", "ALLOW", "PASS", 0)
        recorder.record_test("T2", "Red worker cross-reads blue secret", "red-worker", "file:read /data/blue/blue_secret.txt", "DENY", "DENY", "PASS", 1)
        recorder.record_test("T3", "Blue worker reads own secret", "blue-worker", "file:read /data/blue/blue_secret.txt", "ALLOW", "ALLOW", "PASS", 0)
        recorder.record_test("T4", "Negative Control: Red reads leaky fixture", "red-worker", "file:read /data/leaky/blue_leaked.txt", "DENY", "ALLOW", "FAIL", 0)
        
        recs = [r.to_dict() for r in recorder.records]
        self.anchor_data = {
            "run_id": "synthetic-tamper-demo-001",
            "tip_record_hash": recs[-1]["record_hash"],
            "total_records": len(recs),
            "anchor_type": "SYNTHETIC_DEMO_ANCHOR",
        }
        return recs

    def _get_disposable_output_path(self, attack_id: str) -> Path:
        """Generate a collision-resistant unique scratch path for a disposable experiment."""
        exp_uid = uuid.uuid4().hex[:8]
        return TAMPER_SCRATCH_DIR / f"{attack_id.lower()}_{exp_uid}.jsonl"

    def run_all_attacks(self) -> List[TamperExperimentResult]:
        """Run all 6 standard tampering attacks and return their results."""
        return [
            self.attack_1_field_modification(),
            self.attack_2_record_deletion(),
            self.attack_3_record_reordering(),
            self.attack_4_broken_hash_link(),
            self.attack_5_full_chain_rewrite(),
            self.attack_6_tail_truncation(),
        ]

    def attack_1_field_modification(self) -> TamperExperimentResult:
        """Attack 1: Modify a field without recalculating record_hash."""
        recs = self._ensure_base_evidence()
        target_idx = min(3, len(recs) - 1)
        orig_rec = dict(recs[target_idx])
        test_id = orig_rec.get("test_id", f"Record-{target_idx+1}")

        # Apply mutation (flip result)
        tampered_recs = [dict(r) for r in recs]
        new_result = "PASS" if orig_rec.get("result") == "FAIL" else "FAIL"
        new_outcome = "DENY" if orig_rec.get("actual_outcome") == "ALLOW" else "ALLOW"
        tampered_recs[target_idx]["result"] = new_result
        tampered_recs[target_idx]["actual_outcome"] = new_outcome

        output_path = self._get_disposable_output_path("attack_1")
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        detected = not v_res.is_valid and v_res.error_type == "RECORD_HASH_MISMATCH"

        return TamperExperimentResult(
            attack_id="ATTACK_1",
            attack_name="Field Modification (Cover-up)",
            attack_description="Attacker modifies recorded test outcome fields without recomputing the SHA-256 payload hash.",
            tampered_file=str(output_path),
            transformation_applied=f"Modified Record {target_idx + 1} ({test_id}): result '{orig_rec.get('result')}' -> '{new_result}', actual_outcome '{orig_rec.get('actual_outcome')}' -> '{new_outcome}'",
            original_snippet=json.dumps(orig_rec, indent=2),
            tampered_snippet=json.dumps(tampered_recs[target_idx], indent=2),
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation=(
                f"The verifier recomputes the SHA-256 hash over the canonical JSON payload. "
                f"Because payload fields were changed, the computed hash no longer matches "
                f"the sealed 'record_hash' stored in the record."
            ),
            architectural_note="Canonical payload serialization prevents whitespace or key ordering evasion.",
            anchor_provenance=self.anchor_provenance,
        )

    def attack_2_record_deletion(self) -> TamperExperimentResult:
        """Attack 2: Delete an intermediate record to conceal an evaluation."""
        recs = self._ensure_base_evidence()
        target_idx = 1  # Record 2
        orig_rec = dict(recs[target_idx])
        test_id = orig_rec.get("test_id", "Record-2")

        tampered_recs = [dict(r) for idx, r in enumerate(recs) if idx != target_idx]

        output_path = self._get_disposable_output_path("attack_2")
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        detected = not v_res.is_valid and v_res.error_type in ("SEQUENCE_BREAK", "HASH_CHAIN_DISCONTINUITY")

        return TamperExperimentResult(
            attack_id="ATTACK_2",
            attack_name="Record Deletion (Selective Erasure)",
            attack_description="Attacker deletes an intermediate record entirely from the log file to conceal a test.",
            tampered_file=str(output_path),
            transformation_applied=f"Removed record sequence {orig_rec.get('sequence_number')} (test_id: {test_id})",
            original_snippet=f"Total records: {len(recs)}",
            tampered_snippet=f"Total records: {len(tampered_recs)} (Record index {target_idx} missing)",
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation=(
                f"Record deletion causes two immediate cryptographic failures: "
                f"1) Sequence number jump (Record 3 follows Record 1, expected sequence 2). "
                f"2) Hash chain discontinuity (downstream previous_record_hash still points to the deleted record)."
            ),
            architectural_note="Dual sequence numbering and previous-record hash linking prevents undetected deletions.",
            anchor_provenance=self.anchor_provenance,
        )

    def attack_3_record_reordering(self) -> TamperExperimentResult:
        """Attack 3: Swap two records to alter timeline or causation."""
        recs = self._ensure_base_evidence()
        tampered_recs = [dict(r) for r in recs]
        tampered_recs[0], tampered_recs[1] = tampered_recs[1], tampered_recs[0]

        output_path = self._get_disposable_output_path("attack_3")
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
            transformation_applied=f"Swapped record 1 ({recs[0].get('test_id')}) and record 2 ({recs[1].get('test_id')})",
            original_snippet=f"Order: {recs[0].get('test_id')}, {recs[1].get('test_id')}",
            tampered_snippet=f"Order: {tampered_recs[0].get('test_id')}, {tampered_recs[1].get('test_id')}",
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation=(
                f"Swapping records breaks sequence numbering (found sequence 2 at line 1, expected 1), "
                f"and breaks previous_record_hash linking (Record 1 must point to GENESIS_HASH)."
            ),
            architectural_note="Genesis requirement and sequential ordering enforce strict chronological immutability.",
            anchor_provenance=self.anchor_provenance,
        )

    def attack_4_broken_hash_link(self) -> TamperExperimentResult:
        """Attack 4: Corrupt previous_record_hash pointer."""
        recs = self._ensure_base_evidence()
        tampered_recs = [dict(r) for r in recs]
        target_idx = min(2, len(tampered_recs) - 1)
        tampered_recs[target_idx]["previous_record_hash"] = "f" * 64

        output_path = self._get_disposable_output_path("attack_4")
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
            transformation_applied=f"Replaced previous_record_hash in record {target_idx + 1} with {'f'*64}",
            original_snippet=f"previous_record_hash: {recs[target_idx]['previous_record_hash'][:24]}...",
            tampered_snippet=f"previous_record_hash: {'f'*24}...",
            verifier_result=asdict(v_res),
            detected_as_tampered=not v_res.is_valid,
            is_expected_outcome=detected,
            explanation="The verifier detects that record previous_record_hash does not match the actual hash of its predecessor.",
            architectural_note="Ensures unbroken cryptographic continuity between all chronological events.",
            anchor_provenance=self.anchor_provenance,
        )

    def attack_5_full_chain_rewrite(self) -> TamperExperimentResult:
        """Attack 5: Full chain rewrite (Demonstrates documented limitation & Trust Anchor defense)."""
        recs = self._ensure_base_evidence()
        tampered_recs = [dict(r) for r in recs]

        # Maliciously falsify target record and recalculate downstream hashes
        target_idx = min(3, len(tampered_recs) - 1)
        orig_rec = dict(tampered_recs[target_idx])
        tampered_recs[target_idx]["result"] = "PASS" if orig_rec.get("result") == "FAIL" else "FAIL"
        tampered_recs[target_idx]["actual_outcome"] = "DENY" if orig_rec.get("actual_outcome") == "ALLOW" else "ALLOW"
        tampered_recs[target_idx]["test_description"] = "Falsified outcome with recomputed hash"

        payload = {k: tampered_recs[target_idx][k] for k in HASHED_FIELDS}
        tampered_recs[target_idx]["record_hash"] = compute_payload_hash(payload)

        # Recalculate all downstream hashes down the chain
        prev_hash = tampered_recs[target_idx]["record_hash"]
        for i in range(target_idx + 1, len(tampered_recs)):
            tampered_recs[i]["previous_record_hash"] = prev_hash
            p = {k: tampered_recs[i][k] for k in HASHED_FIELDS}
            tampered_recs[i]["record_hash"] = compute_payload_hash(p)
            prev_hash = tampered_recs[i]["record_hash"]

        output_path = self._get_disposable_output_path("attack_5")
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        v_res = EvidenceVerifier.verify_file(str(output_path))
        # Internal verification PASSES because all hashes are mathematically recalculated!
        passes_internally = v_res.is_valid

        # Demonstrate trust anchor defense:
        original_tip = self.anchor_data.get("tip_record_hash") if self.anchor_data else recs[-1]["record_hash"]
        anchor_check_res = EvidenceVerifier.verify_file(
            str(output_path),
            anchor_data={"tip_record_hash": original_tip, "total_records": len(recs)},
            require_anchor=True,
        )
        anchor_detected = not anchor_check_res.is_valid

        return TamperExperimentResult(
            attack_id="ATTACK_5",
            attack_name="Full-Chain Rewrite (Documented Cryptographic Boundary)",
            attack_description=(
                "Attacker with full write access rewrites record outcome AND recalculates all downstream "
                "SHA-256 hashes, leaving the local file mathematically self-consistent."
            ),
            tampered_file=str(output_path),
            transformation_applied="Rewrote test outcome and recalculated canonical SHA-256 hashes down the chain",
            original_snippet=f"Hash: {recs[target_idx]['record_hash'][:24]}... (Result: {orig_rec.get('result')})",
            tampered_snippet=f"Hash: {tampered_recs[target_idx]['record_hash'][:24]}... (Result: {tampered_recs[target_idx]['result']}, recalculated)",
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
            anchor_provenance=self.anchor_provenance,
            trust_anchor_check={
                "anchor_tested": True,
                "anchor_expected_tip": original_tip,
                "tampered_chain_tip": tampered_recs[-1]["record_hash"],
                "anchor_detected_tampering": anchor_detected,
                "anchor_error_message": anchor_check_res.error_message,
            },
        )

    def attack_6_tail_truncation(self) -> TamperExperimentResult:
        """Attack 6: Tail Truncation (Attacker truncates trailing records)."""
        recs = self._ensure_base_evidence()
        if len(recs) < 2:
            raise ValueError("Tail truncation requires at least 2 records.")

        # Truncate the last record
        tampered_recs = [dict(r) for r in recs[:-1]]
        deleted_rec = recs[-1]

        output_path = self._get_disposable_output_path("attack_6")
        with open(output_path, "w", encoding="utf-8") as f:
            for r in tampered_recs:
                f.write(json.dumps(r) + "\n")

        # Internal verification on prefix alone PASSES because remaining records are valid prefix!
        v_res = EvidenceVerifier.verify_file(str(output_path))
        prefix_valid = v_res.is_valid

        # Trust anchor defense: checks total_records and tip_record_hash
        original_tip = self.anchor_data.get("tip_record_hash") if self.anchor_data else recs[-1]["record_hash"]
        expected_count = self.anchor_data.get("total_records") if self.anchor_data else len(recs)
        anchor_check_res = EvidenceVerifier.verify_file(
            str(output_path),
            anchor_data={"tip_record_hash": original_tip, "total_records": expected_count},
            require_anchor=True,
        )
        anchor_detected = not anchor_check_res.is_valid

        return TamperExperimentResult(
            attack_id="ATTACK_6",
            attack_name="Tail Truncation (Log Truncation Attack)",
            attack_description=(
                "Attacker truncates the trailing record from the evidence chain to hide the final evaluation outcome."
            ),
            tampered_file=str(output_path),
            transformation_applied=f"Truncated final record (sequence {deleted_rec.get('sequence_number')}, test_id {deleted_rec.get('test_id')})",
            original_snippet=f"Total records: {len(recs)} | Tip: {recs[-1]['record_hash'][:24]}...",
            tampered_snippet=f"Total records: {len(tampered_recs)} | Tip: {tampered_recs[-1]['record_hash'][:24]}...",
            verifier_result=asdict(v_res),
            detected_as_tampered=anchor_detected,
            is_expected_outcome=anchor_detected and prefix_valid,
            explanation=(
                "1. Internal chain verification PASSES on the remaining prefix because records 1..N-1 are "
                "consecutively numbered and cryptographically linked.\n"
                "2. Trust Anchor verification DETECTS TRUNCATION: The independent commitment stores the expected "
                "record count and tip hash. The truncated log fails with ANCHOR_RECORD_COUNT_MISMATCH and TRUST_ANCHOR_MISMATCH."
            ),
            architectural_note=(
                "A hash chain alone cannot detect if an attacker cuts off the most recent events without an anchor "
                "committing to the expected chain tip or total record count."
            ),
            anchor_provenance=self.anchor_provenance,
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
