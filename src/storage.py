"""Run history persistence, indexing, and comparison engine for BREACHLINE."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional

from src.models import GENESIS_HASH
from src.verifier import EvidenceVerifier

OUTPUT_DIR = Path("output")
RUNS_DIR = OUTPUT_DIR / "runs"
INDEX_FILE = RUNS_DIR / "index.json"
ANCHORS_DIR = OUTPUT_DIR / "trust_anchors"


def is_safe_run_id(run_id: str) -> bool:
    """Validate that a run_id contains only safe identifier characters (prevent traversal)."""
    if not run_id or not isinstance(run_id, str):
        return False
    return bool(re.match(r"^[A-Za-z0-9_-]+$", run_id))


def ensure_storage_dirs() -> None:
    """Ensure required output directories exist."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    ANCHORS_DIR.mkdir(parents=True, exist_ok=True)


def load_runs_index() -> List[Dict[str, Any]]:
    """Load the metadata index of all previous runs."""
    ensure_storage_dirs()
    if not INDEX_FILE.exists():
        return []
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("runs", [])
    except Exception:
        return []


def save_runs_index(runs: List[Dict[str, Any]]) -> None:
    """Save the runs index file."""
    ensure_storage_dirs()
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump({"runs": runs, "updated_at": datetime.now(timezone.utc).isoformat()}, f, indent=2)


def persist_run(
    run_id: str,
    test_cases: List[Dict[str, Any]],
    records: List[Dict[str, Any]],
    summary: Dict[str, Any],
    execution_mode: str = "local_sandbox",
    environment_info: Optional[Dict[str, Any]] = None,
) -> Path:
    """Persist a complete test run with its evidence, config, and reports."""
    ensure_storage_dirs()
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write evidence.jsonl in run directory
    evidence_path = run_dir / "evidence.jsonl"
    with open(evidence_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # 2. Write config.json
    config_path = run_dir / "config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(test_cases, f, indent=2)

    # 3. Verify evidence chain independently
    verif = EvidenceVerifier.verify_file(str(evidence_path))

    # 4. Count metrics
    total_tests = len(records)
    policy_matches = sum(1 for r in records if r.get("result") == "PASS")
    policy_mismatches = sum(1 for r in records if r.get("result") == "FAIL")
    unexpected_access = sum(
        1 for r in records
        if r.get("expected_outcome") == "DENY" and r.get("actual_outcome") == "ALLOW"
    )

    meta = {
        "run_id": run_id,
        "timestamp_utc": records[0]["timestamp_utc"] if records else datetime.now(timezone.utc).isoformat(),
        "finish_time_utc": records[-1]["timestamp_utc"] if records else datetime.now(timezone.utc).isoformat(),
        "execution_mode": execution_mode,
        "environment_info": environment_info or {},
        "total_tests": total_tests,
        "policy_matches": policy_matches,
        "policy_mismatches": policy_mismatches,
        "unexpected_access_count": unexpected_access,
        "evidence_integrity": {
            "is_valid": verif.is_valid,
            "total_records": verif.total_records,
            "error_type": verif.error_type,
            "error_message": verif.error_message,
        },
    }

    # Write meta.json
    with open(run_dir / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    # 5. Generate and persist independent trust anchor commitment
    try:
        tip_hash = records[-1].get("record_hash", "") if records else ""
        evidence_bytes = evidence_path.read_bytes()
        evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
        anchor_data = {
            "run_id": run_id,
            "anchored_at_utc": datetime.now(timezone.utc).isoformat(),
            "total_records": total_tests,
            "tip_record_hash": tip_hash,
            "evidence_sha256": evidence_sha256,
            "policy_result": "PASS" if policy_mismatches == 0 else "FAIL",
            "anchor_type": "LOCAL_COMMITMENT_STORE",
            "description": "Independently stored cryptographic run commitment to detect full-chain rewrites",
        }
        with open(ANCHORS_DIR / f"{run_id}.anchor.json", "w", encoding="utf-8") as f:
            json.dump(anchor_data, f, indent=2)
    except Exception:
        pass

    # Update global index (prepend newest)
    index_runs = [r for r in load_runs_index() if r.get("run_id") != run_id]
    index_runs.insert(0, meta)
    save_runs_index(index_runs)

    # Maintain root output/ for backwards compatibility with CLI
    try:
        shutil.copy2(evidence_path, OUTPUT_DIR / "evidence.jsonl")
    except Exception:
        pass

    return run_dir


def get_run_anchor(run_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve independently stored trust anchor commitment for a run."""
    if not is_safe_run_id(run_id):
        return None
    anchor_file = ANCHORS_DIR / f"{run_id}.anchor.json"
    if anchor_file.exists():
        try:
            with open(anchor_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full details of a specific run."""
    if not is_safe_run_id(run_id):
        return None
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists():
        return None

    meta_file = run_dir / "meta.json"
    evidence_file = run_dir / "evidence.jsonl"
    config_file = run_dir / "config.json"

    meta = {}
    if meta_file.exists():
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

    records = []
    if evidence_file.exists():
        with open(evidence_file, "r", encoding="utf-8") as f:
            for line in f:
                clean = line.strip()
                if clean:
                    records.append(json.loads(clean))

    config = []
    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)

    return {
        "meta": meta,
        "records": records,
        "config": config,
        "run_dir": str(run_dir),
    }


def get_latest_run() -> Optional[Dict[str, Any]]:
    """Get the most recent run."""
    index = load_runs_index()
    if not index:
        return None
    latest_id = index[0]["run_id"]
    return get_run(latest_id)


def compare_runs(run_id_a: str, run_id_b: str) -> Dict[str, Any]:
    """Compare two runs and return detailed differences in policy and evidence."""
    run_a = get_run(run_id_a)
    run_b = get_run(run_id_b)

    if not run_a:
        raise ValueError(f"Run ID '{run_id_a}' not found.")
    if not run_b:
        raise ValueError(f"Run ID '{run_id_b}' not found.")

    meta_a = run_a["meta"]
    meta_b = run_b["meta"]

    records_a = {r["test_id"]: r for r in run_a["records"]}
    records_b = {r["test_id"]: r for r in run_b["records"]}

    all_test_ids = sorted(list(set(records_a.keys()) | set(records_b.keys())))

    test_comparisons = []
    differences_count = 0

    for tid in all_test_ids:
        ra = records_a.get(tid)
        rb = records_b.get(tid)

        status_change = "UNCHANGED"
        if ra and not rb:
            status_change = "REMOVED_IN_B"
            differences_count += 1
        elif rb and not ra:
            status_change = "ADDED_IN_B"
            differences_count += 1
        else:
            if ra["result"] != rb["result"] or ra["actual_outcome"] != rb["actual_outcome"]:
                status_change = "OUTCOME_CHANGED"
                differences_count += 1

        test_comparisons.append({
            "test_id": tid,
            "status_change": status_change,
            "run_a": {
                "role": ra["role"] if ra else None,
                "operation": ra["operation"] if ra else None,
                "expected": ra["expected_outcome"] if ra else None,
                "actual": ra["actual_outcome"] if ra else None,
                "result": ra["result"] if ra else None,
                "record_hash": ra["record_hash"] if ra else None,
            } if ra else None,
            "run_b": {
                "role": rb["role"] if rb else None,
                "operation": rb["operation"] if rb else None,
                "expected": rb["expected_outcome"] if rb else None,
                "actual": rb["actual_outcome"] if rb else None,
                "result": rb["result"] if rb else None,
                "record_hash": rb["record_hash"] if rb else None,
            } if rb else None,
        })

    return {
        "run_id_a": run_id_a,
        "run_id_b": run_id_b,
        "meta_a": meta_a,
        "meta_b": meta_b,
        "differences_count": differences_count,
        "config_identical": run_a.get("config") == run_b.get("config"),
        "test_comparisons": test_comparisons,
    }
