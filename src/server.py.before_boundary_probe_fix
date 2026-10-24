"""FastAPI Application Server for BREACHLINE Security Workbench.

Exposes REST APIs for boundary testing, evidence verification,
tampering demonstration, multi-run history, and serves the web interface.
"""

from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.boundary_lab import (
    ALLOWED_OPERATIONS,
    ALLOWED_PATH_PREFIXES,
    ALLOWED_WORKER_ROLES,
    get_boundary_lab_schema,
    validate_boundary_scenario,
)
from src.classification import classify_execution_outcome
from src.local_sandbox import execute_local_operation, setup_local_sandbox
from src.models import GENESIS_HASH, HASHED_FIELDS, SCHEMA_VERSION, TestCase
from src.report import DEFAULT_REPORT_HTML_PATH, DEFAULT_REPORT_JSON_PATH, generate_report
from src.runner import TestRunner, check_docker_environment
from src.storage import (
    compare_runs,
    get_latest_run,
    get_run,
    get_run_anchor,
    is_safe_run_id,
    load_runs_index,
    persist_run,
)
from src.tamper import EvidenceTamperLab
from src.verifier import EvidenceVerifier

app = FastAPI(
    title="BREACHLINE Security Workbench API",
    description="Evidence-Producing Boundary-Test Harness for AI Evaluation Sandboxes",
    version="1.0.0",
)

# Hardened CORS: explicit configurable origin allowlist (eliminating wildcard with credentials)
_cors_env = os.environ.get(
    "BREACHLINE_CORS_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:8008,http://127.0.0.1:8008,http://localhost:8009,http://127.0.0.1:8009"
)
CORS_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

STATIC_DIR = Path("src/static")
STATIC_DIR.mkdir(parents=True, exist_ok=True)


class ExecuteRunRequest(BaseModel):
    mode: str = Field(default="auto", description="'auto', 'docker', 'local_sandbox', or 'demo'")
    test_cases: Optional[List[Dict[str, Any]]] = Field(default=None, description="Custom test scenario list")


class ProbeRequest(BaseModel):
    role: str
    operation: str
    target_path: str
    expected_outcome: str = "DENY"
    test_description: str = "Custom boundary probe"


class CompareRequest(BaseModel):
    run_id_a: str
    run_id_b: str


class TamperRequest(BaseModel):
    run_id: Optional[str] = None
    attack_id: str = Field(default="ALL", description="'ATTACK_1' to 'ATTACK_6' or 'ALL'")



# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/status")
def get_system_status() -> Dict[str, Any]:
    """Retrieve runtime diagnostics, Docker status, and summary metrics."""
    docker_status = check_docker_environment()
    runs = load_runs_index()
    latest = runs[0] if runs else None

    # Calculate aggregate stats
    total_runs = len(runs)
    total_cases = sum(r.get("total_tests", 0) for r in runs)
    total_matches = sum(r.get("policy_matches", 0) for r in runs)
    total_mismatches = sum(r.get("policy_mismatches", 0) for r in runs)
    total_unexpected = sum(r.get("unexpected_access_count", 0) for r in runs)
    valid_chains = sum(1 for r in runs if r.get("evidence_integrity", {}).get("is_valid", False))
    invalid_chains = sum(1 for r in runs if not r.get("evidence_integrity", {}).get("is_valid", False))

    cumulative = {
        "total_runs": total_runs,
        "total_cases_executed": total_cases,
        "policy_matches": total_matches,
        "policy_mismatches": total_mismatches,
        "unexpected_access_outcomes": total_unexpected,
        "verified_evidence_chains": valid_chains,
        "invalid_evidence_chains": invalid_chains,
    }

    return {
        "status": "online",
        "system_info": {
            "os": platform.system(),
            "release": platform.release(),
            "python": sys.version.split()[0],
            "server_time_utc": datetime.now(timezone.utc).isoformat(),
        },
        "docker_environment": docker_status,
        "metrics": {
            **cumulative,
            "cumulative": cumulative,
        },
        "latest_run": latest,
    }


@app.get("/api/runs")
def list_all_runs() -> Dict[str, Any]:
    """List metadata for all past test runs."""
    runs = load_runs_index()
    return {"runs": runs, "count": len(runs)}


@app.get("/api/runs/{run_id}")
def get_run_details(run_id: str) -> Dict[str, Any]:
    """Retrieve full details of a specific test run."""
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return run


@app.post("/api/runs/execute")
def trigger_test_run(req: ExecuteRunRequest = Body(...)) -> Dict[str, Any]:
    """Execute a boundary test run and persist evidence."""
    valid_modes = {"auto", "docker", "local_sandbox", "simulated", "local_os", "demo"}
    if req.mode not in valid_modes:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid execution mode '{req.mode}'. Must be one of: {sorted(valid_modes)}"
        )

    config_file = "config/test_cases.json"
    temp_config = None

    if req.test_cases:
        # Validate all provided test cases
        for idx, tc in enumerate(req.test_cases, start=1):
            ok, err = validate_boundary_scenario(tc)
            if not ok:
                raise HTTPException(status_code=400, detail=f"Scenario #{idx} validation error: {err}")

        # Write temporary config
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(req.test_cases, f, indent=2)
            temp_config = f.name
            config_file = temp_config

    try:
        runner = TestRunner(config_path=config_file, mode=req.mode)
        summary = runner.run_all(verify_workers=False)

        # Generate reports for root
        generate_report(evidence_path=str(runner.evidence_path))

        return {
            "success": True,
            "run_id": summary["run_id"],
            "summary": summary,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Execution error: {str(e)}")
    finally:
        if temp_config and os.path.exists(temp_config):
            os.remove(temp_config)


@app.get("/api/runs/{run_id}/verify")
def verify_run_evidence(run_id: str) -> Dict[str, Any]:
    """Independently verify the cryptographic evidence chain of a run, checked against trust anchor."""
    if not is_safe_run_id(run_id):
        raise HTTPException(status_code=400, detail="Invalid run_id format.")

    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    evidence_file = Path(run["run_dir"]) / "evidence.jsonl"
    if not evidence_file.exists():
        raise HTTPException(status_code=404, detail="Evidence file missing for this run.")

    anchor = get_run_anchor(run_id)
    verif = EvidenceVerifier.verify_file(str(evidence_file), anchor_data=anchor)

    # Also build detailed link-by-link chain inspection
    chain_details = []
    expected_prev = GENESIS_HASH
    for idx, rec in enumerate(run["records"], start=1):
        chain_details.append({
            "sequence_number": rec.get("sequence_number"),
            "test_id": rec.get("test_id"),
            "role": rec.get("role"),
            "operation": rec.get("operation"),
            "expected_outcome": rec.get("expected_outcome"),
            "actual_outcome": rec.get("actual_outcome"),
            "result": rec.get("result"),
            "previous_record_hash": rec.get("previous_record_hash"),
            "record_hash": rec.get("record_hash"),
            "link_valid": rec.get("previous_record_hash") == expected_prev,
        })
        expected_prev = rec.get("record_hash")

    return {
        "run_id": run_id,
        "is_valid": verif.is_valid,
        "total_records": verif.total_records,
        "error_type": verif.error_type,
        "error_message": verif.error_message,
        "details": verif.details,
        "anchor_verified": verif.anchor_verified,
        "anchor_status": verif.anchor_status,
        "has_trust_anchor": anchor is not None,
        "trust_anchor": {
            "status": verif.anchor_status or ("VERIFIED" if verif.anchor_verified else "UNANCHORED"),
            "anchored": anchor is not None,
            "stored_tip_hash": anchor.get("tip_record_hash") if anchor else None,
            "error": verif.error_message if (verif.anchor_status and "DIVERGED" in verif.anchor_status) else None,
        },
        "chain": chain_details,
    }


@app.get("/api/runs/{run_id}/anchor")
def get_run_anchor_endpoint(run_id: str) -> Dict[str, Any]:
    """Retrieve independently stored trust anchor commitment for a run."""
    if not is_safe_run_id(run_id):
        raise HTTPException(status_code=400, detail="Invalid run_id format.")
    anchor = get_run_anchor(run_id)
    if not anchor:
        raise HTTPException(status_code=404, detail=f"No trust anchor commitment found for run '{run_id}'.")
    return anchor


@app.get("/api/runs/{run_id}/evidence")
def download_run_evidence(run_id: str) -> Any:
    """Download raw JSONL evidence for a run."""
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    evidence_file = Path(run["run_dir"]) / "evidence.jsonl"
    if not evidence_file.exists():
        raise HTTPException(status_code=404, detail="Evidence file missing.")
    return FileResponse(
        str(evidence_file),
        media_type="application/x-ndjson",
        filename=f"breachline_evidence_{run_id}.jsonl",
    )


@app.get("/api/runs/{run_id}/report")
def get_run_report(run_id: str, format: str = Query("html", pattern="^(html|json|txt)$")) -> Any:
    """Export run report in requested format."""
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    evidence_file = Path(run["run_dir"]) / "evidence.jsonl"
    if not evidence_file.exists():
        raise HTTPException(status_code=404, detail="Evidence file missing.")

    temp_html = Path(run["run_dir"]) / "report.html"
    temp_json = Path(run["run_dir"]) / "report.json"
    temp_txt = Path(run["run_dir"]) / "report.txt"

    data = generate_report(
        evidence_path=str(evidence_file),
        report_json_path=str(temp_json),
        report_txt_path=str(temp_txt),
        report_html_path=str(temp_html),
    )

    if format == "html":
        return HTMLResponse(content=temp_html.read_text(encoding="utf-8"))
    elif format == "txt":
        return PlainTextResponse(content=temp_txt.read_text(encoding="utf-8"))
    else:
        return JSONResponse(content=data)


@app.post("/api/runs/compare")
def compare_two_runs(req: CompareRequest = Body(...)) -> Dict[str, Any]:
    """Compare two test runs for policy and evidence drift."""
    try:
        return compare_runs(req.run_id_a, req.run_id_b)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/findings")
def get_recent_findings() -> Dict[str, Any]:
    """Retrieve detailed findings for all policy mismatches across runs."""
    runs = load_runs_index()
    all_findings = []

    for r_meta in runs:
        run_id = r_meta.get("run_id")
        run_data = get_run(run_id)
        if not run_data:
            continue

        for rec in run_data.get("records", []):
            if rec.get("result") == "FAIL" or (rec.get("expected_outcome") == "DENY" and rec.get("actual_outcome") == "ALLOW"):
                is_neg = "/leaky/" in rec.get("operation", "") or "negative" in rec.get("test_description", "").lower()
                all_findings.append({
                    "finding_id": f"FINDING-{rec.get('test_id')}-{run_id[:8]}",
                    "run_id": run_id,
                    "test_id": rec.get("test_id"),
                    "worker": rec.get("role"),
                    "operation": rec.get("operation"),
                    "expected_outcome": rec.get("expected_outcome"),
                    "observed_outcome": rec.get("actual_outcome"),
                    "policy_result": "FAIL",
                    "timestamp": rec.get("timestamp_utc"),
                    "record_hash": rec.get("record_hash"),
                    "is_negative_control": is_neg,
                    "explanation": (
                        "Negative control deliberate misconfiguration detected."
                        if is_neg
                        else "Observed operation succeeded despite policy specifying DENY."
                    ),
                    "interpretation": (
                        "The test harness actively caught a permissive DAC setting (0644). Test validation confirmed."
                        if is_neg
                        else "Boundary violation: container/worker accessed a protected foreign tenant file."
                    ),
                    "recommended_next_step": (
                        "No fix required for negative control fixture. Harness is working as designed."
                        if is_neg
                        else "Restrict POSIX permission bits on target resource (chmod 600) and verify worker UID isolation."
                    ),
                })

    return {"findings": all_findings, "total": len(all_findings)}


@app.post("/api/tamper/execute")
def execute_tamper_demo(req: TamperRequest = Body(...)) -> Dict[str, Any]:
    """Run disposable evidence-tampering simulations without touching original files."""
    if req.run_id and not is_safe_run_id(req.run_id):
        raise HTTPException(status_code=400, detail="Invalid run_id format.")

    lab = EvidenceTamperLab(run_id=req.run_id) if req.run_id else EvidenceTamperLab()

    attack_map = {
        "ATTACK_1": lab.attack_1_field_modification,
        "ATTACK_2": lab.attack_2_record_deletion,
        "ATTACK_3": lab.attack_3_record_reordering,
        "ATTACK_4": lab.attack_4_broken_hash_link,
        "ATTACK_5": lab.attack_5_full_chain_rewrite,
        "ATTACK_6": lab.attack_6_tail_truncation,
    }

    if req.attack_id == "ALL":
        results = [asdict(r) for r in lab.run_all_attacks()]
    elif req.attack_id in attack_map:
        results = [asdict(attack_map[req.attack_id]())]
    else:
        raise HTTPException(status_code=400, detail=f"Unknown attack_id '{req.attack_id}'. Must be 'ALL' or one of: {list(attack_map.keys())}")

    return {
        "success": True,
        "experiments": results,
        "disclaimer": (
            "All tampering simulations execute exclusively on disposable copies in output/tamper_scratch/. "
            "Original evidence files remain intact."
        ),
    }


@app.get("/api/boundary-lab/schema")
def get_lab_schema() -> Dict[str, Any]:
    """Retrieve available workers, fixtures, and preset test suites for the Boundary Lab."""
    return get_boundary_lab_schema()


@app.post("/api/boundary-lab/probe")
def execute_boundary_probe(probe: ProbeRequest = Body(...)) -> Dict[str, Any]:
    """Execute a single interactive boundary probe under POSIX DAC enforcement."""
    # 1. Validate probe parameters strictly
    scenario_dict = {
        "test_id": "CUSTOM-PROBE",
        "role": probe.role,
        "operation": probe.operation,
        "target_path": probe.target_path,
        "expected_outcome": probe.expected_outcome,
        "test_description": probe.test_description,
    }
    val_ok, val_err = validate_boundary_scenario(scenario_dict)
    if not val_ok:
        raise HTTPException(status_code=400, detail=val_err)

    # 2. Execute against local sandbox
    res = execute_local_operation(probe.role, probe.operation, probe.target_path)
    actual_outcome, policy_result, error_detail = classify_execution_outcome(res, probe.expected_outcome)

    return {
        "probe": scenario_dict,
        "execution": res,
        "actual_outcome": actual_outcome,
        "policy_result": policy_result,
        "error_detail": error_detail,
        "is_unexpected_access": (probe.expected_outcome == "DENY" and actual_outcome == "ALLOW"),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Static Web Interface Mount
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def serve_index() -> Any:
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="""<!DOCTYPE html><html><body style="background:#080d1a;color:#fff;font-family:sans-serif;padding:2rem;">
        <h2>BREACHLINE Workbench Initializing...</h2></body></html>"""
    )

# Mount remaining static assets (CSS, JS)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
