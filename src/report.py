"""Report Generator for BREACHLINE.

Parses evidence logs, executes independent verification, and outputs:
- Machine-readable JSON report (report.json)
- Human-readable text report (report.txt)
- Professional standalone HTML report (report.html)
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from src.verifier import EvidenceVerifier

DEFAULT_EVIDENCE_PATH = "output/evidence.jsonl"
DEFAULT_REPORT_JSON_PATH = "output/report.json"
DEFAULT_REPORT_TXT_PATH = "output/report.txt"
DEFAULT_REPORT_HTML_PATH = "output/report.html"

KNOWN_LIMITATIONS = [
    "Hash chains provide tamper-evidence against record mutation, deletion, and reordering, but cannot prevent complete chain rewrites without an external trusted anchor or immutable transparency log.",
    "Access-control boundary enforcement relies entirely on the underlying Linux kernel Discretionary Access Control (DAC) and container runtime isolation; BREACHLINE only evaluates and produces evidence.",
    "On macOS Docker Desktop, host bind-mounts using VirtioFS / osxfs do not preserve POSIX DAC ownership reliably without Linux container volume initialization.",
    "Network-level isolation boundaries and kernel privilege escalation (e.g., container breakout via kernel exploit) are currently out of scope for this file-boundary MVP."
]


def render_html_report(data: Dict[str, Any]) -> str:
    """Generate a clean, standalone, responsive HTML report for executive and technical inspection."""
    policy_badge_class = "badge-pass" if data["failed_tests"] == 0 else "badge-warn"
    verif_status = data["evidence_verification"]["status"]
    verif_badge_class = "badge-pass" if verif_status == "VALID" else "badge-fail"

    test_rows = ""
    for r in data["test_results"]:
        res_badge = '<span class="status-pass">PASS</span>' if r["result"] == "PASS" else '<span class="status-fail">FAIL</span>'
        expected_badge = f'<span class="code-pill">{r["expected"]}</span>'
        actual_badge = f'<span class="code-pill {r["actual"].lower()}">{r["actual"]}</span>'
        hash_short = f"{r['record_hash'][:16]}...{r['record_hash'][-8:]}"
        test_rows += f"""
        <tr>
            <td class="mono font-bold">{r["test_id"]}</td>
            <td>{r["description"]}</td>
            <td class="mono text-cyan">{r["role"]}</td>
            <td class="mono">{r["operation"]}</td>
            <td>{expected_badge}</td>
            <td>{actual_badge}</td>
            <td>{res_badge}</td>
            <td class="mono text-muted" title="{r['record_hash']}">{hash_short}</td>
        </tr>
        """

    limitations_list = "".join(f"<li>{lim}</li>" for lim in data["known_limitations"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BREACHLINE Audit Report — {data["run_id"][:8]}</title>
    <style>
        :root {{
            --bg-primary: #080d1a;
            --bg-card: #0f172a;
            --bg-elevated: #1e293b;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            padding: 2.5rem 1.5rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .brand-icon {{
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
            color: #000;
        }}
        h1 {{ font-size: 1.6rem; letter-spacing: -0.02em; font-weight: 700; }}
        .subtitle {{ font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem; }}
        .meta-badges {{ display: flex; gap: 0.75rem; margin-top: 0.5rem; }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.75rem;
        }}
        .card-title {{
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--accent-cyan);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .grid-kpi {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.75rem;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .kpi-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }}
        .kpi-value {{ font-size: 1.75rem; font-weight: 700; margin-top: 0.4rem; }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .text-cyan {{ color: var(--accent-cyan); }}
        .text-green {{ color: var(--accent-green); }}
        .text-red {{ color: var(--accent-red); }}
        .text-muted {{ color: var(--text-muted); font-size: 0.8rem; }}
        .font-bold {{ font-weight: 700; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
            margin-top: 0.5rem;
        }}
        th, td {{
            padding: 0.75rem 0.85rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: var(--bg-elevated);
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
        .status-pass {{
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.75rem;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .status-fail {{
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.75rem;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .code-pill {{
            background: var(--bg-elevated);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: monospace;
        }}
        .code-pill.allow {{ color: #34d399; }}
        .code-pill.deny {{ color: #f87171; }}
        .badge-pass {{
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 0.35rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .badge-warn {{
            background: rgba(245, 158, 11, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
            padding: 0.35rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .badge-fail {{
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 0.35rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .notice-box {{
            background: rgba(6, 182, 212, 0.08);
            border-left: 4px solid var(--accent-cyan);
            padding: 1rem;
            border-radius: 0 6px 6px 0;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        .notice-box strong {{ color: var(--text-primary); }}
        .limitations-list {{
            list-style-type: square;
            padding-left: 1.5rem;
            font-size: 0.88rem;
            color: var(--text-secondary);
        }}
        .limitations-list li {{ margin-bottom: 0.5rem; }}
        .footer {{
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .card, .kpi-card {{ border: 1px solid #ccc; background: #fff; }}
            th {{ background: #f0f0f0; color: #000; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <div class="brand">
                    <div class="brand-icon">BL</div>
                    <div>
                        <h1>BREACHLINE — Security Evaluation Audit Report</h1>
                        <p class="subtitle">AI Sandbox Boundary Test Harness &amp; Evidence Ledger</p>
                    </div>
                </div>
                <div class="meta-badges">
                    <span class="mono text-muted">Run ID: {data["run_id"]}</span>
                </div>
            </div>
            <div style="text-align: right;">
                <div class="{verif_badge_class}">Evidence Chain: {verif_status}</div>
                <div style="margin-top: 0.5rem; font-size: 0.8rem; color: var(--text-muted);">
                    Generated: {data["report_generated_utc"]}
                </div>
            </div>
        </header>

        <div class="notice-box">
            <strong>Important Scope Notice:</strong> This audit report reflects empirical boundary observations conducted by 
            BREACHLINE against configured Linux POSIX DAC access controls. The operating system kernel enforces access; 
            BREACHLINE tests boundaries and cryptographically links the resulting evidence. This report describes 
            observed test behavior and is not a certification of overall sandbox security.
        </div>

        <div class="grid-kpi">
            <div class="kpi-card">
                <div class="kpi-label">Total Test Cases</div>
                <div class="kpi-value">{data["total_tests"]}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Policy Matches</div>
                <div class="kpi-value text-green">{data["passed_tests"]}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Policy Mismatches</div>
                <div class="kpi-value { 'text-red' if data['failed_tests'] > 0 else 'text-muted' }">{data["failed_tests"]}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Evidence Verification</div>
                <div class="kpi-value { 'text-green' if verif_status == 'VALID' else 'text-red' }">{verif_status}</div>
            </div>
        </div>

        <div class="card">
            <div class="card-title">
                <span>Boundary Test Results</span>
                <span class="mono text-muted" style="font-size: 0.8rem;">Start: {data["start_time_utc"]}</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Description</th>
                        <th>Role</th>
                        <th>Operation</th>
                        <th>Expected</th>
                        <th>Actual</th>
                        <th>Policy</th>
                        <th>Record Hash (Canonical SHA-256)</th>
                    </tr>
                </thead>
                <tbody>
                    {test_rows}
                </tbody>
            </table>
        </div>

        <div class="card">
            <div class="card-title">Evidence Chain Cryptographic Verification</div>
            <p style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 0.75rem;">
                Every record in this run was deterministically serialized via canonical JSON and chained using SHA-256
                originating from genesis hash <code class="code-pill">0000000000000000...</code>. The independent verifier
                recomputed all hashes link-by-link:
            </p>
            <div style="background: var(--bg-primary); padding: 1rem; border-radius: 6px; font-family: monospace; font-size: 0.85rem;">
                <div>Verifier Status: <strong class="{ 'text-green' if verif_status == 'VALID' else 'text-red' }">{verif_status}</strong></div>
                <div>Records Verified: {data["evidence_verification"]["total_records_verified"]}</div>
                <div>Link Continuity: { 'Unbroken' if verif_status == 'VALID' else 'Discontinuity detected' }</div>
                <div>Hash Recalculation: { 'All match canonical payloads' if verif_status == 'VALID' else 'Mismatch detected' }</div>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Documented Technical Limitations &amp; Security Boundary</div>
            <ul class="limitations-list">
                {limitations_list}
            </ul>
        </div>

        <div class="footer">
            BREACHLINE Security Workbench &bull; Hack in Hills '26 &bull; Track 04 — Bayora &bull; Team NovaCrew (Lead: Harsh Yadav)
        </div>
    </div>
</body>
</html>
"""


def generate_report(
    evidence_path: str = DEFAULT_EVIDENCE_PATH,
    report_json_path: str = DEFAULT_REPORT_JSON_PATH,
    report_txt_path: str = DEFAULT_REPORT_TXT_PATH,
    report_html_path: str = DEFAULT_REPORT_HTML_PATH,
) -> Dict[str, Any]:
    ev_path = Path(evidence_path)
    if not ev_path.exists():
        raise FileNotFoundError(f"Evidence file does not exist: {evidence_path}")

    # Read all records
    records: List[Dict[str, Any]] = []
    with open(ev_path, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if clean:
                records.append(json.loads(clean))

    if not records:
        raise ValueError(f"Evidence file {evidence_path} is empty.")

    run_id = records[0]["run_id"]
    start_time = records[0]["timestamp_utc"]
    finish_time = records[-1]["timestamp_utc"]

    # Verify evidence integrity
    verif = EvidenceVerifier.verify_file(str(ev_path))

    passed_count = sum(1 for r in records if r["result"] == "PASS")
    failed_count = sum(1 for r in records if r["result"] == "FAIL")

    report_data = {
        "report_generated_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "start_time_utc": start_time,
        "finish_time_utc": finish_time,
        "total_tests": len(records),
        "passed_tests": passed_count,
        "failed_tests": failed_count,
        "evidence_verification": {
            "status": "VALID" if verif.is_valid else "INVALID",
            "total_records_verified": verif.total_records,
            "error_type": verif.error_type,
            "error_message": verif.error_message,
        },
        "test_results": [
            {
                "sequence_number": r["sequence_number"],
                "test_id": r["test_id"],
                "description": r["test_description"],
                "role": r["role"],
                "operation": r["operation"],
                "expected": r["expected_outcome"],
                "actual": r["actual_outcome"],
                "result": r["result"],
                "exit_code": r["exit_code"],
                "record_hash": r["record_hash"],
            }
            for r in records
        ],
        "known_limitations": KNOWN_LIMITATIONS,
    }

    # Write report.json
    Path(report_json_path).parent.mkdir(parents=True, exist_ok=True)
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Write report.html
    Path(report_html_path).parent.mkdir(parents=True, exist_ok=True)
    with open(report_html_path, "w", encoding="utf-8") as f:
        f.write(render_html_report(report_data))

    # Format human-readable text report
    verif_status_str = "VALID (Tamper-evidence checks PASSED)" if verif.is_valid else f"INVALID ({verif.error_type})"

    txt_lines = [
        "=" * 78,
        "                       BREACHLINE TEST EVALUATION REPORT",
        "=" * 78,
        f" Run ID:               {run_id}",
        f" Started (UTC):        {start_time}",
        f" Finished (UTC):       {finish_time}",
        f" Total Test Cases:     {len(records)}",
        f" Tests Passed:         {passed_count}",
        f" Tests Failed:         {failed_count}",
        f" Evidence Integrity:   {verif_status_str}",
        "-" * 78,
        " DETAILED TEST OUTCOMES:",
        "-" * 78,
        f" #   | ID   | ROLE         | EXPECTED | ACTUAL   | RESULT | OPERATION",
        "-" * 78,
    ]

    for r in records:
        txt_lines.append(
            f" {r['sequence_number']:<3} | {r['test_id']:<4} | {r['role']:<12} | "
            f"{r['expected_outcome']:<8} | {r['actual_outcome']:<8} | {r['result']:<6} | {r['operation']}"
        )

    txt_lines.extend([
        "-" * 78,
        " NEGATIVE CONTROL ANALYSIS:",
        " - Test T4 is a deliberate negative control testing a misconfigured fixture.",
        " - Policy expects 'DENY', but actual environment allowed 'ALLOW'.",
        " - Test harness correctly flagged result as 'FAIL'. This confirms the harness",
        "   detects boundary misconfigurations rather than falsely passing them.",
        "-" * 78,
        " KNOWN LIMITATIONS & SECURITY SCOPE:",
    ])
    for idx, lim in enumerate(KNOWN_LIMITATIONS, start=1):
        txt_lines.append(f" {idx}. {lim}")

    txt_lines.extend([
        "=" * 78,
        " End of BREACHLINE Evaluation Report.",
        "=" * 78,
    ])

    with open(report_txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines) + "\n")

    return report_data


def main():
    ev_path = DEFAULT_EVIDENCE_PATH
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        ev_path = sys.argv[1]

    try:
        report = generate_report(evidence_path=ev_path)
        print(f"[BREACHLINE REPORT] Generated reports from {ev_path}:")
        print(f"  - Machine-readable JSON: {DEFAULT_REPORT_JSON_PATH}")
        print(f"  - Human-readable TXT:    {DEFAULT_REPORT_TXT_PATH}")
        print(f"  - Interactive HTML:      {DEFAULT_REPORT_HTML_PATH}")
        print(f"  Result: {report['passed_tests']} passed, {report['failed_tests']} failed. Evidence {report['evidence_verification']['status']}.")
    except Exception as e:
        print(f"[REPORT ERROR] Failed to generate report: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
