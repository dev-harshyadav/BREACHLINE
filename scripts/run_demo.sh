#!/usr/bin/env bash
set -euo pipefail

# BREACHLINE — 90-Second Complete Technical Demonstration
# Team NovaCrew | Hack in Hills '26 | Track 04 — Bayora

echo "=========================================================="
echo "    BREACHLINE: AI EVALUATION SANDBOX BOUNDARY HARNESS"
echo "=========================================================="
echo "Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] Python 3 is required"; exit 1; }

echo "[STEP 1/6] Running automated test suite..."
python3 -m pytest -q

echo ""
echo "[STEP 2/6] Inspecting Sandbox Environment..."
if docker info >/dev/null 2>&1; then
    echo "[INFO] Docker daemon active. Initializing Docker worker containers..."
    docker compose up -d fixture-init red-worker blue-worker
    RUN_MODE="docker"
else
    echo "[INFO] Docker daemon offline. Initializing Local POSIX DAC Sandbox with real file fixtures..."
    echo "       (To run with Docker containers, start Docker Desktop and run: docker compose up -d)"
    RUN_MODE="local_sandbox"
fi

echo ""
echo "[STEP 3/6] Executing boundary test runner (Mode: ${RUN_MODE})..."
python3 -m src.runner --${RUN_MODE}

echo ""
echo "[STEP 4/6] Independently verifying cryptographic evidence log..."
python3 -m src.verifier output/evidence.jsonl

echo ""
echo "[STEP 5/6] Generating evaluation reports..."
python3 -m src.report output/evidence.jsonl

echo ""
echo "[STEP 6/6] Running evidence tampering detection demonstration..."
./scripts/tamper_demo.sh

echo ""
echo "=========================================================="
echo "  BREACHLINE DEMONSTRATION COMPLETE!"
echo "  Interactive Web UI:   ./breachline serve"
echo "  Reports generated in: output/report.txt, report.json, report.html"
echo "  Evidence log in:      output/evidence.jsonl"
echo "=========================================================="
