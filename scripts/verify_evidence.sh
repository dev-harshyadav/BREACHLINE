#!/usr/bin/env bash
set -euo pipefail

# BREACHLINE — Independent Evidence Verifier Script
EVIDENCE_FILE="${1:-output/evidence.jsonl}"

echo "=========================================================="
echo "  BREACHLINE INDEPENDENT EVIDENCE VERIFICATION"
echo "=========================================================="
echo "Verifying file: ${EVIDENCE_FILE}"
echo ""

python3 -m src.verifier "${EVIDENCE_FILE}"
