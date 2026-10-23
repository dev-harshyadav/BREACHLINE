#!/usr/bin/env bash
set -uo pipefail

# BREACHLINE — Tampering Detection Demonstration
# Shows how the independent verifier detects various evidence tampering attempts,
# and clearly demonstrates the documented full-chain rewrite limitation.

ORIGINAL_EVIDENCE="output/evidence.jsonl"
TMP_DIR="output/tamper_scratch"

if [ ! -f "${ORIGINAL_EVIDENCE}" ]; then
  echo "[ERROR] Original evidence file '${ORIGINAL_EVIDENCE}' not found."
  echo "Please run 'python3 -m src.runner' or './scripts/run_demo.sh' first."
  exit 1
fi

mkdir -p "${TMP_DIR}"

echo "=========================================================="
echo "    BREACHLINE EVIDENCE TAMPERING DEMONSTRATION"
echo "=========================================================="
echo "Original untampered evidence verification baseline:"
python3 -m src.verifier "${ORIGINAL_EVIDENCE}"
echo ""

echo "----------------------------------------------------------"
echo "ATTACK 1: Field Tampering (Attacker changes FAIL to PASS)"
echo "----------------------------------------------------------"
ATTACK1="${TMP_DIR}/tamper_field.jsonl"
python3 -c '
import json
with open("'"${ORIGINAL_EVIDENCE}"'", "r") as f:
    recs = [json.loads(line) for line in f]
# Modify test T4 result from FAIL to PASS without updating hash
recs[3]["result"] = "PASS"
with open("'"${ATTACK1}"'", "w") as f:
    for r in recs:
        f.write(json.dumps(r) + "\n")
'
python3 -m src.verifier "${ATTACK1}" || echo "--> ATTACK 1 DETECTED AS EXPECTED: Hash mismatch."
echo ""

echo "----------------------------------------------------------"
echo "ATTACK 2: Record Deletion (Attacker deletes T2 evidence)"
echo "----------------------------------------------------------"
ATTACK2="${TMP_DIR}/tamper_deletion.jsonl"
python3 -c '
import json
with open("'"${ORIGINAL_EVIDENCE}"'", "r") as f:
    recs = [json.loads(line) for line in f]
# Delete record 2 (T2)
del recs[1]
with open("'"${ATTACK2}"'", "w") as f:
    for r in recs:
        f.write(json.dumps(r) + "\n")
'
python3 -m src.verifier "${ATTACK2}" || echo "--> ATTACK 2 DETECTED AS EXPECTED: Sequence break detected."
echo ""

echo "----------------------------------------------------------"
echo "ATTACK 3: Record Reordering (Attacker swaps T1 and T2)"
echo "----------------------------------------------------------"
ATTACK3="${TMP_DIR}/tamper_reorder.jsonl"
python3 -c '
import json
with open("'"${ORIGINAL_EVIDENCE}"'", "r") as f:
    recs = [json.loads(line) for line in f]
# Swap records
recs[0], recs[1] = recs[1], recs[0]
with open("'"${ATTACK3}"'", "w") as f:
    for r in recs:
        f.write(json.dumps(r) + "\n")
'
python3 -m src.verifier "${ATTACK3}" || echo "--> ATTACK 3 DETECTED AS EXPECTED: Sequence break detected."
echo ""

echo "----------------------------------------------------------"
echo "ATTACK 4: Broken Hash Link (Corrupted previous_record_hash)"
echo "----------------------------------------------------------"
ATTACK4="${TMP_DIR}/tamper_broken_link.jsonl"
python3 -c '
import json
with open("'"${ORIGINAL_EVIDENCE}"'", "r") as f:
    recs = [json.loads(line) for line in f]
# Corrupt previous hash
recs[2]["previous_record_hash"] = "0" * 64
with open("'"${ATTACK4}"'", "w") as f:
    for r in recs:
        f.write(json.dumps(r) + "\n")
'
python3 -m src.verifier "${ATTACK4}" || echo "--> ATTACK 4 DETECTED AS EXPECTED: Hash discontinuity."
echo ""

echo "----------------------------------------------------------"
echo "ATTACK 5: Full-Chain Rewrite (Documented Limitation)"
echo "----------------------------------------------------------"
echo "In this scenario, an attacker with write access rewrites"
echo "record T4 and recomputes all SHA-256 hashes down the chain."
ATTACK5="${TMP_DIR}/tamper_full_rewrite.jsonl"
python3 -c '
import json
from src.models import compute_payload_hash, HASHED_FIELDS

with open("'"${ORIGINAL_EVIDENCE}"'", "r") as f:
    recs = [json.loads(line) for line in f]

# Maliciously change T4 outcome and recompute hash
recs[3]["result"] = "PASS"
recs[3]["actual_outcome"] = "DENY"
recs[3]["test_description"] = "Falsified outcome"
payload = {k: recs[3][k] for k in HASHED_FIELDS}
recs[3]["record_hash"] = compute_payload_hash(payload)

with open("'"${ATTACK5}"'", "w") as f:
    for r in recs:
        f.write(json.dumps(r) + "\n")
'

python3 -m src.verifier "${ATTACK5}"
echo ""
echo "OBSERVATION:"
echo "As documented in SECURITY_MODEL.md and LIMITATIONS.md:"
echo "Internal hash-chain verification alone passes because the mathematical"
echo "links are self-consistent. To detect a full-chain rewrite, the system"
echo "must compare against a trusted external anchor (e.g. anchor ledger or"
echo "witness timestamp). BREACHLINE explicitly documents this boundary."
echo "=========================================================="
