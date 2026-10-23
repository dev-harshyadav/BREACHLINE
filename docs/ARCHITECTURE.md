# BREACHLINE Architecture Specification

## 1. Executive Overview

**BREACHLINE** is an evidence-producing boundary-test harness designed to empirically evaluate access-control isolation in AI evaluation sandboxes. When sandboxing autonomous AI agents or untrusted workloads, developers commonly rely on container boundaries. However, container configuration errors, permissive filesystem permissions, or leaky volumes can quietly compromise tenant isolation.

BREACHLINE operates on a foundational security principle:
> **The operating system and container runtime provide access-control enforcement.** BREACHLINE does not enforce isolation itself; it tests the environment under test, compares expected outcomes against actual operating system enforcement, records structured evidence, and cryptographically hash-chains the results for independent verification.

---

## 2. System Architecture & Topology

```
+---------------------------------------------------------------------------------+
|                                HOST / TEST ORCHESTRATOR                        |
|                                                                                 |
|   +-----------------------+           +------------------+                      |
|   | config/test_cases.json|           | config/policy.json|                     |
|   +-----------+-----------+           +------------------+                      |
|               |                                                                 |
|               v                                                                 |
|       +---------------+       HTTP /execute       +-------------------------+   |
|       |  src/runner   | ------------------------> | breachline-red-worker   |   |
|       +-------+-------+                           | (UID 1001, GID 1001)    |   |
|               |                                   +------------+------------+   |
|               |               HTTP /execute                    |                |
|               | ------------------------------------+          | Mounts:        |
|               v                                     |          | /data:ro       |
|       +---------------+                             v          v                |
|       | src/evidence  |                   +-------------------------+           |
|       +-------+-------+                   | breachline-blue-worker  |           |
|               |                           | (UID 1002, GID 1002)    |           |
|               v                           +------------+------------+           |
|       output/evidence.jsonl                            | Mounts:                |
|               |                                        | /data:ro               |
|       +-------+-------+                                v                        |
|       |               |                 +-------------------------------+       |
|       v               v                 |    breachline-fixture-vol     |       |
|  src/verifier    src/report             |    (POSIX DAC Initialized)    |       |
|  (Independent)  (JSON / TXT)            |   /red/   (1001:1001, 0700)   |       |
|                                         |   /blue/  (1002:1002, 0700)   |       |
|                                         |   /leaky/ (1002:1002, 0755)   |       |
|                                         +-------------------------------+       |
+---------------------------------------------------------------------------------+
```

---

## 3. Container Sandbox Security Design

BREACHLINE enforces the principle of least privilege across all test worker containers:

1. **Non-Root User Identities**:
   - `red-worker`: UID `1001`, GID `1001` (`reduser:redgroup`).
   - `blue-worker`: UID `1002`, GID `1002` (`blueuser:bluegroup`).
2. **Read-Only Root Filesystem**:
   - Containers run with `read_only: true`. Worker processes cannot modify root binaries, libraries, or system paths.
3. **Dropped Linux Capabilities**:
   - All default Linux capabilities dropped via `cap_drop: [ALL]`.
   - Prevent capability reacquisition: `security_opt: [no-new-privileges:true]`.
4. **Isolated Writable Scratch Space**:
   - Writable operations are restricted strictly to an in-memory `tmpfs` mounted at `/tmp`.
5. **No Docker Socket Access**:
   - Neither the Docker socket (`/var/run/docker.sock`) nor administrative APIs are mounted into the worker containers.
6. **Volume Initialization Pattern (`fixture-init`)**:
   - Host-to-guest bind mounts on macOS Docker Desktop (VirtioFS / osxfs) translate host user credentials, bypassing POSIX Discretionary Access Control (DAC).
   - BREACHLINE uses an initialization container (`breachline-fixture-init`) to populate a native Docker volume (`breachline-fixture-vol`) formatted with standard Linux ext4 DAC permissions. This ensures exact, reproducible access-control enforcement across macOS, Linux, and cloud environments.

---

## 4. Test Execution & Mapping Logic

The test harness evaluates operations against a simple state matrix:

| Test ID | Role | Target Path | Environment Permission | Expected Outcome | Actual Outcome | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | `red-worker` | `/data/red/red_secret.txt` | Owner 1001, Mode 0600 | `ALLOW` | `ALLOW` (Exit 0) | **PASS** |
| **T2** | `red-worker` | `/data/blue/blue_secret.txt` | Owner 1002, Mode 0600 | `DENY` | `DENY` (Exit 1) | **PASS** |
| **T3** | `blue-worker` | `/data/blue/blue_secret.txt` | Owner 1002, Mode 0600 | `ALLOW` | `ALLOW` (Exit 0) | **PASS** |
| **T4** | `red-worker` | `/data/leaky/blue_leaked.txt` | Owner 1002, Mode 0644 | `DENY` | `ALLOW` (Exit 0) | **FAIL** |

### Exit Code Mapping
- `exit_code == 0` $\rightarrow$ `ALLOW`
- `exit_code != 0` (e.g. `1` / `Errno 13 Permission denied`) $\rightarrow$ `DENY`

### Result Classification
- `actual_outcome == expected_outcome` $\rightarrow$ `result = "PASS"`
- `actual_outcome != expected_outcome` $\rightarrow$ `result = "FAIL"`

> **Note on Test T4 (Negative Control):**
> Test T4 validates the test harness itself. Because `/data/leaky/blue_leaked.txt` has permissive permissions (`0644`), the operating system allows read access (`ALLOW`). The policy expects `DENY`. The harness flags `FAIL`, proving that the test harness actively catches boundary misconfigurations rather than generating false positives.

---

## 5. Cryptographic Evidence Recorder & Verification

Every test execution is permanently recorded as an individual JSON record appended to `output/evidence.jsonl`.

### Canonical Serialization Rules
To guarantee that identical dictionary data produces identical hashes across platforms, records are serialized canonically:
- **Lexicographically sorted keys**: `sort_keys=True`
- **Compact separators**: `separators=(',', ':')` (no extra spaces)
- **Deterministic encoding**: UTF-8 bytes (`ensure_ascii=True`)

### Fields Covered by `record_hash`
The following 13 fields are serialized into the hashable payload:
1. `schema_version`
2. `run_id`
3. `sequence_number`
4. `timestamp_utc`
5. `test_id`
6. `test_description`
7. `role`
8. `operation`
9. `expected_outcome`
10. `actual_outcome`
11. `result`
12. `exit_code`
13. `previous_record_hash`

> **Critical Rule:** `record_hash` is strictly **excluded** from its own payload calculation.

### Hash Chaining Mechanism
- **Genesis Hash**: The first record (`sequence_number = 1`) links to the documented 64-character null SHA-256 hash:
  `0000000000000000000000000000000000000000000000000000000000000000`
- **Chained Records**: For record $N > 1$:
  $$\text{previous\_record\_hash}_N = \text{record\_hash}_{N-1}$$
  $$\text{record\_hash}_N = \text{SHA256}(\text{CanonicalJSON}(\text{Payload}_N))$$

### Independent Verification Flow
`src/verifier.py` acts completely independently of the runner:
1. Validates JSON parsing and required schema keys.
2. Checks sequential progression: $S_i = i$.
3. Checks genesis anchor: Record 1 `previous_record_hash == GENESIS_HASH`.
4. Checks cryptographic link: Record $N$ `previous_record_hash == Record` $N-1$ `record_hash`.
5. Recomputes canonical SHA-256 for each record and asserts equality with `record_hash`.
6. Halts at the first invalid record, outputting the exact record number, reason, and error type.
