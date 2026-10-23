# BREACHLINE Security Model & Threat Assessment

## 1. Core Security Principle

BREACHLINE evaluates whether a configured execution environment correctly enforces access-control boundaries between untrusted worker roles.

```
+-------------------------------------------------------------+
|                     SECURITY BOUNDARY MAP                   |
|                                                             |
|   [ ENVIRONMENT ENFORCEMENT ]                               |
|   Enforced by: Linux Kernel (POSIX DAC, Namespaces, Cgroups)|
|   Mechanism:   UID/GID file ownership, 0700/0600 mode bits, |
|                read-only mounts, capability drops.          |
|                                                             |
|   [ TEST HARNESS ROLE ]                                     |
|   BREACHLINE does NOT enforce security rules.               |
|   BREACHLINE stimulates the environment, records the        |
|   kernel's response (ALLOW/DENY), and produces tamper-      |
|   evident cryptographic audit trails.                       |
+-------------------------------------------------------------+
```

---

## 2. In-Scope Threat Vectors

The following scenarios are within scope and actively evaluated:

1. **Cross-Tenant Unauthorized File Read**:
   - An untrusted worker process (e.g., `red-worker`, UID `1001`) attempting to inspect private workspace files belonging to a distinct tenant (`blue-worker`, UID `1002`).
2. **Evaluation Environment Misconfiguration**:
   - Accidental deployment of overly broad file permissions (e.g., world-readable `0644` / `0755` permissions on sensitive evaluation fixtures).
3. **Evidence Log Alteration**:
   - Post-execution modification of recorded test evidence (e.g., changing a test result from `FAIL` to `PASS`).
4. **Evidence Log Pruning & Reordering**:
   - Deletion of inconvenient audit entries or rearranging execution order.
5. **Audit Chain Corruption**:
   - Insertion of forged records into the historical sequence without recalculating cryptographic links.

---

## 3. Out-of-Scope Threat Vectors

The prototype explicitly does not defend against or test:

1. **Linux Kernel Zero-Day Exploits / Container Breakouts**:
   - If an attacker compromises the underlying Linux kernel (e.g., dirty COW, unpatched privilege escalation vulnerabilities), container boundary isolation collapses.
2. **Compromised Host / Hypervisor**:
   - An attacker possessing `root` privileges on the host Docker daemon can inspect, modify, or terminate any container process directly.
3. **Full-Chain Evidence Rewrite (Without External Anchor)**:
   - If an adversary with unrestricted file-system write access rewrites the entire `evidence.jsonl` log and recalculates every SHA-256 hash starting from the genesis block, internal hash checks will appear valid. Detecting a full rewrite requires an external anchor (see [Section 5](#5-what-the-verifier-cannot-establish)).
4. **Network Side-Channels and Covert Channels**:
   - Timing attacks, shared CPU cache side-channels, or DNS exfiltration are not tested in this prototype.
5. **Host Filesystem ACL Bypasses on macOS Bind-Mounts**:
   - macOS VirtioFS translation maps host permissions inconsistently across users. The prototype isolates fixtures inside a dedicated Linux container volume to guarantee strict kernel DAC enforcement.

---

## 4. What the Evidence Verifier Can Detect

The independent verifier (`src/verifier.py`) mathematically verifies the evidence log against the following anomalies:

- **Field Tampering**: Any modification to test results, exit codes, timestamps, test IDs, or role labels invalidates the record's canonical SHA-256 hash.
- **Record Deletion**: Deleting any record disrupts sequential numbering ($1, 2, 3\dots$) and causes a broken link (`previous_record_hash` mismatch).
- **Record Reordering**: Swapping adjacent records fails both sequence validation and cryptographic hash chaining.
- **Corrupted Genesis**: Any alteration to the genesis block's initial link (`GENESIS_HASH`) is flagged immediately.

---

## 5. What the Verifier Cannot Establish

- **Tamper-Proofing**: The evidence log is **tamper-evident**, not tamper-proof. It cannot physically prevent a privileged entity from altering files; it guarantees that any unauthorized alteration is detectable.
- **External Anchoring**: The hash chain proves relative integrity between records within the log. To achieve non-repudiation against an adversary capable of replacing the entire file, the tip hash (or root hash) must be published to a trusted external anchor (e.g., an append-only transparency ledger, timestamping authority, or git commit signature).
- **Underlying Code Correctness**: The verifier verifies that the recorded log has not changed since creation; it does not independently re-execute Docker containers.

---

## 6. Execution Modes & OS Enforcement Guarantees

BREACHLINE explicitly reports whether a test run was enforced by the operating system kernel:

| Mode | `is_os_enforced` | Enforcement Entity | Description |
| :--- | :---: | :--- | :--- |
| **`docker`** | `True` | Linux Kernel (POSIX DAC) | Real non-root containers (`red-worker` UID 1001, `blue-worker` UID 1002) attempt filesystem access on an ext4 volume. Kernel returns real `Errno 13 Permission Denied`. |
| **`local_os`** | `True` | Host OS Kernel | Direct host syscalls (`open()`, `stat()`). Blocks mode `0000` files via real host kernel DAC. |
| **`simulated`** | `False` | Application Logic | Fallback string matching on role names. Explicitly flagged as `is_os_enforced: False` in logs and reports. Never claimed as proof of OS security. |

### Execution Errors vs. Policy Denials
- A test run encountering a container timeout, dropped connection, unhandled exception, or path traversal violation is classified as `actual_outcome: "ERROR"` and `policy_result: "FAIL"`.
- Execution errors are **never** treated as successful access denials (`DENY`).

### Non-Guarantee Disclosure
BREACHLINE evaluates configured boundary isolation on tested filesystem resources. It does **not** guarantee overall sandbox security or prove resistance against unmodeled threats (kernel zero-days, container escape exploits, or hardware side-channels).
