# Known Limitations & Technical Disclosures

This document outlines the known technical boundaries, design trade-offs, and environmental limitations of the BREACHLINE prototype.

---

## 1. Filesystem Semantics: macOS Docker Desktop vs. Linux Hosts

### Observed Behavior
When mounting local directories directly from a macOS host into Docker Desktop containers via standard bind mounts (`./fixtures:/data`), macOS utilizes virtualization file sharing drivers (VirtioFS or legacy osxfs). 

- These drivers translate macOS host file ownership and Access Control Lists (ACLs) dynamically into the container VM.
- Consequently, container processes running under arbitrary non-root UIDs (e.g., UID `1001`) may be granted read access to files created by the host user, effectively bypassing POSIX Discretionary Access Control (DAC) permission bits (`chmod 600`).

### BREACHLINE Mitigation & Architecture
To ensure rigorous, reproducible testing across any operating system:
1. BREACHLINE isolates test fixtures inside a native Docker volume (`breachline-fixture-vol`).
2. A dedicated initialization service (`breachline-fixture-init`) formats the volume inside the Linux kernel container layer, assigning exact UID ownership (`1001:1001` for red, `1002:1002` for blue) and POSIX permission bits (`0700` directories, `0600` secret files).
3. Containers mount this volume as read-only (`:ro`).

**Takeaway:** Never rely on host bind-mounts when testing POSIX DAC boundaries under macOS Docker Desktop without validating how the virtualization layer translates file permissions.

---

## 2. Hash-Chain Integrity vs. Full-Chain Rewrites

### The Mathematical Limitation
BREACHLINE utilizes canonical SHA-256 hash chaining to link each audit record to its predecessor, starting from a documented genesis hash (`GENESIS_HASH = "0" * 64`).

- **What it detects:** Any localized mutation (modifying a test result, deleting an entry, swapping entries) is mathematically detected because subsequent record links and recomputed hashes immediately diverge.
- **What it cannot detect alone:** If an adversary possesses unrestricted write access to `evidence.jsonl` AND rewrites all subsequent records from the altered point onward (recomputing valid SHA-256 hashes for all records), the file will remain internally consistent.

### Required Production Enhancement
To prevent full-chain rewrites in high-assurance environments:
- **External Anchoring**: The final tip hash (or Merkle root) must be periodically anchored into an external, append-only log (e.g., an RFC 3161 cryptographic timestamping service, an immutable cloud transparency log like Google Rekor / Sigstore, or an external ledger).
- **Append-Only Filesystem / WORM Storage**: The log file should be streamed directly to write-once-read-many (WORM) storage where historical blocks cannot be modified or replaced.

---

## 3. Discretionary Access Control (DAC) vs. Mandatory Access Control (MAC)

BREACHLINE validates Linux Discretionary Access Control (DAC) boundaries implemented via distinct Linux UIDs/GIDs and file permission bits.

- **DAC Limitations:** DAC relies on the object owner or administrative superuser correctly configuring file mode bits. If an administrator inadvertently grants world-read permissions (`chmod 644`), DAC permits access (as demonstrated in negative control test `T4`).
- **Mandatory Access Control (MAC):** High-security evaluation sandboxes often layer MAC policies (e.g., SELinux type enforcement, AppArmor profiles, or seccomp-bpf syscall filters) to enforce policy rules regardless of file ownership. The current MVP tests DAC permissions; MAC policies can be integrated into future test suites.

---

## 4. Network and Execution Boundaries

- **In Scope:** Local filesystem read boundaries between two isolated non-root container users.
- **Out of Scope:**
  - Network-level packet filtering / egress filtering tests.
  - Multi-tenant GPU / CUDA memory isolation.
  - CPU side-channel timing analysis.
  - Container escape vulnerabilities targeting the host kernel.
