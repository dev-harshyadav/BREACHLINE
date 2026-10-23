# BREACHLINE: Step-by-Step Judge Demonstration Script

**Project:** BREACHLINE — Evidence-Producing Boundary-Test Harness for AI Evaluation Sandboxes  
**Hackathon:** Hack in Hills '26  
**Track:** Track 04 — Securing Adversarial AI Safety Testing Infrastructure  
**Team:** NovaCrew  
**Team Lead:** Harsh Yadav  
**Tagline:** *"Don't just claim isolation. Test the boundary. Verify the evidence."*

---

## 10-Step Competitive Demonstration Protocol

| Step | Action | Focus Area | What the Judge Sees | Spoken Presentation Point |
| :--- | :--- | :--- | :--- | :--- |
| **01** | Open Application | Command Center / Overview | Clean Dark Navy SOC Dashboard, 8 Live KPI cards | Core purpose: Testing boundaries rather than assuming container names isolate workloads. |
| **02** | Check Readiness | System Diagnostics (View 10) | Python 3.14 runtime, Docker Workers online (UID 1001/1002), volume integrity | Pre-flight validation: verifies real Linux DAC environment before executing tests. |
| **03** | Configure Test | Click "Run Boundary Tests" | Guided Modal: Docker Isolation Mode, Scenarios T1-T4 breakdown | Worker separation (Red UID 1001 vs Blue UID 1002) and deliberate negative control setup. |
| **04** | Execute Tests | Click "Start Evaluation Run" | Progress indicator & live execution table update | Genuine execution across Docker worker REST endpoints and Linux kernel DAC. |
| **05** | Explain Results | Test Results Table | T1 (PASS), T2 (PASS), T3 (PASS), T4 (FAIL - Negative Control) | T1-T3 pass expected permissions. T4 catches misconfigured 0644 mode bits. |
| **06** | Inspect Violation | Violation Inspector (View 5) | Finding Card: `FINDING-T4`, expected DENY vs observed ALLOW | Mismatch detection: Explains why this is an intentional control, not a production breach. |
| **07** | Verify Evidence | Evidence Vault & Verifier | Deterministic Canonical JSON, Genesis Block, Unbroken Hash Chain | Independent cryptographic verification: 64-zero genesis anchor, canonical payload hashing. |
| **08** | Tamper Simulation | Tamper Lab (View 8) | Attack 1 (Field Mod) & Attack 5 (Full-Chain Rewrite + Trust Anchor) | Dual defense: Hash chains catch local edits; Independent Trust Anchor catches rewrites. |
| **09** | Generate Report | Report Center (View 9) | Embedded interactive HTML audit report, download buttons (HTML/JSON/TXT) | Audit deliverable: Separate Policy Result (`FAIL`) from Evidence Result (`VALID`). |
| **10** | Close with Value | Wrap-Up & Value Summary | Honest security model & limitations | Defensible engineering: Evaluating tested behavior without claiming absolute immunity. |

---

### Step 1: Open the Application (Overview Dashboard)
**Action:** Launch `./breachline serve --port 8008` and navigate to `http://localhost:8008/`.  
**Spoken Script:**
> *"Judges, in AI evaluation infrastructure, red-team and blue-team agents frequently run in separate sandboxes. Teams routinely assume that having container names or separate virtual networks guarantees isolation. In reality, misconfigured shared volumes and permissive file mode bits silently leak sensitive evaluation benchmarks and credentials.
>
> BREACHLINE is built to solve this exact problem. Our motto is: **'Don't just claim isolation. Test the boundary. Verify the evidence.'**
>
> Our Command Center displays real-time metrics from actual runs: total boundary evaluations, policy matches, unexpected access detections, and cryptographic verification statuses."*

---

### Step 2: Check System Readiness (System Diagnostics)
**Action:** Click **"Settings & Environment"** in the sidebar.  
**Spoken Script:**
> *"Before running security tests, we must verify the execution environment. Under System Diagnostics, you see our Darwin host, Python runtime, and critical infrastructure: both the **Red Worker** (`UID 1001:1001`) and **Blue Worker** (`UID 1002:1002`) containers are active and healthy.
>
> Notice that the workers mount an isolated Linux volume (`breachline-fixture-vol`). This avoids macOS VirtioFS permission translations and ensures tests execute against genuine Linux Kernel POSIX Discretionary Access Control (DAC)."*

---

### Step 3: Configure the Test (Guided Modal)
**Action:** Click the top-right button **"Run Boundary Tests"** to open the Guided Test Execution modal.  
**Spoken Script:**
> *"When configuring an evaluation, BREACHLINE supports three explicit execution modes:
> 1. **Docker Worker Isolation** — Real Linux kernel DAC across non-root containers.
> 2. **Host OS POSIX DAC** — Kernel syscalls under the local process identity.
> 3. **Simulated Mode** — Explicitly labeled application-level simulation for offline logic testing.
>
> We never silently substitute a simulated run for real OS enforcement. We select Docker mode and review our standard 4-test matrix: T1 through T4."*

---

### Step 4: Execute the Tests
**Action:** Click **"Start Evaluation Run"** in the modal.  
**Spoken Script:**
> *"We trigger the run. The runner dispatches authenticated execution commands to the worker containers. Each container executes filesystem read syscalls as an unprivileged user against target resources."*

---

### Step 5: Explain the Results
**Action:** Point to the newly rendered **Latest Boundary Evaluation Results** table.  
**Spoken Script:**
> *"The results are in:
> - **T1 (Red reads Red Secret):** Expected `ALLOW`, Observed `ALLOW` &rarr; **PASS**. Red accesses its own credential.
> - **T2 (Red reads Blue Secret):** Expected `DENY`, Observed `DENY` &rarr; **PASS**. The Linux kernel denies Red with `[Errno 13] Permission denied`. Cross-tenant boundary is enforced!
> - **T3 (Blue reads Blue Secret):** Expected `ALLOW`, Observed `ALLOW` &rarr; **PASS**. Blue accesses its own benchmark.
> - **T4 (Red reads Leaky Fixture):** Expected `DENY`, Observed `ALLOW` &rarr; **FAIL**.
>
> Crucially, Test T4 is an **intentional negative control fixture** configured with permissive `0644` permissions. BREACHLINE detects the discrepancy and flags it as a policy mismatch."*

---

### Step 6: Open the Failed Case (Violation Inspector)
**Action:** Click **"Violation Inspector"** in the sidebar.  
**Spoken Script:**
> *"In the Violation Inspector, the engine analyzes `FINDING-T4`. It documents the exact worker, target resource, and the expected vs observed outcome (`DENY` &rarr; `ALLOW`).
>
> It also clearly identifies this as a **DELIBERATE NEGATIVE CONTROL**. We do not present this as a real production breach; we present it as proof that our harness genuinely catches access-control misconfigurations rather than generating rubber-stamp passes."*

---

### Step 7: Verify the Evidence (Evidence Vault & Cryptographic Verifier)
**Action:** Click **"Evidence Vault"**, click a record to view the canonical JSON, then navigate to **"Integrity Verifier"** and click **"Execute Cryptographic Verification"**.  
**Spoken Script:**
> *"Every single event is serialized into deterministic canonical JSON—keys sorted lexicographically, whitespace eliminated—and hashed with SHA-256 into a chronological chain anchored to a 64-zero genesis block.
>
> When we run the standalone verifier, it independently recomputes every hash from scratch. It verifies all 4 records and confirms the chain is mathematically **VALID**."*

---

### Step 8: Demonstrate Tampering Detection & Trust Anchor Defense (Tamper Lab)
**Action:** Click **"Tamper Lab"**. Click **"Attack 1: Modify Field"**, then click **"Attack 5: Full-Chain Rewrite"**.  
**Spoken Script:**
> *"To prove our tamper-evidence is real, our Tamper Lab tests attacks on disposable copies while keeping the original evidence untouched:
> - **Attack 1:** An attacker edits Record 4 to turn FAIL into PASS. The verifier immediately catches it with `RECORD_HASH_MISMATCH`.
> - **Attack 2, 3, & 4:** Deletions, timeline swaps, and broken pointers are caught with `SEQUENCE_BREAK` and `HASH_CHAIN_DISCONTINUITY`.
> - **Attack 5:** Now look at the advanced vector: an attacker rewrites the whole chain and recalculates all SHA-256 hashes. A hash chain alone is internally self-consistent. But BREACHLINE introduces an **Independent Trust Anchor** commitment! Look at the result: the external anchor catches the tip-hash divergence immediately: `COMMITMENT DIVERGED`. The rewrite is caught!"*

---

### Step 9: Generate the Report (Audit Report Center)
**Action:** Click **"Audit Reports"** in the sidebar. Show the report iframe, and point to the download buttons.  
**Spoken Script:**
> *"Every run produces a judge-ready, downloadable audit report available in HTML, JSON, and TXT formats.
>
> Notice the two distinct headers:
> - **Policy Result: FAIL** (Because Test T4 detected the negative-control access violation).
> - **Evidence Integrity: VALID** (Because the audit records and cryptographic trust anchors are mathematically intact).
>
> We never conflate policy security with evidence validity."*

---

### Step 10: Close with the Value
**Action:** Return to the Overview page.  
**Spoken Script:**
> *"Judges, BREACHLINE is designed to bring rigor and technical credibility to AI evaluation sandboxes:
> 1. We test boundaries empirically with non-root workers.
> 2. We detect unexpected access outcomes.
> 3. We record immutable, verifiable evidence.
> 4. We disclose known limitations honestly: BREACHLINE tests configured DAC behavior; it does not claim to replace kernel security or hypervisor hardening.
>
> All 33 unit and integration tests pass cleanly. Thank you, and we welcome your questions."*

---

## Command-Line Alternative (Terminal-Only Presentation)

If presenting from a terminal without browser:

```bash
# 1. Run all 33 tests
python3 -m pytest tests/ -v

# 2. Run boundary evaluation in genuine Docker mode
./breachline run --mode docker

# 3. Verify the generated cryptographic evidence
./breachline verify output/evidence.jsonl

# 4. Demonstrate all 5 tampering attack detections + Trust Anchor defense
./breachline tamper --attack all

# 5. Generate multi-format audit reports
./breachline report

# 6. Launch web workbench on port 8008
./breachline serve --port 8008
```
