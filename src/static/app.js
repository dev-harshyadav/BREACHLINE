/**
 * BREACHLINE Security Workbench — Frontend Application Logic
 */

let state = {
  currentView: 'overview',
  systemStatus: null,
  latestRunId: null,
  activeRunData: null,
  runsList: [],
  labSchema: null,
};

// Initialize Application
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupEventHandlers();
  const heroRun = document.getElementById('hero-run-tests');
  if (heroRun) heroRun.addEventListener('click', () => openRunModal());
  await refreshAll();
  handleHashRouting();
});

// Navigation Handling
function setupNavigation() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const view = link.getAttribute('data-view');
      navigateTo(view);
    });
  });
}

function navigateTo(viewName) {
  state.currentView = viewName;
  window.location.hash = viewName;

  document.querySelectorAll('.nav-link').forEach(l => {
    if (l.getAttribute('data-view') === viewName) {
      l.classList.add('active');
    } else {
      l.classList.remove('active');
    }
  });

  document.querySelectorAll('.view-section').forEach(sec => {
    sec.classList.remove('active');
  });

  const activeSec = document.getElementById(`view-${viewName}`);
  if (activeSec) {
    activeSec.classList.add('active');
  }

  // Update Page Title
  const titles = {
    'overview': 'Security Boundary Overview',
    'boundary-lab': 'Boundary Testing Laboratory',
    'scenarios': 'Configured Test Scenarios',
    'history': 'Run History & Reproducibility',
    'inspector': 'Violation & Anomaly Inspector',
    'vault': 'Cryptographic Evidence Vault',
    'verification': 'Independent Integrity Verifier',
    'tamper-lab': 'Evidence Tampering Laboratory',
    'reports': 'Audit Report Center',
    'settings': 'Environment & Security Settings',
  };
  document.getElementById('current-view-title').textContent = titles[viewName] || 'BREACHLINE Workbench';

  // Trigger view-specific data refresh
  if (viewName === 'vault' || viewName === 'verification') {
    renderVaultAndVerification();
  } else if (viewName === 'inspector') {
    renderInspector();
  } else if (viewName === 'reports') {
    renderReportFrame();
  }
}

function handleHashRouting() {
  const hash = window.location.hash.replace('#', '');
  if (hash && document.getElementById(`view-${hash}`)) {
    navigateTo(hash);
  }
}

// Run Modal Functions
function openRunModal() {
  const modal = document.getElementById('run-modal');
  if (modal) modal.classList.add('open');
}

function closeRunModal() {
  const modal = document.getElementById('run-modal');
  if (modal) modal.classList.remove('open');
}

// Event Handlers
function setupEventHandlers() {
  document.getElementById('btn-refresh-status').addEventListener('click', async () => {
    await refreshAll();
  });

  document.getElementById('btn-run-suite').addEventListener('click', () => {
    openRunModal();
  });

  const modeSel = document.getElementById('select-exec-mode');
  const hint = document.getElementById('modal-mode-hint');
  if (modeSel && hint) {
    modeSel.addEventListener('change', () => {
      if (modeSel.value === 'docker') {
        hint.textContent = 'Genuine Linux kernel enforcement across isolated container boundaries (Red: UID 1001 vs Blue: UID 1002).';
      } else if (modeSel.value === 'local_os') {
        hint.textContent = 'Executes real OS open() syscalls against local host filesystem permissions under current process UID.';
      } else {
        hint.textContent = 'Application-level role branching for offline environments. Explicitly marked as is_os_enforced: false.';
      }
    });
  }

  const btnStartRun = document.getElementById('btn-modal-start-run');
  if (btnStartRun) {
    btnStartRun.addEventListener('click', async () => {
      const selectedMode = document.getElementById('select-exec-mode')?.value || 'auto';
      closeRunModal();
      await triggerRun(selectedMode);
    });
  }

  document.getElementById('btn-quick-verify').addEventListener('click', async () => {
    navigateTo('verification');
    await runFullVerification();
  });

  document.getElementById('btn-run-full-verifier').addEventListener('click', async () => {
    await runFullVerification();
  });

  // Boundary Probe Form
  document.getElementById('form-boundary-probe').addEventListener('submit', async e => {
    e.preventDefault();
    await submitBoundaryProbe();
  });

  // Export buttons
  document.getElementById('btn-export-jsonl').addEventListener('click', () => {
    if (state.latestRunId) {
      window.open(`/api/runs/${state.latestRunId}/evidence`, '_blank');
    } else {
      alert('No run available to export.');
    }
  });

  document.getElementById('btn-export-json').addEventListener('click', () => {
    if (state.latestRunId) {
      window.open(`/api/runs/${state.latestRunId}/report?format=json`, '_blank');
    } else {
      alert('No run available to export.');
    }
  });

  // Report downloads
  document.getElementById('btn-download-html').addEventListener('click', () => {
    if (state.latestRunId) window.open(`/api/runs/${state.latestRunId}/report?format=html`, '_blank');
  });
  document.getElementById('btn-download-json').addEventListener('click', () => {
    if (state.latestRunId) window.open(`/api/runs/${state.latestRunId}/report?format=json`, '_blank');
  });
  document.getElementById('btn-download-txt').addEventListener('click', () => {
    if (state.latestRunId) window.open(`/api/runs/${state.latestRunId}/report?format=txt`, '_blank');
  });
  document.getElementById('btn-print-report').addEventListener('click', () => {
    const iframe = document.getElementById('report-iframe');
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.print();
    }
  });

  // Run Comparison
  document.getElementById('btn-open-compare').addEventListener('click', openCompareModal);
  document.getElementById('btn-execute-compare').addEventListener('click', executeRunComparison);
}

// Data Fetching & Core Refresh
async function refreshAll() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    state.systemStatus = data;

    updateHeaderAndSidebar(data);
    updateKpis(data.metrics, data.latest_run);

    if (data.latest_run) {
      state.latestRunId = data.latest_run.run_id;
      await fetchRunDetails(state.latestRunId);
    }

    await fetchRunsHistory();
    await fetchBoundaryLabSchema();
    await renderInspector();
  } catch (err) {
    console.error('Failed to load status:', err);
  }
}

function updateHeaderAndSidebar(status) {
  const isDocker = status.docker_environment && status.docker_environment.available;
  const modeText = isDocker ? 'Docker Containerized (Isolated)' : 'Local POSIX Sandbox (Kernel DAC)';
  
  document.getElementById('header-mode-text').textContent = modeText;
  document.getElementById('sidebar-env-text').textContent = isDocker ? 'Docker Connected' : 'Local Sandbox Active';

  // Settings view table
  const tbody = document.getElementById('tbody-env-settings');
  if (tbody) {
    tbody.innerHTML = `
      <tr><td>Host OS</td><td class="mono">${status.system_info.os} ${status.system_info.release}</td></tr>
      <tr><td>Python Runtime</td><td class="mono">${status.system_info.python}</td></tr>
      <tr><td>Execution Mode</td><td class="mono">${modeText}</td></tr>
      <tr><td>Docker Status</td><td class="mono">${isDocker ? '<span class="text-green">Available</span>' : '<span class="text-amber">Offline / Unavailable</span>'}</td></tr>
      <tr><td>Red Worker URL</td><td class="mono">${status.docker_environment?.red_worker?.url || 'N/A'}</td></tr>
      <tr><td>Blue Worker URL</td><td class="mono">${status.docker_environment?.blue_worker?.url || 'N/A'}</td></tr>
      <tr><td>Diagnostic Notice</td><td class="text-secondary" style="font-size:0.85rem;">${status.docker_environment?.message || ''}</td></tr>
    `;
  }
}

function updateKpis(metrics, latestRun) {
  if (!metrics) return;
  document.getElementById('kpi-total-runs').textContent = metrics.total_runs;
  document.getElementById('kpi-cases-executed').textContent = metrics.total_cases_executed;
  document.getElementById('kpi-policy-matches').textContent = metrics.policy_matches;
  document.getElementById('kpi-policy-mismatches').textContent = metrics.policy_mismatches;
  document.getElementById('kpi-unexpected-access').textContent = metrics.unexpected_access_outcomes;
  document.getElementById('kpi-verified-chains').textContent = metrics.verified_evidence_chains;
  document.getElementById('kpi-invalid-chains').textContent = metrics.invalid_evidence_chains;

  if (latestRun) {
    document.getElementById('kpi-recent-run').textContent = latestRun.run_id.slice(0, 8) + '...';
  } else {
    document.getElementById('kpi-recent-run').textContent = 'None';
  }
}

async function fetchRunDetails(runId) {
  try {
    const res = await fetch(`/api/runs/${runId}`);
    if (!res.ok) return;
    const data = await res.json();
    state.activeRunData = data;
    renderOverviewResults(data);
    renderScenariosTable(data.config || []);
  } catch (err) {
    console.error('Failed to fetch run details:', err);
  }
}

function renderOverviewResults(runData) {
  const tbody = document.getElementById('tbody-overview-results');
  if (!runData || !runData.records || runData.records.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted" style="text-align:center;">No test execution recorded yet. Click "Run Boundary Tests".</td></tr>`;
    return;
  }

  let html = '';
  runData.records.forEach(r => {
    const isPass = r.result === 'PASS';
    const resBadge = isPass ? '<span class="badge badge-pass">PASS</span>' : '<span class="badge badge-fail">FAIL</span>';
    const isUnexpected = r.expected_outcome === 'DENY' && r.actual_outcome === 'ALLOW';
    const noteBadge = isUnexpected ? '<span class="badge badge-warn">UNEXPECTED ACCESS</span>' : '<span class="text-muted">Expected</span>';

    html += `
      <tr>
        <td class="mono font-bold">${r.test_id}</td>
        <td>${r.test_description}</td>
        <td class="mono text-cyan">${r.role}</td>
        <td class="mono" style="font-size:0.8rem;">${r.operation}</td>
        <td><span class="mono pill-${r.expected_outcome.toLowerCase()}">${r.expected_outcome}</span></td>
        <td><span class="mono pill-${r.actual_outcome.toLowerCase()}">${r.actual_outcome}</span></td>
        <td>${resBadge}</td>
        <td>${noteBadge}</td>
      </tr>
    `;
  });
  tbody.innerHTML = html;

  // Overview Verification summary box
  const meta = runData.meta || {};
  const verif = meta.evidence_integrity || {};
  const isValid = verif.is_valid;
  const isAnchored = meta.anchored || (meta.trust_anchor && meta.trust_anchor.anchored);
  const statusHtml = `
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <div>
        Status: <strong class="${isValid ? 'text-green' : 'text-red'}">${isValid ? 'VALID (Tamper-Evidence Passed)' : 'INVALID / TAMPERED'}</strong>
        <span style="color:var(--text-muted); margin-left:1rem;">Verified ${verif.total_records || 0} Records</span>
        ${isAnchored ? '<span class="badge badge-pass" style="margin-left:0.75rem;">TRUST ANCHOR VERIFIED</span>' : ''}
      </div>
      <div class="mono text-cyan" style="font-size:0.75rem;">Run ID: ${meta.run_id || 'N/A'}</div>
    </div>
  `;
  document.getElementById('overview-verification-box').innerHTML = statusHtml;

  // Badges in Card Header
  document.getElementById('latest-run-badges').innerHTML = `
    <span class="badge badge-info">Mode: ${meta.execution_mode || 'auto'}</span>
    <span class="badge ${isValid ? 'badge-pass' : 'badge-fail'}">Chain: ${isValid ? 'VALID' : 'INVALID'}</span>
    ${isAnchored ? '<span class="badge badge-pass">Anchored</span>' : ''}
  `;
}

function renderScenariosTable(configList) {
  const tbody = document.getElementById('tbody-scenarios-list');
  if (!tbody) return;
  if (!configList || configList.length === 0) {
    configList = state.labSchema?.presets?.standard_demo || [];
  }
  let html = '';
  configList.forEach(tc => {
    const isNeg = tc.is_negative_control || tc.test_id === 'T4';
    html += `
      <tr>
        <td class="mono font-bold">${tc.test_id}</td>
        <td class="mono text-cyan">${tc.role}</td>
        <td class="mono" style="font-size:0.8rem;">${tc.target_path}</td>
        <td><span class="mono pill-${tc.expected_outcome.toLowerCase()}">${tc.expected_outcome}</span></td>
        <td>${isNeg ? '<span class="badge badge-warn">NEGATIVE CONTROL</span>' : '<span class="text-muted">Standard</span>'}</td>
        <td style="font-size:0.85rem; color:var(--text-secondary);">${tc.test_description}</td>
      </tr>
    `;
  });
  tbody.innerHTML = html;
}

// Run Boundary Tests Trigger
async function triggerRun(mode = 'auto') {
  const btn = document.getElementById('btn-run-suite');
  btn.disabled = true;
  btn.innerHTML = `<span class="dot-pulse"></span> Running...`;

  try {
    const res = await fetch('/api/runs/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: mode }),
    });

    if (!res.ok) {
      const err = await res.json();
      alert(`Test run failed: ${err.detail || 'Unknown error'}`);
      return;
    }

    const data = await res.json();
    state.latestRunId = data.run_id;
    await refreshAll();
    navigateTo('overview');
  } catch (err) {
    console.error('Run failed:', err);
    alert(`Execution error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `&#9654; Run Boundary Tests`;
  }
}

// Boundary Lab
async function fetchBoundaryLabSchema() {
  try {
    const res = await fetch('/api/boundary-lab/schema');
    if (!res.ok) return;
    const data = await res.json();
    state.labSchema = data;

    const tbody = document.getElementById('tbody-lab-fixtures');
    if (tbody && data.fixtures) {
      let html = '';
      data.fixtures.forEach(f => {
        html += `
          <tr>
            <td class="mono font-bold text-cyan">${f.resource_id}</td>
            <td class="mono">${f.path}</td>
            <td class="mono">${f.owner}</td>
            <td class="mono text-amber">${f.mode}</td>
            <td style="font-size:0.85rem; color:var(--text-secondary);">${f.description}</td>
          </tr>
        `;
      });
      tbody.innerHTML = html;
    }
  } catch (err) {
    console.error('Failed to load lab schema:', err);
  }
}

async function submitBoundaryProbe() {
  const role = document.getElementById('probe-worker').value;
  const operation = document.getElementById('probe-operation').value;
  const path = document.getElementById('probe-path').value;
  const expected = document.getElementById('probe-expected').value;

  const btn = document.getElementById('btn-submit-probe');
  btn.disabled = true;
  btn.textContent = 'Probing...';

  try {
    const res = await fetch('/api/boundary-lab/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role: role,
        operation: operation,
        target_path: path,
        expected_outcome: expected,
        test_description: `Interactive probe: ${role} ${operation} ${path}`,
      }),
    });

    const data = await res.json();
    const container = document.getElementById('probe-result-container');
    const out = document.getElementById('probe-result-output');
    container.style.display = 'block';

    out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    alert(`Probe error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = '⚡ Dispatch Probe';
  }
}

// Run History Table
async function fetchRunsHistory() {
  try {
    const res = await fetch('/api/runs');
    if (!res.ok) return;
    const data = await res.json();
    state.runsList = data.runs || [];

    const tbody = document.getElementById('tbody-run-history');
    if (!tbody) return;

    if (state.runsList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-muted" style="text-align:center;">No history recorded yet.</td></tr>`;
      return;
    }

    let html = '';
    state.runsList.forEach(r => {
      const verif = r.evidence_integrity || {};
      const verifBadge = verif.is_valid ? '<span class="badge badge-pass">VALID</span>' : '<span class="badge badge-fail">INVALID</span>';
      html += `
        <tr>
          <td class="mono font-bold text-cyan" style="cursor:pointer;" onclick="selectRun('${r.run_id}')">${r.run_id.slice(0, 8)}...</td>
          <td class="mono" style="font-size:0.8rem;">${r.timestamp_utc || ''}</td>
          <td><span class="badge badge-info">${r.execution_mode || 'auto'}</span></td>
          <td class="mono">${r.total_tests || 0}</td>
          <td class="mono text-green">${r.policy_matches || 0}</td>
          <td class="mono text-red">${r.policy_mismatches || 0}</td>
          <td>${verifBadge}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="selectRun('${r.run_id}')">Inspect</button>
            <a class="btn btn-secondary btn-sm" href="/api/runs/${r.run_id}/evidence" target="_blank">&#128190;</a>
          </td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

async function selectRun(runId) {
  state.latestRunId = runId;
  await fetchRunDetails(runId);
  navigateTo('overview');
}

// Run Comparison
function openCompareModal() {
  const modal = document.getElementById('compare-modal');
  const selA = document.getElementById('compare-select-a');
  const selB = document.getElementById('compare-select-b');

  selA.innerHTML = '';
  selB.innerHTML = '';

  state.runsList.forEach((r, idx) => {
    const optA = document.createElement('option');
    optA.value = r.run_id;
    optA.textContent = `${r.run_id.slice(0, 8)} (${r.timestamp_utc?.slice(11, 19)}) - ${r.execution_mode}`;
    selA.appendChild(optA);

    const optB = document.createElement('option');
    optB.value = r.run_id;
    optB.textContent = `${r.run_id.slice(0, 8)} (${r.timestamp_utc?.slice(11, 19)}) - ${r.execution_mode}`;
    selB.appendChild(optB);
  });

  if (selB.options.length > 1) {
    selB.selectedIndex = 1;
  }

  modal.classList.add('open');
}

function closeCompareModal() {
  document.getElementById('compare-modal').classList.remove('open');
}

async function executeRunComparison() {
  const runA = document.getElementById('compare-select-a').value;
  const runB = document.getElementById('compare-select-b').value;

  try {
    const res = await fetch('/api/runs/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ run_id_a: runA, run_id_b: runB }),
    });

    if (!res.ok) {
      const err = await res.json();
      alert(`Comparison error: ${err.detail}`);
      return;
    }

    const data = await res.json();
    closeCompareModal();

    const diffBox = document.getElementById('comparison-diff-output');
    document.getElementById('card-comparison-results').style.display = 'block';

    let tableHtml = `
      <div style="margin-bottom:1rem; font-size:0.9rem;">
        Comparing <strong>Run A (${runA.slice(0, 8)})</strong> vs <strong>Run B (${runB.slice(0, 8)})</strong>:
        <span class="badge ${data.differences_count > 0 ? 'badge-warn' : 'badge-pass'}" style="margin-left:0.5rem;">
          ${data.differences_count} Differences Detected
        </span>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Test ID</th>
            <th>Diff Status</th>
            <th>Run A Result</th>
            <th>Run B Result</th>
            <th>Expected A vs B</th>
            <th>Actual A vs B</th>
          </tr>
        </thead>
        <tbody>
    `;

    data.test_comparisons.forEach(tc => {
      const statusBadge = tc.status_change === 'UNCHANGED'
        ? '<span class="badge badge-pass">UNCHANGED</span>'
        : `<span class="badge badge-warn">${tc.status_change}</span>`;

      tableHtml += `
        <tr>
          <td class="mono font-bold">${tc.test_id}</td>
          <td>${statusBadge}</td>
          <td><span class="badge ${tc.run_a?.result === 'PASS' ? 'badge-pass' : 'badge-fail'}">${tc.run_a?.result || 'N/A'}</span></td>
          <td><span class="badge ${tc.run_b?.result === 'PASS' ? 'badge-pass' : 'badge-fail'}">${tc.run_b?.result || 'N/A'}</span></td>
          <td class="mono">${tc.run_a?.expected || '-'} &rarr; ${tc.run_b?.expected || '-'}</td>
          <td class="mono">${tc.run_a?.actual || '-'} &rarr; ${tc.run_b?.actual || '-'}</td>
        </tr>
      `;
    });

    tableHtml += `</tbody></table>`;
    diffBox.innerHTML = tableHtml;
  } catch (err) {
    alert(`Comparison error: ${err.message}`);
  }
}

// Violation Inspector
async function renderInspector() {
  try {
    const res = await fetch('/api/findings');
    if (!res.ok) return;
    const data = await res.json();
    const findings = data.findings || [];

    document.getElementById('inspector-count-badge').textContent = `${findings.length} Findings`;

    const container = document.getElementById('inspector-findings-list');
    if (!container) return;

    if (findings.length === 0) {
      container.innerHTML = `<div class="text-muted" style="text-align:center; padding:2rem;">No policy violations or unexpected access detected.</div>`;
      return;
    }

    let html = '';
    findings.forEach(f => {
      const isNeg = f.is_negative_control;
      html += `
        <div class="finding-card ${isNeg ? 'negative-control' : ''}">
          <div class="finding-title">
            <div>
              <span class="mono font-bold text-red" style="font-size:1.05rem;">${f.finding_id}</span>
              <span class="badge ${isNeg ? 'badge-warn' : 'badge-fail'}" style="margin-left:0.5rem;">
                ${isNeg ? 'DELIBERATE NEGATIVE CONTROL' : 'POLICY VIOLATION'}
              </span>
            </div>
            <span class="mono text-muted" style="font-size:0.8rem;">Run: ${f.run_id.slice(0, 8)}</span>
          </div>

          <div class="finding-grid">
            <div><strong>Worker:</strong> <span class="mono text-cyan">${f.worker}</span></div>
            <div><strong>Target Resource:</strong> <span class="mono">${f.resource}</span></div>
            <div><strong>Operation:</strong> <span class="mono">${f.operation}</span></div>
            <div><strong>Expected vs Observed:</strong> <span class="mono pill-deny">${f.expected_outcome}</span> &rarr; <span class="mono pill-allow">${f.observed_outcome}</span></div>
          </div>

          <div style="font-size:0.88rem; line-height:1.6;">
            <div><strong>Technical Explanation:</strong> <span class="text-secondary">${f.explanation}</span></div>
            <div><strong>Security Interpretation:</strong> <span class="text-secondary">${f.interpretation}</span></div>
            <div style="margin-top:0.35rem;"><strong>Recommended Next Step:</strong> <span class="text-amber">${f.recommended_next_step}</span></div>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  } catch (err) {
    console.error('Failed to render inspector:', err);
  }
}

// Evidence Vault & Canonical JSON view
function renderVaultAndVerification() {
  const records = state.activeRunData?.records || [];
  const tbody = document.getElementById('tbody-evidence-records');
  if (!tbody) return;

  if (records.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted" style="text-align:center;">No records available.</td></tr>`;
    return;
  }

  let html = '';
  records.forEach((r, idx) => {
    const prevShort = r.previous_record_hash.slice(0, 10) + '...';
    const recShort = r.record_hash.slice(0, 10) + '...';
    html += `
      <tr style="cursor:pointer;" onclick="inspectRecord(${idx})">
        <td class="mono font-bold">${r.sequence_number}</td>
        <td class="mono text-cyan">${r.test_id}</td>
        <td class="mono">${r.role}</td>
        <td class="mono" style="font-size:0.8rem;">${r.operation}</td>
        <td><span class="mono pill-${r.actual_outcome.toLowerCase()}">${r.actual_outcome}</span></td>
        <td><span class="badge ${r.result === 'PASS' ? 'badge-pass' : 'badge-fail'}">${r.result}</span></td>
        <td class="mono text-muted" title="${r.previous_record_hash}">${prevShort}</td>
        <td class="mono font-bold text-cyan" title="${r.record_hash}">${recShort}</td>
      </tr>
    `;
  });
  tbody.innerHTML = html;

  if (records.length > 0) {
    inspectRecord(0);
  }
}

function inspectRecord(idx) {
  const records = state.activeRunData?.records || [];
  if (records[idx]) {
    document.getElementById('vault-json-preview').textContent = JSON.stringify(records[idx], null, 2);
  }
}

// Independent Verifier Execution
async function runFullVerification() {
  if (!state.latestRunId) {
    alert('No run available to verify.');
    return;
  }

  const outCard = document.getElementById('verifier-output-card');
  const flowContainer = document.getElementById('chain-visual-flow');
  outCard.innerHTML = `<span class="dot-pulse"></span> Verifying SHA-256 cryptographic chain...`;

  try {
    const res = await fetch(`/api/runs/${state.latestRunId}/verify`);
    const data = await res.json();

    const isValid = data.is_valid;
    const anchor = data.trust_anchor || {};
    const anchorStatus = anchor.status || 'UNANCHORED';
    const isAnchorOk = anchorStatus === 'VERIFIED';
    const isAnchorDiverged = anchorStatus === 'DIVERGED';

    outCard.innerHTML = `
      <div style="margin-bottom:0.75rem;">
        Verification Result: <strong class="${isValid ? 'text-green' : 'text-red'}" style="font-size:1.1rem;">
          ${isValid ? 'PASS: Cryptographic Chain Intact' : 'FAIL: Verification Error Detected'}
        </strong>
      </div>
      <div>&bull; Total Records Examined: <strong>${data.total_records}</strong></div>
      <div>&bull; Genesis Rule: <strong>Satisfied (64 zeroes genesis anchor)</strong></div>
      <div>&bull; Canonical Hashing: <strong>${isValid ? 'All record hashes match computed digests' : 'Hash divergence detected'}</strong></div>
      <div>&bull; Previous Link Integrity: <strong>${isValid ? 'Unbroken chronological continuity' : 'Discontinuity detected'}</strong></div>
      ${data.error_message ? `<div class="text-red" style="margin-top:0.5rem;">Reason: ${data.error_message}</div>` : ''}

      <div style="margin-top:0.9rem; padding:0.75rem; border-radius:var(--radius-sm); background:${isAnchorOk ? 'rgba(5, 150, 105, 0.12)' : (isAnchorDiverged ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.12)')}; border: 1px solid ${isAnchorOk ? 'var(--green-pass)' : (isAnchorDiverged ? 'var(--red-fail)' : 'var(--amber-warn)')};">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>Independent Trust Anchor:</strong>
            <span class="mono font-bold ${isAnchorOk ? 'text-green' : (isAnchorDiverged ? 'text-red' : 'text-amber')}" style="margin-left:0.4rem;">
              ${anchorStatus}
            </span>
          </div>
          <span class="badge ${isAnchorOk ? 'badge-pass' : (isAnchorDiverged ? 'badge-fail' : 'badge-warn')}">
            ${anchor.anchored ? (isAnchorOk ? 'DEFENDED AGAINST REWRITE' : 'COMMITMENT DIVERGED') : 'LOCAL ONLY'}
          </span>
        </div>
        ${anchor.anchored ? `
          <div class="mono text-muted" style="font-size:0.78rem; margin-top:0.35rem;">
            External Anchor Tip: <span class="text-cyan">${anchor.stored_tip_hash?.slice(0, 24)}...</span>
          </div>
        ` : `<div class="text-secondary" style="font-size:0.8rem; margin-top:0.25rem;">No independent external anchor registered for this local run.</div>`}
        ${anchor.error ? `<div class="text-red" style="font-size:0.82rem; margin-top:0.35rem;">${anchor.error}</div>` : ''}
      </div>
    `;

    // Render visual flow
    let flowHtml = '';
    (data.chain || []).forEach((c, idx) => {
      const linkValid = c.link_valid;
      flowHtml += `
        <div class="chain-node ${linkValid ? 'valid' : 'invalid'}">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
            <div>
              <span class="mono font-bold text-cyan">Record #${c.sequence_number} (${c.test_id})</span>
              <span class="badge ${c.result === 'PASS' ? 'badge-pass' : 'badge-fail'}" style="margin-left:0.5rem;">${c.result}</span>
            </div>
            <span class="mono text-muted" style="font-size:0.75rem;">Link: ${linkValid ? 'VALID' : 'BROKEN'}</span>
          </div>
          <div class="mono" style="font-size:0.8rem; color:var(--text-secondary);">
            Previous: <span class="text-muted">${c.previous_record_hash}</span>
          </div>
          <div class="mono" style="font-size:0.8rem; color:var(--text-main);">
            Record Hash: <span class="text-cyan">${c.record_hash}</span>
          </div>
        </div>
        ${idx < (data.chain.length - 1) ? '<div class="chain-arrow">&#8595; SHA-256 Link</div>' : ''}
      `;
    });
    flowContainer.innerHTML = flowHtml;
  } catch (err) {
    outCard.innerHTML = `<span class="text-red">Verification failed to execute: ${err.message}</span>`;
  }
}

// Evidence Tampering Lab
async function runTamperAttack(attackId) {
  const container = document.getElementById('tamper-results-container');
  container.innerHTML = `<div style="padding:1.5rem; text-align:center;"><span class="dot-pulse"></span> Running disposable tamper simulation...</div>`;

  try {
    const res = await fetch('/api/tamper/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_id: attackId }),
    });

    const data = await res.json();
    const experiments = data.experiments || [];

    let html = '';
    experiments.forEach(exp => {
      const isDetected = exp.detected_as_tampered;
      const isRewriteLimitation = exp.attack_id === 'ATTACK_5';

      let statusBadge = '';
      if (isDetected) {
        statusBadge = '<span class="badge badge-pass">TAMPERING DETECTED AS EXPECTED</span>';
      } else if (isRewriteLimitation) {
        statusBadge = '<span class="badge badge-warn">LIMITATION DEMONSTRATED (SELF-CONSISTENT REWRITE)</span>';
      } else {
        statusBadge = '<span class="badge badge-fail">UNDETECTED</span>';
      }

      html += `
        <div class="card" style="border-left: 4px solid ${isDetected ? 'var(--green-pass)' : (isRewriteLimitation ? 'var(--amber-warn)' : 'var(--red-fail)')}; margin-top:1.25rem;">
          <div class="card-header">
            <div>
              <span class="mono font-bold text-cyan" style="font-size:1.05rem;">${exp.attack_id}: ${exp.attack_name}</span>
              <span style="margin-left:0.5rem;">${statusBadge}</span>
            </div>
            <span class="mono text-muted" style="font-size:0.75rem;">Disposable Copy</span>
          </div>

          <p style="color:var(--text-secondary); margin-bottom:0.75rem;">${exp.attack_description}</p>
          
          <div style="background:var(--bg-input); padding:0.85rem; border-radius:var(--radius-sm); margin-bottom:0.75rem; font-size:0.85rem;">
            <div><strong>Transformation:</strong> <span class="mono text-red">${exp.transformation_applied}</span></div>
            <div><strong>Internal Chain Integrity:</strong> <span class="mono ${exp.verifier_result.is_valid ? 'text-amber font-bold' : 'text-green'}">${exp.verifier_result.is_valid ? 'VALID (Self-Consistent Hash Chain Recomputed)' : 'INVALID (Link or Hash Broken)'}</span></div>
            ${exp.verifier_result.error_message ? `<div><strong>Error Detected:</strong> <span class="mono text-red">${exp.verifier_result.error_message}</span></div>` : ''}
          </div>

          ${exp.trust_anchor_check ? `
            <div style="margin-bottom:0.75rem; padding:0.75rem; border-radius:var(--radius-sm); background:rgba(6, 182, 212, 0.1); border:1px solid var(--accent-cyan); font-size:0.85rem;">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong>Independent Trust Anchor Defense:</strong>
                <span class="badge ${exp.trust_anchor_check.detected_by_trust_anchor ? 'badge-pass' : 'badge-warn'}">
                  ${exp.trust_anchor_check.detected_by_trust_anchor ? 'REWRITE DETECTED BY ANCHOR' : exp.trust_anchor_check.trust_anchor_status}
                </span>
              </div>
              <div class="text-secondary" style="margin-top:0.4rem; font-size:0.82rem;">
                ${exp.trust_anchor_check.error || 'External commitment matches.'}
              </div>
              <div class="mono" style="font-size:0.75rem; color:var(--text-muted); margin-top:0.35rem;">
                Stored Anchor Tip: <span class="text-cyan">${exp.trust_anchor_check.stored_tip_hash?.slice(0, 20)}...</span> | Rewritten Tip: <span class="text-red">${exp.trust_anchor_check.tampered_tip_hash?.slice(0, 20)}...</span>
              </div>
            </div>
          ` : ''}

          <div style="font-size:0.88rem; line-height:1.6;">
            <div><strong>Cryptographic Explanation:</strong> <span class="text-secondary">${exp.explanation}</span></div>
            <div style="margin-top:0.35rem;"><strong>Architectural Takeaway:</strong> <span class="text-cyan">${exp.architectural_note}</span></div>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div class="text-red">Error running tampering experiment: ${err.message}</div>`;
  }
}

// Reports View
function renderReportFrame() {
  const iframe = document.getElementById('report-iframe');
  if (state.latestRunId && iframe) {
    iframe.src = `/api/runs/${state.latestRunId}/report?format=html`;
  }
}
