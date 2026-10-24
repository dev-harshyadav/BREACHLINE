const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

async function runComprehensiveFrontendTests() {
  const htmlPath = path.join(__dirname, '../src/static/index.html');
  const appJsPath = path.join(__dirname, '../src/static/app.js');
  const htmlContent = fs.readFileSync(htmlPath, 'utf-8');
  const appJsContent = fs.readFileSync(appJsPath, 'utf-8');

  console.log('===============================================================');
  console.log('BREACHLINE WORKBENCH FRONTEND VERIFICATION SUITE');
  console.log('===============================================================');

  const errors = [];
  const warnings = [];

  const virtualConsole = new (require('jsdom').VirtualConsole)();
  virtualConsole.on('error', (...args) => {
    console.error('  [BROWSER ERROR]:', ...args);
    errors.push(args.join(' '));
  });
  virtualConsole.on('warn', (...args) => {
    warnings.push(args.join(' '));
  });

  const dom = new JSDOM(htmlContent, {
    url: 'http://127.0.0.1:8008/',
    runScripts: 'dangerously',
    virtualConsole,
  });

  const { window } = dom;

  // Real fetch connecting to live backend on 8008
  window.fetch = async (url, opts) => {
    const fullUrl = url.startsWith('http') ? url : `http://127.0.0.1:8008${url}`;
    try {
      const res = await fetch(fullUrl, opts);
      const text = await res.text();
      return {
        ok: res.ok,
        status: res.status,
        statusText: res.statusText,
        text: async () => text,
        json: async () => JSON.parse(text),
      };
    } catch (e) {
      console.error(`Fetch failed for ${fullUrl}:`, e.message);
      throw e;
    }
  };

  // Evaluate app.js
  window.eval(appJsContent);
  window.document.dispatchEvent(new window.Event('DOMContentLoaded'));

  // Wait for initial refresh
  await new Promise(r => setTimeout(r, 1200));

  const allViews = [
    'overview',
    'boundary-lab',
    'scenarios',
    'history',
    'inspector',
    'vault',
    'verification',
    'tamper-lab',
    'reports',
    'settings',
  ];

  console.log('\n--- TEST 1: Direct Hash Navigation & DOM Visibility ---');
  for (const view of allViews) {
    window.location.hash = `#${view}`;
    window.dispatchEvent(new window.HashChangeEvent('hashchange'));
    await new Promise(r => setTimeout(r, 350));

    const sec = window.document.getElementById(`view-${view}`);
    const activeSecs = Array.from(window.document.querySelectorAll('.view-section.active'));
    
    if (!sec) {
      errors.push(`Missing section #view-${view}`);
      console.error(`❌ Section #view-${view} does not exist in DOM!`);
      continue;
    }

    const isActive = sec.classList.contains('active');
    const parentIsMain = sec.parentElement && sec.parentElement.tagName === 'MAIN';
    const textLen = sec.textContent.trim().length;
    const cards = sec.querySelectorAll('.card').length;

    console.log(`[View: ${view.padEnd(14)}] Active: ${isActive ? '✅' : '❌'} | Parent: ${parentIsMain ? 'MAIN (✅)' : 'WRONG (❌)'} | TextLen: ${textLen} | Cards: ${cards} | Active Count: ${activeSecs.length}`);

    if (!isActive) errors.push(`View ${view} failed to acquire .active class`);
    if (!parentIsMain) errors.push(`View ${view} is nested under ${sec.parentElement.tagName} instead of MAIN`);
    if (textLen < 50) errors.push(`View ${view} has insufficient content (${textLen} chars)`);
    if (activeSecs.length !== 1) errors.push(`Multiple or zero active sections during view ${view}: ${activeSecs.length}`);
  }

  console.log('\n--- TEST 2: Sidebar Navigation Link Clicks ---');
  const navLinks = Array.from(window.document.querySelectorAll('.nav-link'));
  for (const link of navLinks) {
    const viewName = link.getAttribute('data-view');
    link.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
    await new Promise(r => setTimeout(r, 350));

    const activeSec = window.document.querySelector('.view-section.active');
    const expectedSec = window.document.getElementById(`view-${viewName}`);
    const match = activeSec === expectedSec;
    const linkActive = link.classList.contains('active');

    console.log(`[Click: ${viewName.padEnd(14)}] Matches Section: ${match ? '✅' : '❌'} | Link Active: ${linkActive ? '✅' : '❌'}`);
    if (!match) errors.push(`Sidebar link for ${viewName} did not activate #view-${viewName}`);
    if (!linkActive) errors.push(`Sidebar link for ${viewName} did not get .active class`);
  }

  console.log('\n--- TEST 3: Graceful Unknown Route Recovery ---');
  window.location.hash = '#nonexistent-route-xyz-999';
  window.dispatchEvent(new window.HashChangeEvent('hashchange'));
  await new Promise(r => setTimeout(r, 350));

  const activeAfterUnknown = window.document.querySelector('.view-section.active');
  const recoveredToOverview = activeAfterUnknown && activeAfterUnknown.id === 'view-overview';
  console.log(`[Unknown Route Test] Recovered to Overview: ${recoveredToOverview ? '✅' : '❌'}`);
  if (!recoveredToOverview) errors.push('Unknown route did not gracefully recover to view-overview');

  console.log('\n--- TEST 4: Boundary Lab Probe Execution ---');
  window.location.hash = '#boundary-lab';
  window.dispatchEvent(new window.HashChangeEvent('hashchange'));
  await new Promise(r => setTimeout(r, 400));

  const probeForm = window.document.getElementById('form-boundary-probe');
  probeForm.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
  await new Promise(r => setTimeout(r, 1200));

  const obsCard = window.document.getElementById('probe-observation-card');
  const obsVisible = obsCard && obsCard.style.display !== 'none';
  const obsUid = window.document.getElementById('obs-uid')?.textContent;
  const obsActual = window.document.getElementById('obs-actual-outcome')?.textContent;
  const obsPolicy = window.document.getElementById('obs-policy-result')?.textContent;
  console.log(`[Probe Execution] Observation Card Visible: ${obsVisible ? '✅' : '❌'} | UID: ${obsUid} | Actual: ${obsActual} | Policy: ${obsPolicy}`);
  if (!obsVisible) errors.push('Probe observation card was not displayed after submit');
  if (!obsActual || obsActual === '—') errors.push('Actual outcome was not populated on observation card');

  console.log('\n--- TEST 5: Cryptographic Chain Verification ---');
  window.location.hash = '#verification';
  window.dispatchEvent(new window.HashChangeEvent('hashchange'));
  await new Promise(r => setTimeout(r, 400));

  const btnVerify = window.document.getElementById('btn-run-full-verifier');
  btnVerify.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
  await new Promise(r => setTimeout(r, 1200));

  const verOut = window.document.getElementById('verifier-output-card')?.textContent;
  const chainNodes = window.document.querySelectorAll('#chain-visual-flow .chain-node').length;
  console.log(`[Verifier Output] Contains PASS/FAIL: ${verOut.includes('PASS') || verOut.includes('FAIL') ? '✅' : '❌'} | Visual Chain Nodes: ${chainNodes}`);
  if (!verOut.includes('PASS') && !verOut.includes('FAIL')) errors.push('Verifier card did not render verification result');
  if (chainNodes === 0) errors.push('No visual chain nodes rendered in verification flow');

  console.log('\n--- TEST 6: Evidence Tampering Simulation ---');
  window.location.hash = '#tamper-lab';
  window.dispatchEvent(new window.HashChangeEvent('hashchange'));
  await new Promise(r => setTimeout(r, 400));

  // Run attack 1
  await window.runTamperAttack('ATTACK_1');
  await new Promise(r => setTimeout(r, 1000));

  const tamperCards = window.document.querySelectorAll('#tamper-results-container .card').length;
  console.log(`[Tamper Simulation] Rendered Result Cards: ${tamperCards}`);
  if (tamperCards === 0) errors.push('No tamper result cards rendered after attack');

  console.log('\n===============================================================');
  console.log(`VERIFICATION SUMMARY: ${errors.length === 0 ? 'ALL CHECKS PASSED ✅' : 'FAILURES DETECTED ❌'}`);
  console.log(`Total Errors: ${errors.length}`);
  if (errors.length > 0) {
    errors.forEach(e => console.error('  - ' + e));
  }
  console.log('===============================================================');

  if (errors.length > 0) process.exit(1);
}

runComprehensiveFrontendTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
