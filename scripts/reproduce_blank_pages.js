const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

async function testFrontend() {
  const htmlPath = path.join(__dirname, '../src/static/index.html');
  const appJsPath = path.join(__dirname, '../src/static/app.js');
  const htmlContent = fs.readFileSync(htmlPath, 'utf-8');
  const appJsContent = fs.readFileSync(appJsPath, 'utf-8');

  console.log('--- Initializing JSDOM test environment ---');

  const virtualConsole = new (require('jsdom').VirtualConsole)();
  virtualConsole.on('error', (...args) => console.error('[BROWSER CONSOLE ERROR]:', ...args));
  virtualConsole.on('warn', (...args) => console.warn('[BROWSER CONSOLE WARN]:', ...args));
  virtualConsole.on('log', (...args) => console.log('[BROWSER CONSOLE LOG]:', ...args));

  const dom = new JSDOM(htmlContent, {
    url: 'http://127.0.0.1:8008/',
    runScripts: 'dangerously',
    virtualConsole,
  });

  const { window } = dom;

  // Polyfill fetch to query live backend on 8008
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
      console.error(`Fetch error for ${fullUrl}:`, e.message);
      throw e;
    }
  };

  // Execute app.js in window context
  try {
    window.eval(appJsContent);
  } catch (err) {
    console.error('Fatal error evaluating app.js:', err);
  }

  // Trigger DOMContentLoaded
  window.document.dispatchEvent(new window.Event('DOMContentLoaded'));

  // Wait for initial refreshAll to settle
  await new Promise(r => setTimeout(r, 1200));

  console.log('\n--- Checking initial view state ---');
  checkActiveView(window, 'Initial Load');

  const navLinks = Array.from(window.document.querySelectorAll('.nav-link'));
  console.log(`Found ${navLinks.length} nav links.`);

  for (const link of navLinks) {
    const viewName = link.getAttribute('data-view');
    console.log(`\n==============================================`);
    console.log(`Clicking nav link for view: "${viewName}"`);
    console.log(`==============================================`);

    link.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));

    // Wait for view render and async fetch to complete
    await new Promise(r => setTimeout(r, 600));

    checkActiveView(window, viewName);
  }
}

function checkActiveView(window, testLabel) {
  const allSections = Array.from(window.document.querySelectorAll('.view-section'));
  const activeSections = allSections.filter(s => s.classList.contains('active'));

  console.log(`[${testLabel}] Total sections: ${allSections.length}, Active sections: ${activeSections.length}`);

  if (activeSections.length === 0) {
    console.error(`🚨 BLANK SCREEN BUG: No section has .active class! Entire page is black!`);
    return;
  }

  if (activeSections.length > 1) {
    console.warn(`⚠️ OVERLAPPING SECTIONS: Multiple sections active: ${activeSections.map(s => s.id).join(', ')}`);
  }

  const active = activeSections[0];
  const sectionId = active.id;
  const cards = Array.from(active.querySelectorAll('.card'));
  const tables = Array.from(active.querySelectorAll('table'));
  const tbodies = Array.from(active.querySelectorAll('tbody'));

  console.log(`Active section: #${sectionId}`);
  console.log(`  Cards count: ${cards.length}`);
  console.log(`  Tables count: ${tables.length}`);

  tbodies.forEach((tb, i) => {
    const rows = tb.querySelectorAll('tr');
    console.log(`  tbody #${tb.id || i}: ${rows.length} rows`);
    if (rows.length > 0) {
      console.log(`    First row sample: "${rows[0].textContent.trim().replace(/\s+/g, ' ').slice(0, 80)}..."`);
    } else {
      console.error(`    🚨 EMPTY TBODY #${tb.id || i}: 0 rows rendered!`);
    }
  });

  // Check if active section text content is empty
  const textContent = active.textContent.trim();
  if (textContent.length === 0) {
    console.error(`🚨 EMPTY VIEW: Section #${sectionId} has NO visible text content!`);
  } else {
    console.log(`  Visible text length: ${textContent.length} characters.`);
  }
}

testFrontend().catch(console.error);
