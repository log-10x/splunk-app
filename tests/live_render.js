// Render a view of the app on a running Splunk and report what is actually on the page.
//
//   npm install playwright          (drives the Chrome already on the machine)
//   node tests/live_render.js <view> <outprefix> [searchterm]
//   SPLUNK_WEB=http://localhost:8000 SPLUNK_USER=admin SPLUNK_PASS=... 
//
// Why this exists: the 10x Search tab shipped for months as a page that rendered
// "Loading..." and nothing else, on every Splunk version, while every static asset it
// referenced resolved and every REST endpoint answered. The only check that sees a page
// is a browser. This logs in, opens /app/tenx-for-splunk/<view>, waits, screenshots, and
// prints the signals that matter as one JSON document: whether a search bar or a
// dashboard body is present, whether "Loading..." is still on screen, whether the
// expansion hook's beforeSend is installed on jQuery, the console errors, and every POST
// the page made to /search/jobs or /tenx-search. Given a term, it also types a search
// on whichever input the page offers, Splunk's search bar or a dashboard form, runs it,
// and reports whether the results carry the term and where the job was posted.
//
// A healthy 10x Search tab reads: loadingStuck false, dashboardBody true, hookInstalled
// true, no console errors, and with a term, termOccurrences above zero and a job posted
// to /tenx-search. The benchmark harness in log-10x/benchmarks (splunk-license) stands up
// an instance this runs against.
const { chromium } = require('playwright');

const BASE = process.env.SPLUNK_WEB || 'http://localhost:8000';
const USER = process.env.SPLUNK_USER || 'admin';
const PASS = process.env.SPLUNK_PASS || 'Chang3d!Bench21';
const [view, out, term] = process.argv.slice(2);

(async () => {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const posted = [];
  page.on('request', r => { if (r.method() === 'POST') posted.push(r.url()); });
  const consoleErrors = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200)); });
  page.on('pageerror', e => consoleErrors.push('pageerror: ' + String(e).slice(0, 200)));

  await page.goto(`${BASE}/en-US/account/login`, { waitUntil: 'domcontentloaded', timeout: 120000 });
  await page.fill('input[name="username"]', USER);
  await page.fill('input[name="password"]', PASS);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 120000 }).catch(() => {}),
    page.click('input[type="submit"], button[type="submit"]'),
  ]);

  const url = `${BASE}/en-US/app/tenx-for-splunk/${view}`;
  await page.goto(url, { waitUntil: 'load', timeout: 180000 });
  await page.waitForTimeout(8000);

  const signals = await page.evaluate(() => {
    const q = s => document.querySelector(s);
    const text = s => (q(s) ? q(s).textContent.trim().slice(0, 120) : null);
    return {
      title: document.title,
      bodyChars: document.body.innerText.length,
      loadingStuck: /Loading\.\.\./.test(document.body.innerText),
      searchBar: !!(q('.search-bar') || q('textarea.search-field') || q('[data-test="search-bar"]') || q('.search-bar-wrapper')),
      timeRangePicker: !!(q('.time-range-picker') || q('[data-test="time-range-picker"]') || q('.timerange')),
      searchTitle: text('.search-title'),
      dashboardBody: !!q('.dashboard-body'),
      applicationJsLoaded: !!window.__tenx_application_js_loaded,
      hookInstalled: !!(window.$ && window.$.ajaxSettings && typeof window.$.ajaxSettings.beforeSend === 'function'),
      appBar: !!(q('#placeholder-app-bar') || q('.app-bar') || q('[data-role="app-nav"]')),
      h1: text('h1') || text('h2'),
      firstText: document.body.innerText.replace(/\s+/g, ' ').slice(0, 300),
    };
  });

  await page.screenshot({ path: `${out}.png`, fullPage: true });

  let searchResult = null;
  if (term) {
    // Type into whichever search input the page offers, run it, and wait.
    // Splunk's search page offers a textarea; a classic dashboard form offers a text
    // input plus a Submit button. Handle both, and say which one was used.
    let input = await page.$('textarea.search-field, .search-bar textarea, textarea[name="search"], input[type="search"], .search-bar-input textarea');
    let via = 'search page';
    if (!input) { input = await page.$('.fieldset .input-text input, .input-text input[type="text"], form input[type="text"]'); via = 'dashboard form'; }
    if (input) {
      await input.fill(`index=tenx_enc sourcetype=tenx_encoded ${term}`);
      if (via === 'dashboard form') {
        const submit = await page.$('.form-submit button, button.btn-primary, .submit-button button');
        if (submit) await submit.click(); else await input.press('Enter');
      } else {
        await input.press('Enter');
      }
      await page.waitForTimeout(30000);
      searchResult = await page.evaluate((t) => {
        const body = document.body.innerText;
        const hits = (body.match(new RegExp(t, 'g')) || []).length;
        const count = (body.match(/([\d,]+)\s+events?/i) || [])[1] || null;
        return { termOccurrences: hits, eventCountText: count, snippet: body.replace(/\s+/g, ' ').slice(0, 400) };
      }, term);
      searchResult.via = via;
      await page.screenshot({ path: `${out}-search.png`, fullPage: true });
    } else {
      searchResult = { error: 'no search input found on the page' };
    }
  }

  console.log(JSON.stringify({
    view, url, signals, searchResult,
    searchJobsPostedTo: posted.filter(u => /search\/jobs|tenx-search/.test(u)).map(u => u.replace(BASE, '')).slice(0, 6),
    consoleErrors: consoleErrors.slice(0, 5),
  }, null, 2));
  await browser.close();
})().catch(e => { console.log(JSON.stringify({ view, fatal: String(e).slice(0, 400) })); process.exit(1); });
