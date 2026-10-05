// Report controls only; all network and DOM operations are deterministic mocks.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const elements = new Map();
const element = id => { if (!elements.has(id)) elements.set(id, {textContent: '', innerHTML: '', disabled: false, hidden: false}); return elements.get(id); };
const calls = [];
let fail = false, release = null;
const result = {available: true, run_id: 'run-fixture', scenario_id: 'scenario-fixture', url: '/api/report-file?run_id=run-fixture&scenario_id=scenario-fixture', normalized_records: 1, normalized_events: [], runs: [{run_id: 'run-fixture', scenario_id: 'scenario-fixture', campaign_state: 'COMPLETED'}]};
const context = vm.createContext({document: {getElementById: element}, encodeURIComponent, console, fetch: async (url, options) => {
  calls.push({url, options});
  if (options.method === 'POST') {
    if (release) await new Promise(resolve => { release = resolve; });
    if (fail) return {ok: false, status: 400, json: async () => ({error: {message: 'No completed evidence'}})};
  }
  return {ok: true, json: async () => result};
}});
const source = fs.readFileSync(path.join(__dirname, '../gui/web/app.js'), 'utf8');
vm.runInContext(source.replace(/window.addEventListener\('hashchange', activateRoute\); bindControls\(\); activateRoute\(\);/, ''), context);
(async () => {
  await vm.runInContext('loadReports()', context);
  assert.equal(element('report-open').href, result.url);
  assert.equal(element('report-download').href, result.url + '&download=1');
  assert.equal(element('report-open').hidden, false);
  release = true;
  const generating = vm.runInContext('generateReport()', context);
  await vm.runInContext('generateReport()', context);
  assert.equal(calls.filter(c => c.options.method === 'POST').length, 1);
  assert.equal(element('report-generate').disabled, true);
  release(); release = null; await generating;
  assert.match(element('report-status').textContent, /Report generated/);
  const post = calls.find(c => c.options.method === 'POST');
  assert.equal(post.url, '/api/report/generate');
  assert.equal(JSON.parse(post.options.body).run_id, result.run_id);
  fail = true; await vm.runInContext('generateReport()', context);
  assert.match(element('report-status').textContent, /Report generation failed: No completed evidence/);
  assert.equal(element('report-generate').disabled, false);
  console.log('GUI report frontend: PASS (request, success, failure, links, duplicate suppression)');
})().catch(error => { console.error(error); process.exitCode = 1; });
