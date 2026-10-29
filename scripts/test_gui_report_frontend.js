// Report controls only; all network and DOM operations are deterministic mocks.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const elements = new Map();
const element = id => { if (!elements.has(id)) elements.set(id, {textContent: '', innerHTML: '', disabled: false, hidden: false}); return elements.get(id); };
const calls = [];
let fail = false, release = null;
const result = {available: true, run_id: 'run-fixture', scenario_id: 'scenario-fixture', url: '/api/report-file?run_id=run-fixture&scenario_id=scenario-fixture', normalized_records: 1, normalized_events: [],
  display_identity: {assessment: {display_name: 'Assessment 1', internal_id: 'run-fixture'}},
  runs: [{run_id: 'run-fixture', scenario_id: 'scenario-fixture', display_name: 'Assessment 1', campaign_state: 'COMPLETED'}]};
result.normalized_records = 3;
result.finding_summary = {total_findings: 3, detected: 1, failed: 1, timeout: 1, techniques: 2, targets: 2};
result.normalized_events = [{'MITRE ID': 'T0801', 'Target Host': 'plc9', Detected: true,
  'Detection Method': 'ml', 'Detector Confidence': 0.9994547963142395}];
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
  const original = JSON.stringify(result);
  await vm.runInContext('loadReports()', context);
  assert.equal(JSON.stringify(result), original, 'summary rendering must not mutate normalized data');
  const summary = element('report-normalization').innerHTML;
  for (const [label, count] of [['Total findings',3],['Detected',1],['Failed',1],['Timeout',1],['Techniques',2],['Targets',2]]) {
    assert.ok(summary.includes(`<span>${label}</span><strong>${count}</strong>`), label);
  }
  assert.doesNotMatch(summary, /T0801|plc9|Detection method|Confidence|99\.95|Normalized findings/);
  assert.equal(element('report-open').href, result.url);
  assert.equal(element('report-download').href, result.url + '&download=1');
  assert.equal(element('report-open').hidden, false);
  assert.match(element('report-run').innerHTML, />Assessment 1 \(COMPLETED\)<\/option>/);
  assert.doesNotMatch(element('report-status').textContent, /run-fixture/);
  assert.match(element('report-status').textContent, /Assessment 1/);
  // Changing a representative preview cannot change the run-level totals.
  result.normalized_events[0].Detected = false;
  result.normalized_events[0]['Detector Confidence'] = 0;
  const nonDetected = JSON.stringify(result);
  await vm.runInContext('loadReports()', context);
  assert.equal(element('report-normalization').innerHTML, summary);
  assert.equal(JSON.stringify(result), nonDetected);
  const markup = fs.readFileSync(path.join(__dirname, '../gui/web/index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../gui/web/styles.css'), 'utf8');
  assert.match(markup, /class="report-actions"><button id="report-generate" class="report-action report-action-primary"/);
  assert.match(markup, /<a id="report-open" class="report-action report-action-secondary" hidden target="_blank" rel="noopener">Open Report<\/a>/);
  assert.match(markup, /<a id="report-download" class="report-action report-action-outline" hidden>Download HTML<\/a>/);
  assert.match(markup, /REPORT EVIDENCE SUMMARY/);
  assert.match(markup, /Aggregate findings for the selected saved assessment/);
  assert.doesNotMatch(markup, />NORMALIZATION</);
  assert.match(css, /\.report-actions\{[^}]*flex-wrap:wrap/);
  assert.match(css, /\.report-actions \.report-action:focus-visible\{[^}]*outline:/);
  assert.match(css, /\.report-actions \.report-action\[hidden\]\{display:none\}/);
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
  result.available = false; result.url = null;
  await vm.runInContext('loadReports()', context);
  assert.equal(element('report-open').hidden, true);
  assert.equal(element('report-download').hidden, true);
  assert.equal(element('report-open').href, '');
  assert.equal(element('report-download').href, '');
  assert.equal(calls.filter(c => c.options.method === 'POST').length, 2, 'only the existing explicit generation attempts POST');
  console.log('GUI report frontend: PASS (aggregate summary, no representative finding, unchanged links/generation, immutable data, duplicate suppression)');
})().catch(error => { console.error(error); process.exitCode = 1; });
