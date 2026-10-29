// Pure renderer fixtures: no HTTP requests, services or campaign execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {innerHTML: ''});
  return elements.get(id);
};
const context = vm.createContext({document: {getElementById: element}, console});
const source = fs.readFileSync(path.join(__dirname, '../gui/web/app.js'), 'utf8');
vm.runInContext(source.replace(/window.addEventListener\('hashchange', activateRoute\); bindControls\(\); activateRoute\(\);/, ''), context);
const evaluate = code => vm.runInContext(code, context);
assert.match(evaluate("evidenceValue('N/A')"), /Not applicable.*—/);
assert.match(evaluate('evidenceValue(null)'), /Unavailable.*—/);
assert.match(evaluate("evidenceValue('')"), /Empty string.*&quot;&quot;/);
for (const value of ['unknown', 'unavailable', 'verified', 0, false]) {
  context.fixtureValue = value;
  assert.equal(evaluate('evidenceValue(fixtureValue)'), String(value));
}
assert.equal(evaluate("networkField({source_ip:'N/A', source_node:'plc1'}, 'source_ip', 'source_node')"), 'plc1');
context.rows = Array.from({length: 200}, (_, i) => ({timestamp: `t${i}`, ppo_step: 'N/A', defense: null,
  correlation_id: `correlation-${i}`, payload: {text: '<script>' + 'x'.repeat(5000) + 'PAYLOAD_END'}}));
const before = JSON.stringify(context.rows);
evaluate(`renderEvidenceTable(document.getElementById('body'), rows, [
  {label:'Timestamp',value:r=>r.timestamp}, {label:'PPO step',value:r=>r.ppo_step,optional:true},
  {label:'Defense',value:r=>r.defense,optional:true}, {label:'Packet / flow',value:r=>r.payload,payload:true}
], 'Empty', 'head')`);
assert.doesNotMatch(element('head').innerHTML, /PPO step|Defense|Correlation/);
assert.match(element('body').innerHTML, /correlation-199/);
assert.match(element('body').innerHTML, /PAYLOAD_END/);
assert.doesNotMatch(element('body').innerHTML, /<script>/);
assert.match(element('body').innerHTML, /&lt;script&gt;/);
assert.equal((element('body').innerHTML.match(/<tr>/g) || []).length, 200);
assert.equal(JSON.stringify(context.rows), before);
context.lifecycle = [
  {event_type:'attack_started',correlation_id:'c',generation_id:'g',severity:'LOW'},
  {event_type:'attack_finished',correlation_id:'c',generation_id:'g',severity:'INFO'},
  {event_type:'detection',correlation_id:'c',generation_id:'g',severity:'HIGH'}
];
const lifecycleBefore = JSON.stringify(context.lifecycle);
assert.equal(evaluate('lifecycle.map(e=>attackEventSeverity(e,lifecycle)).join(",")'), 'LOW,LOW,LOW');
assert.equal(evaluate('attackEventSeverity({...lifecycle[1],generation_id:"foreign"},lifecycle)'), null);
assert.equal(evaluate('attackEventSeverity({event_type:"attack_finished",attack_severity:"MEDIUM"},[])'), 'MEDIUM');
assert.equal(JSON.stringify(context.lifecycle), lifecycleBefore);
const summary = element('body').innerHTML.match(/payload-preview">([^<]*)<\/span>/)[1];
assert.ok(summary.length < 150, 'Payload preview stays compact even for a large JSON object');
assert.match(summary, /…$/);
context.rows = [{ppo_step: 0, defense: false}];
evaluate(`renderEvidenceTable(document.getElementById('body'), rows, [
  {label:'PPO step',value:r=>r.ppo_step,optional:true}, {label:'Defense',value:r=>r.defense,optional:true}
], 'Empty', 'head')`);
assert.match(element('head').innerHTML, /PPO step.*Defense/);
assert.match(element('body').innerHTML, /<td>0<\/td><td>false<\/td>/);
const css = fs.readFileSync(path.join(__dirname, '../gui/web/styles.css'), 'utf8');
assert.match(css, /\.evidence-table-container\{[^}]*max-height:420px[^}]*overflow:auto/);
assert.match(css, /\.evidence-table-container th\{[^}]*position:sticky;top:0/);
assert.match(css, /\.payload-preview\{[^}]*text-overflow:ellipsis/);
const html = fs.readFileSync(path.join(__dirname, '../gui/web/index.html'), 'utf8');
const battleSection = html.match(/<section class="page" data-page="battle">(.*?)<\/section>/s)[1];
assert.equal((battleSection.match(/class="table-wrap evidence-table-container"/g) || []).length, 3);
console.log('Evidence frontend: PASS (large fixtures, placeholders, optional columns, full payload, escaping, immutability, scroll CSS)');
