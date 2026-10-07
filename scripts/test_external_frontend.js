'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const root = path.resolve(__dirname,'..'), elements = new Map();
assert.match(fs.readFileSync(path.join(root,'gui/web/styles.css'),'utf8'), /\[data-page="network"\] \[hidden\]\{display:none!important\}/, 'Hidden normal/import panels must override grid/flex display styles');
class Element {
  constructor(tag='div') { this.tagName=tag; this.children=[]; this.listeners={}; this.style={}; this.files=[]; this.value=''; this.textContent=''; this.hidden=false; this.open=false; this.className=''; }
  get classList() { return {contains: c => this.className.split(' ').includes(c)}; }
  get options() { return this.children; }
  set innerHTML(value) { this.markup=value; for(const m of value.matchAll(/id="([^"]+)"/g)) { const child=new Element(); child.id=m[1]; elements.set(m[1],child); } }
  append(...nodes) { nodes.forEach(n => { if(n.parent) n.parent.children=n.parent.children.filter(c=>c!==n); n.parent=this; this.children.push(n); }); }
  prepend(n) { if(n.parent) n.parent.children=n.parent.children.filter(c=>c!==n); n.parent=this; this.children.unshift(n); }
  replaceChildren(...nodes) { this.children=[]; this.textContent=''; this.append(...nodes); }
  addEventListener(name,handler) { this.listeners[name]=handler; }
  closest() { return this.parent; }
  querySelector() { return this.label || new Element('label'); }
}
const network=new Element(), reports=new Element(), sourcePanel=new Element('article'), selector=new Element('select'), heading=new Element(); heading.className='page-heading'; sourcePanel.label=new Element('label'); sourcePanel.append(selector); network.append(heading,sourcePanel,new Element());
elements.set('topology-selector',selector); elements.set('topology-selection-status',new Element());
const native=JSON.parse(fs.readFileSync(path.join(root,'examples/ascend_exchange.json'),'utf8'));
const normal={source:'canonical',revision:'normal',document:{name:'case14',network:{devices:[{id:'scada',name:'SCADA',type:'scada'},{id:'plc1',name:'PLC1',type:'plc'}]}},firewall_policies:[]};
const imported={source:'external',revision:'external',document:{...native,name:'GNS3 clients',network:{devices:[{id:'client1',name:'Client1',type:'generic'},{id:'client2',name:'Client2',type:'generic'},{id:'switch',name:'SW-1',type:'switch'},{id:'fw1',name:'FW-1',type:'firewall'},{id:'internet',name:'Internet',type:'generic'}]}},firewall_policies:[{id:'fw1',name:'FW-1',configuration_available:false,evaluation_supported:false,interfaces:[],rules:[],default_action:null}],pyvis_html:'preview'};
let active=normal, failImport=false; const calls=[], draws=[];
const window={}, context={window,topologySetupReady:true,updateControlStates(){},document:{querySelector:s=>s.includes('network')?network:reports,createElement:tag=>new Element(tag),getElementById:id=>elements.get(id)},drawPyvisTopology:(target,html)=>draws.push(html),
  api:async route=>route==='/api/topology/source'?active:{document:imported.document,revision:'external',pyvis_html:'preview'},
  postApi:async(route,data)=>{ calls.push({route,data}); if(failImport) throw Error('Invalid endpoint'); if(route.endsWith('use-imported')) { active=imported; return active; } if(route.includes('evaluate')) return {action:'deny',allowed:false,matched_rule_id:null}; return {document:imported.document,revision:'external',warnings:[],pyvis_html:'preview'}; }};
vm.runInNewContext(fs.readFileSync(path.join(root,'gui/web/external.js'),'utf8'),context);
const el=id=>elements.get(id), texts=n=>[n.textContent,...n.children.flatMap(texts)].join(' ');
(async()=>{
  await window.syncTopologySource(); assert.equal(network.children[network.children.length-2].hidden,true); assert.equal(el('external-firewall').value,'');
  await window.showExternalImport(); assert.equal(network.children[2].hidden,true); assert.equal(el('external-preview').hidden,false);
  await el('external-import').listeners.click(); assert.match(el('external-status').textContent,/Select/);
  el('external-file').files=[{size:50,text:async()=>'{"topology":{}}'}]; el('external-format').value='gns3'; await el('external-import').listeners.click();
  assert.equal(calls[0].route,'/api/topology/import'); assert.equal(el('external-evaluate').disabled,true,'Preview must not load firewall context');
  await el('external-use').listeners.click();
  assert.equal(el('external-firewall').children[1].textContent,'FW-1'); assert.equal(el('external-firewall').children.length,2);
  assert.equal(el('external-source').value,''); assert.equal(el('external-destination').value,'');
  assert.deepEqual(el('external-source').children.slice(1).map(o=>o.textContent),['Client1','Client2','Internet']);
  assert.match(texts(el('firewall-rules')),/No firewall rules configured/);
  assert.match(texts(el('firewall-rules')),/Configuration: Not Available.*Rules: 0.*Interfaces: 0.*Default policy: Unknown/);
  assert.equal(el('external-evaluate').disabled,true);
  imported.firewall_policies=[{id:'fw1',name:'FW-1',configuration_available:true,evaluation_supported:true,interfaces:[{id:'inside',ip:'10.0.0.1/24'}],rules:[{rule_id:'first',priority:0,action:'deny',source:'client1',destination:'internet',protocol:'tcp',source_port:1234,destination_port:502}],default_action:'allow'}];
  await window.syncTopologySource();
  assert.match(texts(el('firewall-rules')),/Configuration: Imported.*Rules: 1.*Interfaces: 1.*Default policy: ALLOW/);
  assert.equal(el('external-evaluate').disabled,false);
  assert.match(texts(el('firewall-rules')),/DENY.*Client1.*Internet.*TCP\/502.*source port 1234/);
  const firewallRuntime={generation:'g1',core:{state:'RUNTIME',session_id:1,firewalls:[{firewall_id:'fw1',revision:'external',session_id:1,generation_id:'g1',enforced:true,backend:'nftables',rules_installed:3}]}};
  window.renderFirewallEnforcement(firewallRuntime); assert.match(el('firewall-enforcement').textContent,/ACTIVE.*nftables.*Rules Installed: 3/);
  firewallRuntime.core.firewalls[0].enforced=false; firewallRuntime.core.firewalls[0].error='installation failed';
  window.renderFirewallEnforcement(firewallRuntime); assert.match(el('firewall-enforcement').textContent,/FAILED.*installation failed/);
  firewallRuntime.core.firewalls[0].enforced=true; firewallRuntime.core.firewalls[0].revision='old';
  window.renderFirewallEnforcement(firewallRuntime); assert.match(el('firewall-enforcement').textContent,/NOT INITIALIZED/);
  el('external-source').value='client1'; el('external-destination').value='internet'; el('external-protocol').value='tcp'; el('external-port').value='502'; el('external-source-port').value='1234';
  await el('external-evaluate').listeners.click(); assert.equal(calls.at(-1).data.traffic.source_port,1234); assert.equal(calls.at(-1).data.revision,'external'); assert.match(el('external-decision').textContent,/DENY.*modeled policy.*Model decision only/);
  active=normal; window.showCanonicalTopology(); await window.syncTopologySource(); assert.equal(el('external-firewall').children.length,1); assert.equal(el('external-decision').textContent,''); assert.equal(el('external-preview').hidden,true);
  assert.deepEqual(el('external-source').children.slice(1).map(o=>o.value),['scada','plc1']);
  await window.showExternalImport(); failImport=true; await el('external-import').listeners.click(); assert.match(el('external-status').textContent,/rejected/); assert.equal(el('external-use').disabled,true);
  window.renderRemediationRecommendations([{finding:'ASCEND-PG-001',severity:'High',attack_technique:'T0836',affected_asset:'<img onerror=x>',attack_path:[],current_configuration:{firewalls:[]},observed_weakness:'Weakness',recommended_change:'Restrict access',proposed_rules:[{action:'allow',source:'scada',destination:'plc8',protocol:'tcp',destination_port:502,priority:1}],expected_security_benefit:'Reduced exposure',retest_procedure:['Repeat the same test'],applied:false}]);
  const card=el('remediation-list').children[0]; assert.equal(card.tagName,'article'); assert.match(texts(card),/Observed Weakness.*Current Configuration.*Recommended Remediation.*Proposed Change.*Expected Security Benefit.*Retest Procedure/s); assert.match(texts(card),/Not established from retained evidence/); assert.match(texts(card),/PROPOSED — NOT APPLIED/);
  const details=card.children.at(-1); assert.equal(details.tagName,'details'); assert.equal(details.open,false); assert.equal(details.children[1].tagName,'pre'); assert.match(details.children[1].textContent,/"applied": false/); assert.ok(!card.children.some(n=>n.tagName==='pre'),'Raw JSON must be collapsed');
  console.log('External frontend: source switching, FW-1 selector, active endpoints, model evaluation, readable cards and collapsed raw data PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
