/* Active analysis topology and readable remediation; no runtime enforcement. */
(() => {
  const network = document.querySelector('[data-page="network"]'), el = id => document.getElementById(id);
  const make = (tag, text, cls) => { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; };
  const sourcePanel = el('topology-selector').closest('article'); network.prepend(sourcePanel);
  sourcePanel.querySelector('label').textContent = 'Topology Source';
  const normalPanels = Array.from(network.children).filter(n => n !== sourcePanel && !n.classList.contains('page-heading'));
  const panel = make('article', null, 'panel external-import-panel'); panel.hidden = true;
  panel.innerHTML = `<div class="section-heading"><p class="eyebrow">EXTERNAL TOPOLOGY</p><h3>Import External Topology</h3><p>Validate a design, then select Use This Topology. Projection compatibility is shown below; unsupported graphs remain analysis-only.</p></div>
    <div class="form-grid external-import-form"><label class="field" for="external-format"><span>Format</span><select id="external-format"><option value="ascend">ASCEND JSON</option><option value="gns3">GNS3 .gns3</option></select></label>
    <label class="field field-wide" for="external-file"><span>Topology file</span><input id="external-file" type="file" accept=".json,.gns3"></label></div>
    <div class="action-row"><button id="external-import" class="button-primary">Validate</button><a class="button button-outline" href="/api/topology/import-sample" download="ascend_exchange.json">Download ASCEND sample</a></div><p id="external-status" class="status-message" role="status" aria-live="polite">Choose a file to validate.</p>
    <div id="external-preview" class="topology-canvas" hidden></div><div class="action-row"><button id="external-use" class="button-primary" disabled>Use This Topology</button></div>
    <details class="technical-details"><summary>Technical Details</summary><pre id="external-config" class="raw-data"></pre></details>`;
  network.append(panel);
  const firewall = make('article', null, 'panel firewall-panel');
  firewall.innerHTML = `<div class="section-heading"><p class="eyebrow">FIREWALL</p><h3>Firewall policy and enforcement</h3><p id="firewall-context" class="status-message" role="status"></p></div>
    <section class="policy-surface policy-model" aria-labelledby="firewall-model-heading"><div class="policy-surface-heading"><div><p class="surface-kicker">MODEL / POLICY EVALUATION</p><h4 id="firewall-model-heading">Modeled policy decision</h4></div><span class="pill neutral">NO PACKETS SENT</span></div><p>Model evaluation sends no packets and applies no rules.</p>
    <label class="field" for="external-firewall"><span>Firewall</span><select id="external-firewall"></select></label><div id="firewall-rules" class="firewall-rules"></div>
    <div class="form-grid firewall-traffic-form"><label class="field" for="external-source"><span>Source device</span><select id="external-source"></select></label><label class="field" for="external-destination"><span>Destination device</span><select id="external-destination"></select></label>
    <label class="field" for="external-protocol"><span>Protocol</span><select id="external-protocol"><option>tcp</option><option>udp</option><option>icmp</option></select></label>
    <label class="field" for="external-source-port"><span>Source port (optional)</span><input id="external-source-port" type="number" min="0" max="65535"></label>
    <label class="field" for="external-port"><span>Destination port</span><input id="external-port" type="number" min="0" max="65535" value="502"></label></div>
    <div class="action-row"><button id="external-evaluate" class="button-primary" disabled>Evaluate policy</button></div><p id="external-decision" class="status-message policy-decision" role="status"></p></section>
    <section class="policy-surface policy-runtime" aria-labelledby="firewall-runtime-heading"><div class="policy-surface-heading"><div><p class="surface-kicker">RUNTIME ENFORCEMENT</p><h4 id="firewall-runtime-heading">CORE firewall state</h4></div></div><p id="firewall-enforcement" class="status-message enforcement-status" role="status">Firewall Enforcement: NOT INITIALIZED</p></section>`;
  network.append(firewall);
  const recommendations = make('article', null, 'panel'); recommendations.innerHTML = '<h3>Remediation Recommendations</h3><p>Engineer review and independent verification required.</p><div id="remediation-list"></div>';
  document.querySelector('[data-page="reports"]').append(recommendations);
  const runtimeInfo = make('article', null, 'panel'); runtimeInfo.append(make('h3', 'Active Canonical Topology'));
  const runtimeFacts = make('dl', null, 'remediation-facts'); runtimeInfo.append(runtimeFacts);
  document.querySelector('[data-page="runtime"]')?.append(runtimeInfo);
  window.syncRuntimeTopology = async () => {
    const context = await api('/api/topology/source'), capability = context.capabilities;
    if (!capability) return;
    const system = typeof latestSystem === 'undefined' ? null : latestSystem;
    const ready = system?.core?.state === 'RUNTIME' && system?.active_run?.run?.topology_version === context.revision;
    const devices = context.document.network.devices;
    runtimeFacts.replaceChildren();
    [['Active topology', context.document.name], ['Source', context.canonical_source], ['Physical model', capability.physical_model], ['CORE testbed', ready ? 'Ready' : capability.core_testbed], ['PPO', capability.ppo], ['Nodes / links', `${context.node_count} / ${context.link_count}`], ['Firewall', `${context.firewall_policies.length} canonical devices; runtime status shown separately`], ['PLC / RTU devices', devices.filter(d => ['plc', 'rtu'].includes(d.type)).length], ['IDS / IPS devices', devices.filter(d => ['ids', 'ips'].includes(d.type)).length]].forEach(([label, value]) => runtimeFacts.append(make('dt', label), make('dd', String(value))));
  };
  let active = null, preview = null, sequence = 0;
  function options(target, items) { target.replaceChildren(make('option', 'Select…')); target.children[0].value = ''; items.forEach(item => { const option = make('option', item.name || item.id); option.value = item.id; target.append(option); }); target.value = ''; }
  const ruleText = (r, names = {}) => `${String(r.action).toUpperCase()}  ${names[r.source] || r.source} → ${names[r.destination] || r.destination}  ${String(r.protocol).toUpperCase()}/${r.destination_port ?? 'ANY'} (source port ${r.source_port ?? 'ANY'}, priority ${r.priority})`;
  function clearFirewall() { active = null; sequence++; ['external-firewall','external-source','external-destination'].forEach(id => options(el(id), [])); el('firewall-rules').replaceChildren(); el('external-decision').textContent = ''; el('external-evaluate').disabled = true; el('firewall-enforcement').textContent = 'Firewall Enforcement: NOT INITIALIZED'; }
  function showEnforcement(system) {
    const runtime = system?.core, target = el('firewall-enforcement');
    const status = runtime?.firewalls?.find(s => s.firewall_id === el('external-firewall').value && s.revision === active?.revision && s.generation_id === system?.generation && String(s.session_id) === String(runtime.session_id));
    target.textContent = status && runtime.state === 'RUNTIME' ? (status.enforced ? `Firewall Enforcement: ACTIVE · Backend: ${status.backend} · Rules Installed: ${status.rules_installed}. Installation verified; packet blocking requires separate traffic evidence.` : `Firewall Enforcement: FAILED · Reason: ${status.error || 'Installation not verified'}`) : 'Firewall Enforcement: NOT INITIALIZED';
  }
  window.renderFirewallEnforcement = showEnforcement;
  function mode(external) { normalPanels.forEach(n => n.hidden = external || (n.id === 'custom-topology-panel' && !String(el('topology-selector').value).startsWith('custom'))); panel.hidden = !external; if (!external) { el('external-preview').hidden = true; el('external-use').disabled = true; } }
  function ensureOption() { const selector = el('topology-selector'); if (!Array.from(selector.options).some(o => o.value === 'external')) { const option = make('option', 'Import External Topology'); option.value = 'external'; selector.append(option); } }
  function showRules() {
    const target = el('firewall-rules'); target.replaceChildren(); const policy = active?.firewall_policies.find(p => p.id === el('external-firewall').value);
    showEnforcement(typeof latestSystem === 'undefined' ? null : latestSystem);
    el('external-evaluate').disabled = !policy || policy.configuration_available === false || policy.evaluation_supported === false;
    if (!policy) { target.append(make('p', 'No firewall selected or configured for this topology.', 'empty-inline')); return; }
    target.append(make('p', `Firewall: ${policy.name || policy.id} · Configuration: ${policy.configuration_available === false ? 'Not Available' : 'Imported'} · Rules: ${policy.rules.length} · Interfaces: ${(policy.interfaces || []).length} · Default policy: ${policy.default_action == null ? 'Unknown' : String(policy.default_action).toUpperCase()}`, 'firewall-summary'));
    if (policy.import_complete === false && policy.configuration_available) target.append(make('p', 'Partial or unsupported configuration import. Model evaluation unavailable.'));
    if (policy.evaluation_supported === false && policy.configuration_available && policy.import_complete !== false) target.append(make('p', 'Configuration retained; its scope or references are unsupported for model evaluation.'));
    if (!policy.rules.length) target.append(make('p', 'No firewall rules configured. No rules imported.'));
    else { const rules = make('ol', null, 'firewall-rule-list'), names = Object.fromEntries(active.document.network.devices.map(d => [d.id,d.name || d.id])); policy.rules.forEach(r => rules.append(make('li',ruleText(r,names)))); target.append(rules); }
  }
  function bindActive(context) {
    clearFirewall(); active = context; el('firewall-context').textContent = `Active topology: ${context.document.name || context.source}. ${context.runtime_supported ? 'Supported CORE projection.' : 'Analysis only; CORE deployment unavailable.'}`;
    const firewallIds = new Set(context.document.network.devices.filter(d => d.type === 'firewall').map(d => d.id));
    options(el('external-firewall'),context.firewall_policies.filter(p => firewallIds.has(p.id)));
    const endpoints = context.document.network.devices.filter(d => !['switch','firewall','ids','ips'].includes(d.type)); options(el('external-source'),endpoints); options(el('external-destination'),endpoints);
    el('external-firewall').value = context.firewall_policies.find(p => firewallIds.has(p.id))?.id || '';
    const scada = endpoints.find(d => d.type === 'scada'), plc = endpoints.find(d => ['plc','rtu'].includes(d.type)); if (scada && plc) { el('external-source').value = scada.id; el('external-destination').value = plc.id; } showRules();
  }
  function showPreview(result) { preview = result; el('external-status').textContent = `Valid: ${result.document.network.devices.length} devices, ${result.document.links.length} links. ${(result.warnings || []).join(' ')}`; el('external-config').textContent = JSON.stringify(result.document,null,2); el('external-preview').hidden = false; drawPyvisTopology(el('external-preview'),result.pyvis_html); el('external-use').disabled = false; }
  window.showCanonicalTopology = () => { mode(false); clearFirewall(); el('firewall-context').textContent = 'Loading selected topology…'; };
  window.showExternalImport = async () => { mode(true); clearFirewall(); el('firewall-context').textContent = 'Use the validated topology to load its firewall context.'; el('topology-selection-status').textContent = 'External import mode. Validate, then use the topology.'; try { const result = await api('/api/topology/imported'); if (!panel.hidden && result.document) showPreview(result); } catch(e) { el('external-status').textContent = e.message; } };
  window.syncTopologySource = async () => {
    const ticket = ++sequence; ensureOption(); const context = await api('/api/topology/source'); if(ticket !== sequence) return;
    mode(context.source === 'external'); bindActive(context); topologySetupReady = context.runtime_supported; updateControlStates();
    const capability = context.capabilities;
    if (capability) el('firewall-context').textContent = `Active topology: ${context.document.name} · Source: ${context.canonical_source} · Physical model: ${capability.physical_model} · CORE testbed: ${capability.core_testbed} · PPO: ${capability.ppo} · Nodes: ${context.node_count} · Links: ${context.link_count}. ${capability.reason}`;
    if(context.source === 'external') { el('topology-selector').value = 'external'; showPreview({...context,revision:context.preview_revision,warnings:[]}); el('external-status').textContent = `Active imported topology: ${context.document.name}. ${capability?.reason || 'Compatibility must be checked.'}`; }
  };
  el('external-firewall').addEventListener('change', () => { sequence++; el('external-decision').textContent = ''; showRules(); });
  el('external-import').addEventListener('click',async () => {
    const file = el('external-file').files[0]; if(!file) { el('external-status').textContent = 'Select a file first.'; return; } if(file.size > 1900000) { el('external-status').textContent = 'File exceeds the 1.9 MB limit.'; return; }
    preview = null; clearFirewall(); el('firewall-context').textContent = 'Validate and use this preview to load its firewall context.'; el('external-use').disabled = true; el('external-preview').hidden = true; el('external-import').disabled = true;
    try { const result = await postApi('/api/topology/import',{format:el('external-format').value,document:JSON.parse(await file.text())}); if(!panel.hidden) showPreview(result); } catch(e) { el('external-status').textContent = `Import rejected: ${e.message}. Active topology unchanged.`; } finally { el('external-import').disabled = false; }
  });
  el('external-use').addEventListener('click',async () => { if(!preview) return; el('external-use').disabled = true; try { const context = await postApi('/api/topology/use-imported',{revision:preview.revision}); mode(true); bindActive(context); el('topology-selector').value = 'external'; topologySetupReady = context.runtime_supported; updateControlStates(); el('external-status').textContent = `Active imported topology: ${context.document.name}. ${context.capabilities?.reason || 'Check projection compatibility.'}`; } catch(e) { el('external-status').textContent = `Selection failed: ${e.message}`; el('external-use').disabled = false; } });
  el('external-evaluate').addEventListener('click',async () => {
    if(!active) return; const ticket = sequence; if(!el('external-source').value || !el('external-destination').value) { el('external-decision').textContent = 'Select source and destination devices.'; return; }
    const port = id => el(id).value === '' ? null : Number(el(id).value);
    try { const result = await postApi('/api/firewall/evaluate',{revision:active.revision,firewall_id:el('external-firewall').value,traffic:{source:el('external-source').value,destination:el('external-destination').value,protocol:el('external-protocol').value,source_port:port('external-source-port'),destination_port:port('external-port')}}); if(ticket === sequence) el('external-decision').textContent = `${result.action.toUpperCase()} — According to the modeled policy, this traffic would be ${result.allowed ? 'allowed' : 'denied'}. ${result.matched_rule_id || 'Default policy'}. Model decision only; runtime enforcement shown separately.`; } catch(e) { if(ticket === sequence) el('external-decision').textContent = e.message; }
  });
  function section(card,title,content) { const block = make('section',null,'remediation-section'); block.append(make('h4',title)); block.append(typeof content === 'string' ? make('p',content) : content); card.append(block); }
  window.renderRemediationRecommendations = items => {
    const list = el('remediation-list'); list.replaceChildren(); if(!items.length) { list.textContent = 'No completed finding recommendations for this assessment.'; return; }
    items.forEach(item => {
      const card = make('article',null,'remediation-card'); const cardHeading = make('div', null, 'remediation-heading'); cardHeading.append(make('h3',`Finding ${item.finding}`), make('span', String(item.severity || 'Unavailable').toUpperCase(), `severity-badge severity-${String(item.severity || 'unavailable').toLowerCase()}`)); card.append(cardHeading); const facts = make('dl',null,'remediation-facts');
      [['Finding ID',item.finding],['Severity',String(item.severity || 'Unavailable').toUpperCase()],['Attack',[item.attack_technique,item.attack_name].filter(Boolean).join(' / ')],['Affected Asset',item.affected_asset],['Attack Path',item.attack_path?.length ? item.attack_path.join(' → ') : 'Not established from retained evidence.']].forEach(([label,value]) => { const valueNode = make('dd',value); if (label === 'Severity') valueNode.className = 'technical-value'; facts.append(make('dt',label),valueNode); }); card.append(facts);
      section(card,'Observed Weakness',item.observed_weakness || 'Not established from retained evidence.'); const config = make('div'), current = item.current_configuration || {};
      config.append(make('p',`Protocol: ${String(item.protocol || 'Unavailable').toUpperCase()} · Destination Port: ${item.service_port ?? 'Unavailable'}`));
      if(!(current.firewalls || []).length) config.append(make('p','Relevant firewall configuration unavailable for this retained finding.'));
      (current.firewall_devices || []).filter(d => !(current.firewalls || []).some(p => p.id === d.id)).forEach(d => config.append(make('p',`Firewall device: ${d.name || d.id}. No rule configuration retained.`)));
      (current.firewalls || []).forEach(p => { config.append(make('p',`Firewall: ${p.name || p.id} · Configuration: ${p.configuration_available === false ? 'Not Available' : 'Imported'} · Default ${p.default_action == null ? 'Unknown' : p.default_action} (model).`)); if(!p.rules?.length) config.append(make('p','No firewall rules configured.')); else { const rules = make('ul'); p.rules.forEach(r => rules.append(make('li',ruleText(r)))); config.append(rules); } });
      config.append(make('p',current.note || 'Runtime enforcement is not established.')); section(card,'Current Configuration',config); section(card,'Recommended Remediation',item.recommended_change || 'Unavailable');
      const proposed = make('ul'); (item.proposed_rules || []).forEach(r => proposed.append(make('li',ruleText(r)))); section(card,'Proposed Change',proposed.children.length ? proposed : 'No explicit rule changes represented by the engine.'); section(card,'Expected Security Benefit',item.expected_security_benefit || 'Unavailable');
      const steps = make('ol'); (item.retest_procedure || []).forEach(step => steps.append(make('li',step))); section(card,'Retest Procedure',steps); card.append(make('p','PROPOSED — NOT APPLIED','remediation-status'));
      const details = make('details'); details.append(make('summary','Technical Details'),make('pre',JSON.stringify(item,null,2),'raw-data')); card.append(details); list.append(card);
    });
  };
  ensureOption();
})();
