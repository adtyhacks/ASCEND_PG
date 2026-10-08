const byId = id => document.getElementById(id);
const text = value => value === null || value === undefined || value === '' ? 'NONE' : String(value);
const unavailable = value => value === null || value === undefined || value === '' ? 'N/A' : (typeof value === 'object' ? JSON.stringify(value) : String(value));
const escapeHtml = value => unavailable(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
function setElementVisibility(el, visible) {
  if (!el) return;
  el.hidden = !visible;
  if (el.setAttribute && el.removeAttribute) {
    if (!visible) el.setAttribute('hidden', '');
    else el.removeAttribute('hidden');
  }
}
let latestSystem = null, latestActive = null, refreshTimer = null;
let runtimeRefreshSequence = 0, runtimeFresh = false, runtimeRefreshPending = false, runtimeControlPending = false;
let runtimeActionMessage = '', pendingRuntimePath = null;
let topologyControlPending = false;
let selectedTopologyDefinition = null;
let validatedCustomDefinition = null;
let topologySetupReady = false;
const WATCHER_READINESS_REFRESH_LIMIT = 30;
let watcherReadiness = null;
let latestBattle = null, latestCampaignStatus = null, battleVisualSignature = null, battleRefreshSequence = 0, pageRefreshPending = false;
let routeRefreshSequence = 0;
let overviewRefreshSequence = 0, overviewRefreshTicks = 0, overviewVisualSignature = null;
let gridRefreshSequence = 0;

async function readApiResponse(response) {
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error?.message || `Request failed (${response.status})`);
    error.status = response.status; error.code = data.error?.code;
    throw error;
  }
  return data;
}

async function api(path) {
  const response = await fetch(path, {cache: 'no-store'});
  return readApiResponse(response);
}
async function postApi(path, payload = {}) {
  const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
  return readApiResponse(response);
}
function displayName(identity, key, fallback = 'NONE') { return identity?.[key]?.display_name || fallback; }
function activeRunLabel(active, identity) { return active && active.state === 'ACTIVE' ? displayName(identity, 'assessment', 'Assessment in progress') : 'NONE'; }
function setDetails(target, rows) { target.innerHTML = rows.map(([label, value]) => `<div><span>${label}</span><strong>${text(value)}</strong></div>`).join(''); }

function drawPyvisTopology(target, html) {
  if (!html) { target.innerHTML = '<div class="empty-state">No canonical topology is available.</div>'; return; }
  const frame = document.createElement('iframe');
  frame.title = 'Interactive canonical ASCEND topology';
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.srcdoc = html;
  target.replaceChildren(frame);
}

function topologyEditingLocked() {
  const core = latestSystem?.core;
  return core?.state === 'RUNTIME' || core?.session_id != null;
}
function updateControlStates() {
  const usable = runtimeFresh && !runtimeControlPending;
  const core = latestSystem?.core, watcher = latestSystem?.watcher;
  const running = usable && core?.state === 'RUNTIME';
  const start = byId('core-start'), starting = pendingRuntimePath === '/api/runtime/start';
  start.disabled = !(usable && topologySetupReady && !runtimeRefreshPending && !topologyControlPending && core?.state === 'STOPPED' && core?.daemon === 'AVAILABLE');
  start.textContent = starting ? 'Starting CORE…' : 'Start CORE';
  start.setAttribute('aria-busy', String(starting));
  byId('core-stop').disabled = !running;
  byId('core-gui').disabled = !(running && !runtimeControlPending);
  const checkingWatcher = watcherReadiness && (watcherReadiness.remaining > 0 || runtimeRefreshPending);
  byId('watcher-start').disabled = !(running && !checkingWatcher && !['IDLE', 'BUSY'].includes(watcher?.state));
  const sameRun = latestBattle?.active_run?.run?.run_id === latestActive?.run?.run_id;
  const coreReady = running && watcher?.state === 'IDLE' && latestBattle?.active_run?.state === 'ACTIVE' && sameRun;
  const campaignReady = coreReady && ['READY', 'COMPLETED'].includes(latestCampaignStatus?.state);
  byId('campaign-start').disabled = !coreReady;
  byId('campaign-next').disabled = !campaignReady;
  byId('campaign-run').disabled = !campaignReady;
  byId('campaign-isolate').disabled = !coreReady;
  byId('campaign-restore').disabled = !coreReady;
  byId('defense-target').disabled = !coreReady;
  byId('topology-selector').disabled = !runtimeFresh || topologyEditingLocked() || runtimeControlPending || topologyControlPending;
  for (const id of ['custom-topology-json', 'custom-topology-save', 'custom-topology-copy']) byId(id).disabled = byId('topology-selector').disabled;
  for (const id of ['custom-builder-name','custom-builder-add-node','custom-builder-add-edge','custom-builder-validate']) if (byId(id)) byId(id).disabled = byId('topology-selector').disabled;
  setElementVisibility(byId('runtime-next-bar'), running && watcher?.state === 'IDLE');
}
function renderRuntimeState(system) {
  const active = system.active_run;
  const identity = system.display_identity || {};
  const core = system.core.state, watcher = system.watcher.state;
  byId('runtime-daemon').textContent = system.core.daemon === 'AVAILABLE' ? 'Available' : 'Not reachable';
  byId('runtime-session').textContent = core === 'RUNTIME' ? 'Active managed session' : 'No active session';
  byId('runtime-generation').textContent = core === 'RUNTIME' ? displayName(identity, 'runtime_generation', 'Active') : 'Not started';
  byId('runtime-watcher').textContent = watcher === 'IDLE' ? 'Ready' : watcher === 'BUSY' ? 'Active' : 'Not started';
  const rows = active && active.state === 'ACTIVE' ? [['State', active.state], ['Assessment', displayName(identity, 'assessment')], ['CORE session', displayName(identity, 'core_session')], ['Runtime', displayName(identity, 'runtime_generation')], ['Lifecycle', active.run.lifecycle_status], ['Started', active.run.started_at]] : [['Current assessment', active ? active.state : 'NONE'], ['Details', active?.integrity_error || 'No active assessment']];
  setDetails(byId('runtime-recovery'), rows);
  byId('runtime-action-status').textContent = runtimeActionMessage || (system.core.daemon !== 'AVAILABLE' ? 'The CORE daemon is not reachable. Start it manually, then refresh this page.' : core === 'RUNTIME' ? (watcher === 'IDLE' ? 'Security monitoring is ready.' : watcher === 'BUSY' ? 'Security monitoring is active.' : 'The managed CORE session is ready for security monitoring.') : !topologySetupReady ? 'Complete Network Setup before starting a CORE session.' : 'Start CORE creates the managed session for the selected topology.');
  updateControlStates();
}
function reconcileWatcherReadiness(system) {
  if (!watcherReadiness) return;
  if (system.core.state !== 'RUNTIME' || String(system.core.session_id) !== watcherReadiness.sessionId || !watcherReadiness.generation || system.generation !== watcherReadiness.generation) {
    watcherReadiness = null;
    runtimeActionMessage = 'Monitoring startup could not be verified for the current CORE Session and Runtime Generation. Review Technical details.';
  } else if (['IDLE', 'BUSY'].includes(system.watcher.state)) {
    watcherReadiness = null;
    runtimeActionMessage = '';
  } else if (!['UNVERIFIED', 'STARTING', 'UNKNOWN'].includes(system.watcher.state)) {
    watcherReadiness.remaining = 0;
    runtimeActionMessage = `Monitoring status ${system.watcher.state}; startup readiness is not verified.`;
  } else {
    runtimeActionMessage = watcherReadiness.remaining > 0 ? 'Monitoring startup accepted; waiting for readiness confirmation…' : 'Monitoring readiness could not be verified. Review Technical details.';
  }
}
async function refreshRuntimeState() {
  const sequence = ++runtimeRefreshSequence;
  runtimeRefreshPending = true;
  if (watcherReadiness?.remaining > 0) watcherReadiness.remaining -= 1;
  updateControlStates();
  try {
    const data = await api('/api/runtime-diagnostics');
    if (sequence !== runtimeRefreshSequence) return null;
    if (!data?.core?.state || !data?.watcher?.state) throw new Error('Incomplete runtime diagnostics');
    latestSystem = data; latestActive = data.active_run; runtimeFresh = true; runtimeRefreshPending = false;
    reconcileWatcherReadiness(data);
    renderRuntimeState(data);
    if (byId('overview-status-error')) byId('overview-status-error').textContent = data.core.error || '';
    const notice = byId('runtime-refresh-status');
    notice.textContent = data.core.daemon === 'AVAILABLE' ? '' : 'CORE daemon is not reachable. Start it manually; ASCEND-PG will not start the daemon.';
    notice.dataset.state = data.core.daemon === 'AVAILABLE' ? 'current' : 'stale';
    return data;
  } catch (error) {
    if (sequence !== runtimeRefreshSequence) return null;
    runtimeFresh = false; runtimeRefreshPending = false;
    if (watcherReadiness) {
      watcherReadiness.remaining = 0;
      runtimeActionMessage = 'Monitoring startup accepted; readiness is unavailable because assessment status could not be refreshed.';
      byId('runtime-action-status').textContent = runtimeActionMessage;
    }
    const notice = byId('runtime-refresh-status');
    notice.textContent = latestSystem ? 'Status update unavailable — showing last known values.' : 'Assessment status unavailable.';
    if (byId('overview-status-error')) byId('overview-status-error').textContent = error.message;
    notice.dataset.state = 'stale';
    updateControlStates();
    return null;
  }
}
async function loadStatus() { return refreshRuntimeState(); }
function assessmentLabel(active) {
  if (active?.state === 'REJECTED') return 'Assessment unavailable';
  if (active?.state !== 'ACTIVE') return 'No assessment running';
  const run = active.run || {};
  return run.ended_at || ['COMPLETED', 'COMPLETE'].includes(run.status) ? 'Assessment completed' : 'Assessment in progress';
}
function renderRecentSecurityActivity(events) {
  const names = {attack_started:'Attack attempt', attack_finished:'Attack result', detection:'Detection', defense_action:'Defence response', containment:'Containment'};
  const rows = events.filter(event => names[event.event_type]).slice(-5).reverse();
  byId('overview-activity').innerHTML = rows.length ? rows.map(event => {
    const payload = event.evidence || {}, technique = event.mitre_technique || '';
    const step = String(event.technique_name || payload.technique_name || payload.step_name || '').replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase()).replace(/\bIo\b/g, 'I/O').replace(/\bFdi\b/g, 'FDI');
    const method = event.detection_method || payload.detection_method;
    const result = String(payload.return_status || event.result || '').toUpperCase();
    const results = {FAILED:'Failed', TIMEOUT:'Timed out', SUCCESS:'Completed', DETECTED:'Detected', UNDETECTED:'Not detected', STARTED:'Started', COMPROMISED:'Reported compromise', APPLIED:'Applied', CONTAINED:'Contained', EXECUTION_ERROR:'Execution error'};
    const outcome = event.event_type === 'detection' ? (method === 'ml' ? 'Detected by ML' : method === 'suricata' ? 'Detected by network monitoring' : method === 'both' || method === 'hybrid' ? 'Detected by combined monitoring' : 'Detection recorded') : results[result] || 'Security activity recorded';
    const time = new Date(event.timestamp);
    const timestamp = Number.isNaN(time.getTime()) ? 'Time unavailable' : time.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    const target = /^plc\d+$/i.test(event.target_node || '') ? event.target_node.toUpperCase() : event.target_node || 'Target not specified';
    return `<article class="security-activity-item"><div><strong>${escapeHtml(event.sample ? 'SAMPLE scenario' : names[event.event_type])}</strong><time title="${escapeHtml(event.timestamp || 'Sample scenario')}">${escapeHtml(event.sample ? 'SAMPLE' : timestamp)}</time></div><p>${escapeHtml(target)}${technique ? ' · ' + escapeHtml(technique) : ''}${step ? ' — ' + escapeHtml(step) : ''}</p><span>${escapeHtml(event.sample ? event.technical_details['Detection Result'] : outcome)}</span>${technicalDetails(event)}</article>`;
  }).join('') : '<div class="empty-state">No security activity yet.<small>Security events, attack attempts and detections will appear here when the assessment begins.</small></div>';
}
const severityPalette = {Critical:'#7b1e3a',High:'#c0392b',Medium:'#d88a16',Low:'#2b6f8a',Informational:'#6f6a62'};
function friendlyDetectionMethod(value) {
  const names = {ml:'ML',suricata:'Network monitoring',both:'Combined monitoring',hybrid:'Combined monitoring',none:'None recorded',unknown:'Unknown'};
  return names[String(value || '').toLowerCase()] || String(value || 'Unknown').replaceAll('_', ' ');
}
function friendlyResult(value) {
  const result = String(value || '').toUpperCase();
  return {SUCCESS:'Completed',FAILED:'Failed',TIMEOUT:'Timed out',DETECTED:'Detected',UNDETECTED:'Not detected',EXECUTION_ERROR:'Execution error',COMPROMISED:'Reported compromise'}[result] || (value || 'Not available');
}
let cachedAttackCatalogue = null;
function renderSeverityDistribution(distribution = {}) {
  const order = ['Critical','High','Medium','Low','Informational'];
  const values = order.map(label => ({label, count: Number.isFinite(Number(distribution[label])) ? Math.max(0, Number(distribution[label])) : 0}));
  const total = values.reduce((sum, item) => sum + item.count, 0), chart = byId('overview-severity-chart');
  byId('overview-severity-total').textContent = total;
  if (!total) {
    chart.classList.add('empty'); chart.removeAttribute('style'); chart.setAttribute('aria-label', 'No attack severity data available');
    byId('overview-severity-legend').innerHTML = '<p>No attack techniques available.</p>'; return;
  }
  let cursor = 0;
  const segments = values.filter(item => item.count > 0).map(item => {
    const start = cursor, end = cursor + item.count / total * 360; cursor = end;
    return `${severityPalette[item.label]} ${start.toFixed(2)}deg ${end.toFixed(2)}deg`;
  });
  chart.classList.remove('empty'); chart.setAttribute('style', `background:conic-gradient(${segments.join(',')})`);
  chart.setAttribute('aria-label', `Severity distribution for ${total} attacks: ${values.filter(item => item.count > 0).map(item => `${item.label} ${item.count}`).join(', ')}`);
  byId('overview-severity-legend').innerHTML = values.filter(item => item.count > 0).map(item => `<div><i class="severity-swatch" style="background:${severityPalette[item.label]}" aria-hidden="true"></i><span>${item.label}</span><strong>${item.count}</strong></div>`).join('');
}
function renderAttackCatalogue(attacks = []) {
  const target = byId('overview-attack-catalogue');
  if (!attacks.length) { target.innerHTML = '<div class="empty-state">No attack techniques available.<small>Attack catalogue could not be loaded.</small></div>'; return; }
  target.innerHTML = attacks.map(attack => {
    const severity = ['Critical','High','Medium','Low','Informational'].includes(attack.severity) ? attack.severity : 'Informational';
    const sids = Array.isArray(attack.detect_sids) && attack.detect_sids.length ? attack.detect_sids.join(', ') : 'No signature rule';
    const defaultStep = attack.default_step || (attack.stage !== undefined ? `Stage ${attack.stage}` : '');
    return `<details class="attack-card"><summary><span class="attack-severity" style="color:${severityPalette[severity] || '#6f6a62'}">${escapeHtml(severity.toUpperCase())}</span><span class="attack-card-title"><strong>${escapeHtml(attack.title || attack.name || 'Attack technique')}</strong><span>${escapeHtml(attack.technique_id || '')} · ${escapeHtml(attack.tactic || '')}</span></span><span class="attack-result">${escapeHtml(defaultStep)}</span></summary><div class="attack-card-body"><p>${escapeHtml(attack.description || 'Catalogued attack capability.')}</p><div class="attack-facts"><div><span>MITRE ID</span><strong>${escapeHtml(attack.technique_id || 'Catalogued')}</strong></div><div><span>Severity</span><strong>${escapeHtml(severity)}</strong></div><div><span>Tactical Stage</span><strong>${attack.stage !== undefined ? `Stage ${escapeHtml(attack.stage)}` : 'Catalogued'}</strong></div><div><span>MITRE Tactic</span><strong>${escapeHtml(attack.tactic || 'Catalogued')}</strong></div><div><span>Default Step</span><strong>${escapeHtml(attack.default_step || 'Catalogued')}</strong></div><div><span>Script</span><strong>${escapeHtml(attack.script || 'Catalogued')}</strong></div><div><span>Suricata SIDs</span><strong>${escapeHtml(sids)}</strong></div><div><span>Severity Basis</span><strong>${escapeHtml(attack.severity_reason || attack.severity_policy || 'attack-capability-v1')}</strong></div></div></div></details>`;
  }).join('');
}
function renderAssessmentOverview(counts, overview, assessmentName) {
  const available = counts && overview;
  setElementVisibility(byId('overview-results-section'), Boolean(available));
  if (!available) return;
  byId('overview-results-assessment').textContent = assessmentName;
  for (const [id, key] of [['overview-total-findings','total_findings'],['overview-total-detected','detected'],['overview-total-failed','failed'],['overview-total-timeout','timeout']]) byId(id).textContent = counts[key];
  const dvs = overview?.dvs || {};
  byId('overview-finding-dvs').textContent = dvs.finding_available ? `Available for ${dvs.finding_assessed} finding${dvs.finding_assessed === 1 ? '' : 's'}` : 'Pending evidence';
  byId('overview-campaign-dvs').textContent = dvs.campaign_available && Number.isFinite(dvs.campaign_score) ? `${dvs.campaign_score.toFixed(1)} / 100${dvs.campaign_rating ? ` (${dvs.campaign_rating})` : ''}` : 'Pending completion';
  const defense = overview?.defense || {};
  byId('overview-defense-detected').textContent = `${defense.detected} of ${defense.total}`;
  byId('overview-defense-rate').textContent = Number.isFinite(defense.detection_rate) ? `${(defense.detection_rate * 100).toFixed(1)}%` : 'Pending evidence';
  const methods = Object.entries(defense.methods || {}).filter(([method, count]) => Number(count) > 0 && !['none','unknown'].includes(String(method).toLowerCase()));
  byId('overview-defense-methods').textContent = methods.length ? methods.map(([method,count]) => `${friendlyDetectionMethod(method)} (${count})`).join(', ') : 'No detections recorded';
  setElementVisibility(byId('overview-defense-metrics-box'), true);
}
async function loadOverview() {
  const sequence = ++overviewRefreshSequence, runtimeSequence = runtimeRefreshSequence;
  const cataloguePromise = cachedAttackCatalogue ? Promise.resolve(cachedAttackCatalogue) : api('/api/attack-catalogue').catch(() => null);
  const [data, catalogue] = await Promise.all([api('/api/sample-environment'), cataloguePromise]);
  if (!cachedAttackCatalogue && catalogue && Array.isArray(catalogue.attacks)) {
    cachedAttackCatalogue = catalogue;
  }
  const activeCatalogue = cachedAttackCatalogue || catalogue;
  if (sequence !== overviewRefreshSequence || runtimeSequence !== runtimeRefreshSequence) return;
  const signature = 'sample-case14';
  if (signature !== overviewVisualSignature) {
    drawPyvisTopology(byId('overview-topology'), data.pyvis_html);
    overviewVisualSignature = signature;
  }
  const caseName = data.topology.case_name || 'Selected network';
  byId('overview-topology-name').textContent = caseName === 'case14' ? 'IEEE-14' : caseName === 'case30' ? 'IEEE-30' : caseName.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
  byId('overview-topology-summary').textContent = `SAMPLE · ${data.topology.nodes.length} devices · Static demonstration, no live testbed required`;
  setDetails(byId('sample-topology-summary'), Object.entries(data.topology_summary));
  byId('sample-rules-body').innerHTML = data.rules.map(rule => `<tr><td>${escapeHtml(rule.sid)}</td><td>${escapeHtml(rule.name)}</td><td>${escapeHtml(rule.technique)}</td></tr>`).join('');
  if (activeCatalogue) {
    renderSeverityDistribution(activeCatalogue.severity_distribution || {});
    renderAttackCatalogue(activeCatalogue.attacks || []);
  }
  renderAssessmentOverview(null, null, 'Sample Environment');
  renderRecentSecurityActivity(data.security_events || []);
}
async function loadNetwork() {
  const [config, topology] = await Promise.all([api('/api/network-configuration'), api('/api/topology')]);
  renderNetworkConfiguration(config, topology);
  topologySetupReady = true;
  updateControlStates();
}
function gridValue(value, unit = '', digits = 2) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(digits)}${unit ? ' ' + unit : ''}` : 'Not available';
}
function renderBusVoltageProfile(buses = []) {
  const table = byId('grid-bus-voltage-table'), chart = byId('grid-bus-voltage-chart');
  if (!table || !chart) return;
  if (!buses.length) {
    table.innerHTML = '<tr><td colspan="3" class="table-empty">No bus voltage profile data available.</td></tr>';
    chart.innerHTML = '<div class="empty-state">No voltage data</div>';
    return;
  }
  table.innerHTML = buses.map(b => `<tr><td>Bus ${escapeHtml(b.bus_id)}</td><td>${Number(b.voltage_pu).toFixed(4)}</td><td>${Number(b.voltage_angle_deg).toFixed(2)}°</td></tr>`).join('');
  const width = 460, height = 180, padL = 35, padR = 15, padT = 20, padB = 25;
  const chartW = width - padL - padR, chartH = height - padT - padB;
  const voltages = buses.map(b => b.voltage_pu);
  const minV = Math.min(0.9, ...voltages) - 0.02, maxV = Math.max(1.1, ...voltages) + 0.02;
  const barW = Math.max(4, Math.floor(chartW / buses.length) - 4);
  const svgBars = buses.map((b, i) => {
    const x = padL + i * (chartW / buses.length) + 2;
    const norm = Math.max(0, Math.min(1, (b.voltage_pu - minV) / (maxV - minV)));
    const barH = Math.max(2, norm * chartH);
    const y = padT + (chartH - barH);
    const color = b.voltage_pu < 0.95 || b.voltage_pu > 1.05 ? '#d97706' : '#15803d';
    return `<rect class="chart-bar" x="${x}" y="${y}" width="${barW}" height="${barH}" fill="${color}" rx="2"><title>Bus ${b.bus_id}: ${b.voltage_pu.toFixed(4)} pu (${b.voltage_angle_deg.toFixed(1)}°)</title></rect><text class="chart-axis-label" x="${x + barW / 2}" y="${height - 8}">${b.bus_id}</text>`;
  }).join('');
  const midNorm = (1.0 - minV) / (maxV - minV);
  const midY = padT + chartH * (1 - midNorm);
  chart.innerHTML = `<svg class="chart-svg" viewBox="0 0 ${width} ${height}"><line class="chart-grid-line" x1="${padL}" y1="${midY}" x2="${width - padR}" y2="${midY}" /><text class="chart-axis-label" x="${padL - 6}" y="${midY + 3}">1.0</text>${svgBars}</svg>`;
}
function renderLineLoadings(lines = []) {
  const table = byId('grid-line-loading-table'), chart = byId('grid-line-loading-chart');
  if (!table || !chart) return;
  if (!lines.length) {
    table.innerHTML = '<tr><td colspan="2" class="table-empty">The selected grid has no line-loading results.</td></tr>';
    chart.innerHTML = '<div class="empty-state">No line loading data</div>';
    return;
  }
  table.innerHTML = lines.map(l => `<tr><td>Line ${escapeHtml(l.line_id)}</td><td>${Number(l.loading_percent).toFixed(2)}%</td></tr>`).join('');
  const width = 460, height = 180, padL = 35, padR = 15, padT = 20, padB = 25;
  const chartW = width - padL - padR, chartH = height - padT - padB;
  const loadings = lines.map(l => l.loading_percent);
  const maxL = Math.max(10, Math.ceil(Math.max(...loadings) / 10) * 10);
  const barW = Math.max(4, Math.floor(chartW / lines.length) - 4);
  const svgBars = lines.map((l, i) => {
    const x = padL + i * (chartW / lines.length) + 2;
    const norm = Math.max(0, Math.min(1, l.loading_percent / maxL));
    const barH = Math.max(2, norm * chartH);
    const y = padT + (chartH - barH);
    const color = l.loading_percent > 80 ? '#dc2626' : l.loading_percent > 50 ? '#d97706' : '#2563eb';
    return `<rect class="chart-bar" x="${x}" y="${y}" width="${barW}" height="${barH}" fill="${color}" rx="2"><title>Line ${l.line_id}: ${l.loading_percent.toFixed(2)}%</title></rect><text class="chart-axis-label" x="${x + barW / 2}" y="${height - 8}">${l.line_id}</text>`;
  }).join('');
  chart.innerHTML = `<svg class="chart-svg" viewBox="0 0 ${width} ${height}"><line class="chart-grid-line" x1="${padL}" y1="${padT + chartH}" x2="${width - padR}" y2="${padT + chartH}" /><text class="chart-axis-label" x="${padL - 6}" y="${padT + 4}">${maxL}%</text>${svgBars}</svg>`;
}
function renderBaselineTelemetry(telemetry = []) {
  const table = byId('grid-telemetry-table');
  if (!table) return;
  if (!telemetry.length) {
    table.innerHTML = '<tr><td colspan="5" class="table-empty">No baseline telemetry available.</td></tr>';
    return;
  }
  table.innerHTML = telemetry.map(r => `<tr><td>${escapeHtml(r.timestamp)}</td><td>Bus ${escapeHtml(r.src_bus)}</td><td>Bus ${escapeHtml(r.dst_bus)}</td><td>${escapeHtml(r.packet_size_bytes)} B</td><td>${Number(r.voltage_pu).toFixed(4)} pu</td></tr>`).join('');
}
function resetCustomWorkflow(definition = null) {
  validatedCustomDefinition = null;
  const file = byId('custom-topology-file'); if (file) file.value = '';
  setElementVisibility(byId('custom-topology-preview'), false);
  setElementVisibility(byId('custom-topology-error'), false);
  if (byId('custom-topology-error')) byId('custom-topology-error').textContent = '';
  const raw = definition || {case_name:'custom_grid',nodes:[],edges:[]};
  if (byId('custom-topology-json')) byId('custom-topology-json').value = JSON.stringify(raw, null, 2);
  if (definition) renderTopologyBuilder(raw);
  else {
    if (byId('custom-builder-name')) byId('custom-builder-name').value = 'custom_grid';
    if (byId('custom-builder-nodes')) byId('custom-builder-nodes').innerHTML = '';
    if (byId('custom-builder-edges')) byId('custom-builder-edges').innerHTML = '';
  }
}
function renderTopologyBuilder(definition = {}) {
  const nodes = Array.isArray(definition.nodes) ? definition.nodes : [], edges = Array.isArray(definition.edges) ? definition.edges : [];
  byId('custom-builder-name').value = definition.case_name || 'custom_grid';
  byId('custom-builder-nodes').innerHTML = nodes.map((node, index) => `<div class="builder-row builder-node" data-index="${index}"><span class="builder-index">Bus ${index}</span><label>Name<input data-field="name" value="${escapeHtml(node.name || `Bus ${index + 1}`)}"></label><label>Role<select data-field="type"><option value="slack" ${node.type === 'slack' ? 'selected' : ''}>Slack</option><option value="pv" ${node.type === 'pv' ? 'selected' : ''}>Generator (PV)</option><option value="pq" ${node.type === 'pq' ? 'selected' : ''}>Load (PQ)</option></select></label><label>Nominal kV<input type="number" step="0.1" min="0.1" data-field="vn_kv" value="${node.vn_kv ?? 110}"></label><label>Voltage p.u.<input type="number" step="0.001" min="0.1" data-field="voltage" value="${node.voltage ?? 1}"></label><label>Generation MW<input type="number" step="0.1" min="0" data-field="pg" value="${node.pg ?? 0}"></label><label>Load MW<input type="number" step="0.1" min="0" data-field="pl" value="${node.pl ?? 0}"></label><label>Load Mvar<input type="number" step="0.1" min="0" data-field="ql" value="${node.ql ?? 0}"></label><button type="button" class="builder-remove" data-remove-node="${index}" aria-label="Remove bus ${index}">Remove</button></div>`).join('');
  byId('custom-builder-edges').innerHTML = edges.map((edge, index) => `<div class="builder-row builder-edge" data-index="${index}"><span class="builder-index">Line ${index + 1}</span><label>From bus<input type="number" min="0" step="1" data-field="from" value="${edge.from ?? 0}"></label><label>To bus<input type="number" min="0" step="1" data-field="to" value="${edge.to ?? Math.min(1, Math.max(0,nodes.length-1))}"></label><label>Length km<input type="number" min="0.001" step="0.1" data-field="length_km" value="${edge.length_km ?? 1}"></label><label>Resistance Ω/km<input type="number" min="0.0001" step="0.01" data-field="r_ohm_per_km" value="${edge.r_ohm_per_km ?? 0.1}"></label><label>Reactance Ω/km<input type="number" min="0.0001" step="0.01" data-field="x_ohm_per_km" value="${edge.x_ohm_per_km ?? 0.1}"></label><label>Capacitance nF/km<input type="number" min="0" step="0.1" data-field="c_nf_per_km" value="${edge.c_nf_per_km ?? 0}"></label><label>Max current kA<input type="number" min="0.001" step="0.01" data-field="max_i_ka" value="${edge.max_i_ka ?? 0.4}"></label><button type="button" class="builder-remove" data-remove-edge="${index}" aria-label="Remove line ${index + 1}">Remove</button></div>`).join('');
}
function topologyBuilderDefinition() {
  const number = value => Number(value);
  const nodes = [...byId('custom-builder-nodes').querySelectorAll('.builder-node')].map((row, bus_id) => {
    const field = name => row.querySelector(`[data-field="${name}"]`).value;
    return {bus_id, name:field('name').trim(), type:field('type'), vn_kv:number(field('vn_kv')), voltage:number(field('voltage')), pg:number(field('pg')), qg:0, pl:number(field('pl')), ql:number(field('ql'))};
  });
  const edges = [...byId('custom-builder-edges').querySelectorAll('.builder-edge')].map(row => {
    const field = name => row.querySelector(`[data-field="${name}"]`).value;
    return {from:number(field('from')),to:number(field('to')),length_km:number(field('length_km')),r_ohm_per_km:number(field('r_ohm_per_km')),x_ohm_per_km:number(field('x_ohm_per_km')),c_nf_per_km:number(field('c_nf_per_km')),max_i_ka:number(field('max_i_ka'))};
  });
  return {case_name:byId('custom-builder-name').value.trim(),nodes,edges};
}
async function validateAndPreviewCustom(definition) {
  const validated = await postApi('/api/topology/validate', {definition});
  validatedCustomDefinition = validated.definition || definition;
  byId('custom-topology-json').value = JSON.stringify(validatedCustomDefinition, null, 2);
  byId('custom-preview-case').textContent = validated.case_name;
  byId('custom-preview-buses').textContent = validated.num_buses;
  byId('custom-preview-edges').textContent = validated.num_edges;
  if (byId('custom-preview-communication')) byId('custom-preview-communication').textContent = `${validated.communication_nodes} hosts/devices · ${validated.communication_links} CORE links`;
  byId('custom-preview-badge').textContent = 'Valid';
  setElementVisibility(byId('custom-topology-preview'), true);
  setElementVisibility(byId('custom-topology-error'), false);
  byId('topology-selection-status').textContent = `Validated ${validated.case_name}: ${validated.num_buses} buses and ${validated.num_edges} electrical lines. Apply it before starting CORE.`;
  return validated;
}
async function loadGridStatus() {
  const sequence = ++gridRefreshSequence;
  const data = await api('/api/grid-status');
  if (sequence !== gridRefreshSequence) return;
  const grid = data.grid, network = data.network;
  for (const [id,value,unit,digits] of [
    ['grid-count',grid.component_count,'',0],['grid-healthy',grid.healthy,'',0],['grid-warning',grid.warning,'',0],['grid-critical',grid.critical,'',0],
    ['grid-voltage',grid.model_average_voltage_pu,'pu',3],['grid-generation',grid.model_generation_mw,'MW',2],['grid-load',grid.model_load_mw,'MW',2],
    ['grid-live-voltage',grid.measured_voltage_pu,'pu',3],['grid-live-power',grid.measured_power_mw,'MW',2]
  ]) byId(id).textContent = gridValue(value,unit,digits);
  setElementVisibility(byId('grid-card-count'), grid.component_count != null);
  setElementVisibility(byId('grid-card-healthy'), grid.healthy != null);
  setElementVisibility(byId('grid-card-warning'), grid.warning != null);
  setElementVisibility(byId('grid-card-critical'), grid.critical != null);
  setElementVisibility(byId('grid-card-voltage'), grid.model_average_voltage_pu != null);
  setElementVisibility(byId('grid-card-generation'), grid.model_generation_mw != null);
  setElementVisibility(byId('grid-card-load'), grid.model_load_mw != null);
  setElementVisibility(byId('grid-card-live-voltage'), grid.measured_voltage_pu != null);
  setElementVisibility(byId('grid-card-live-power'), grid.measured_power_mw != null);

  const baseline = data.baseline_grid;
  if (baseline?.summary) {
    setElementVisibility(byId('grid-baseline-panel'), true);
    const sum = baseline.summary || {};
    if (byId('grid-baseline-buses')) byId('grid-baseline-buses').textContent = text(sum.electrical_buses);
    if (byId('grid-baseline-voltage-range')) byId('grid-baseline-voltage-range').textContent = text(sum.voltage_range);
    if (byId('grid-baseline-lines')) byId('grid-baseline-lines').textContent = text(sum.lines);
    if (byId('grid-baseline-max-loading')) byId('grid-baseline-max-loading').textContent = text(sum.max_line_loading_pct || (sum.max_line_loading != null ? `${sum.max_line_loading}%` : '—'));
    renderBusVoltageProfile(baseline.bus_voltages || []);
    renderLineLoadings(baseline.line_loadings || []);
    renderBaselineTelemetry(baseline.telemetry || []);
  } else {
    setElementVisibility(byId('grid-baseline-panel'), false);
  }
  setElementVisibility(byId('grid-next-bar'), Boolean(baseline?.summary && baseline.bus_voltages?.length && (baseline.line_loadings?.length || !grid.electrical_connections)));

  byId('grid-case').textContent = data.case_name === 'case14' ? 'IEEE-14' : data.case_name === 'case30' ? 'IEEE-30' : data.case_name.replaceAll('_',' ').replace(/\b\w/g, letter => letter.toUpperCase());
  byId('grid-components').innerHTML = data.components.map(row => `<tr><td>${escapeHtml(row.name)}</td><td>${escapeHtml(row.type)}</td><td>${row.model_voltage_pu == null ? '—' : gridValue(row.model_voltage_pu,'pu',3)}</td><td>${row.model_generation_mw == null && row.model_load_mw == null ? '—' : `${row.model_generation_mw == null ? '—' : gridValue(row.model_generation_mw,'MW')} / ${row.model_load_mw == null ? '—' : gridValue(row.model_load_mw,'MW')}`}</td></tr>`).join('') || '<tr><td colspan="4" class="table-empty">No configured components.</td></tr>';
  setElementVisibility(byId('grid-live-network-panel'), Boolean(data.runtime_available));
  setElementVisibility(byId('grid-live-observations'), Boolean(data.runtime_available));
  if (data.runtime_available) setDetails(byId('grid-network'), [['Network devices',gridValue(network.device_count,'',0)],['Communication connections',gridValue(network.connections,'',0)],
    ['Electrical connections',gridValue(grid.electrical_connections,'',0)],['Responding components',gridValue(network.responding_components,'',0)],
    ['Failed component reads',gridValue(network.offline_components,'',0)],['Network monitoring',network.status],
    ['Observed flow traffic rate',gridValue(network.observed_traffic.bits_per_second,'bit/s')],
    ['Recent detection notices',gridValue(network.recent_detection_notices,'',0)]]);
  else byId('grid-network').innerHTML = '';
  byId('grid-sources').innerHTML = Object.values(data.provenance).map(value => `<p>${escapeHtml(value)}</p>`).join('');
  byId('grid-reactive-generation').textContent = gridValue(grid.model_reactive_generation_mvar,'Mvar');
  byId('grid-reactive-load').textContent = gridValue(grid.model_reactive_load_mvar,'Mvar');
  setElementVisibility(byId('grid-reactive-generation-card'), grid.model_reactive_generation_mvar != null);
  setElementVisibility(byId('grid-reactive-load-card'), grid.model_reactive_load_mvar != null);
  setElementVisibility(byId('grid-reactive-power-panel'), grid.model_reactive_generation_mvar != null || grid.model_reactive_load_mvar != null);
  byId('grid-technical-components').innerHTML = data.runtime_available ? data.components.map(row => `<tr><td>${escapeHtml(row.name)}</td><td>${escapeHtml(row.ip)}</td><td>${escapeHtml(row.last_observed || 'Awaiting observation')}</td></tr>`).join('') : '';
}
function renderNetworkConfiguration(config, topology) {
  selectedTopologyDefinition = config.definition || null;
  byId('network-nodes').textContent = config.node_count; byId('network-edges').textContent = config.edge_count; byId('network-case').textContent = text(config.case_name || config.topology_version); byId('network-types').textContent = Object.keys(config.node_types).length;
  setDetails(byId('network-metadata'), [['Topology version', config.topology_version], ['Case', config.case_name], ['Node types', Object.entries(config.node_types).map(([k, v]) => `${k}: ${v}`).join(', ')]]);
  const selector = byId('topology-selector'), current = config.selected_case || config.case_name;
  const options = (config.available_topologies || []).map(item => `<option value="${escapeHtml(item.case_name)}">${escapeHtml(item.name)}</option>`);
  if (!config.available_topologies?.some(item => item.case_name === 'custom')) {
    options.push('<option value="custom">Custom Topology (Upload JSON)</option>');
  }
  selector.innerHTML = options.join('');
  selector.value = current;
  selector.disabled = !runtimeFresh || topologyEditingLocked() || runtimeControlPending || topologyControlPending;
  byId('topology-selection-status').textContent = `Selected backend topology: ${current}. Changes are available before CORE startup.`;
  drawPyvisTopology(byId('network-topology'), topology.pyvis_html);

  const isCustom = current === 'custom' || String(current).startsWith('custom_');
  setElementVisibility(byId('custom-topology-panel'), isCustom);
  if (!isCustom) {
    resetCustomWorkflow();
  } else if (config.definition) {
    const def = config.definition;
    if (byId('custom-preview-case')) byId('custom-preview-case').textContent = def.case_name;
    if (byId('custom-preview-buses')) byId('custom-preview-buses').textContent = (def.nodes || []).length;
    if (byId('custom-preview-edges')) byId('custom-preview-edges').textContent = (def.edges || []).length;
    if (byId('custom-preview-communication')) byId('custom-preview-communication').textContent = `${(def.nodes || []).length + 4} hosts/devices · ${(def.nodes || []).length + 3} CORE links`;
    if (byId('custom-preview-badge')) byId('custom-preview-badge').textContent = 'Valid';
    setElementVisibility(byId('custom-topology-preview'), true);
    if (byId('custom-topology-json')) byId('custom-topology-json').value = JSON.stringify(def, null, 2);
    renderTopologyBuilder(def);
  }
  setElementVisibility(byId('network-next-bar'), true);
}
async function loadRuntime() { return refreshRuntimeState(); }
function evidenceValue(value) {
  if (value === 'N/A') return '<span title="Not applicable">—</span>';
  if (value === null || value === undefined) return '<span title="Unavailable">—</span>';
  if (value === '') return '<span title="Empty string">&quot;&quot;</span>';
  return escapeHtml(typeof value === 'object' ? JSON.stringify(value) : String(value));
}
function evidenceDetails(value, label = null, expanded = false) {
  if (value === null || value === undefined || value === 'N/A' || value === '') return evidenceValue(value);
  const compact = typeof value === 'object' ? JSON.stringify(value) : String(value);
  const full = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
  const preview = label || (compact.length > 96 ? compact.slice(0, 96) + '…' : compact);
  return `<details class="evidence-details"${expanded ? ' open' : ''}><summary><span class="payload-preview">${escapeHtml(preview)}</span></summary><pre>${escapeHtml(full)}</pre></details>`;
}
function meaningfulEvidence(value) { return value !== null && value !== undefined && value !== '' && value !== 'N/A'; }
function technicalDetails(row, expanded = false) {
  const detail = row.technical_details;
  if (!detail) return evidenceDetails(row, 'Technical Details', expanded);
  return `<details class="evidence-details"${expanded ? ' open' : ''}><summary>Technical Details</summary><div class="details-list">${Object.entries(detail).map(([key,value]) => `<div><span>${escapeHtml(key)}</span><strong>${escapeHtml(Array.isArray(value) ? value.join(', ') : value ?? 'Unavailable')}</strong></div>`).join('')}</div>${evidenceDetails(row, 'Full event')}</details>`;
}
function attackEventSeverity(event, events) {
  if (!['attack_started', 'attack_finished', 'detection'].includes(event.event_type)) return event.severity;
  const identity = ['scenario_id', 'run_id', 'generation_id', 'correlation_id'];
  const start = event.correlation_id ? events.find(candidate => candidate.event_type === 'attack_started' && identity.every(key => candidate[key] === event[key])) : null;
  return start ? (start.attack_severity ?? start.severity) : (event.attack_severity ?? null);
}
function stableEvidenceToken(value) {
  let hash = 2166136261;
  for (const character of String(value)) hash = Math.imul(hash ^ character.charCodeAt(0), 16777619);
  return (hash >>> 0).toString(36);
}
function evidenceRowIdentity(row) {
  if (meaningfulEvidence(row.event_id)) return `event-${stableEvidenceToken(row.event_id)}`;
  const correlation = networkField(row, 'correlation_id', 'attack_event_id');
  if (meaningfulEvidence(correlation)) {
    return `correlation-${stableEvidenceToken(`${correlation}|${row.event_type || ''}|${row.timestamp || ''}|${row.source_ip || row.source_node || ''}|${row.destination_ip || row.target_node || ''}`)}`;
  }
  return `record-${stableEvidenceToken(`${row.timestamp || ''}|${row.event_type || ''}|${row.source_ip || row.source_node || ''}|${row.destination_ip || row.target_node || ''}|${row.protocol || ''}|${networkField(row, 'source_port', 'src_port') || ''}|${networkField(row, 'destination_port', 'dest_port', 'dst_port') || ''}`)}`;
}
function renderEvidenceTable(target, rows, columns, emptyMessage, headerId, state = null) {
  const container = state?.containerId ? byId(state.containerId) : null;
  const scrollTop = container?.scrollTop ?? 0;
  const pageScrollY = state && Number.isFinite(window.scrollY) ? window.scrollY : null;
  const expanded = new Set(state ? [...target.querySelectorAll('tr[data-evidence-key] details[open]')]
    .map(details => details.closest('tr[data-evidence-key]')?.dataset.evidenceKey).filter(Boolean) : []);
  const visible = columns.filter(column => !column.optional || rows.some(row => meaningfulEvidence(column.value(row))));
  byId(headerId).innerHTML = visible.map(column => `<th scope="col">${escapeHtml(column.label)}</th>`).join('') + '<th scope="col">Details</th>';
  if (!rows.length) {
    target.innerHTML = `<tr><td colspan="${visible.length + 1}" class="table-empty">${escapeHtml(emptyMessage)}</td></tr>`;
  } else {
    target.innerHTML = rows.map(row => {
      const key = evidenceRowIdentity(row);
      return `<tr data-evidence-key="${escapeHtml(key)}">${visible.map(column => `<td>${column.payload ? evidenceDetails(column.value(row)) : evidenceValue(column.value(row))}</td>`).join('')}<td>${technicalDetails(row, expanded.has(key))}</td></tr>`;
    }).join('');
  }
  if (container) container.scrollTop = scrollTop;
  if (pageScrollY !== null && typeof window.scrollTo === 'function') window.scrollTo(window.scrollX || 0, pageScrollY);
}
function networkField(event, ...names) { const name = names.find(key => event[key] !== null && event[key] !== undefined && event[key] !== 'N/A'); return name === undefined ? (event[names[0]] ?? null) : event[name]; }
function readableNetworkTime(value) {
  if (!meaningfulEvidence(value)) return value;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString([], {
    year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit'
  });
}
function isModbusPort(value) { return meaningfulEvidence(value) && String(value) === '502'; }
function networkCommunication(event) {
  const sourcePort = networkField(event, 'source_port', 'src_port');
  const destinationPort = networkField(event, 'destination_port', 'dest_port', 'dst_port');
  const application = String(event.application_protocol || '').toLowerCase();
  if (isModbusPort(sourcePort) || isModbusPort(destinationPort) || application === 'modbus') return 'SCADA / Modbus TCP communication';
  const protocol = meaningfulEvidence(event.protocol) ? String(event.protocol).toUpperCase() : null;
  return protocol ? `${protocol} network communication` : 'Network communication';
}
function networkServicePort(event) {
  const sourcePort = networkField(event, 'source_port', 'src_port');
  const destinationPort = networkField(event, 'destination_port', 'dest_port', 'dst_port');
  if (isModbusPort(sourcePort) || isModbusPort(destinationPort)) return '502 (Modbus TCP)';
  return meaningfulEvidence(destinationPort) ? destinationPort : sourcePort;
}
function relatedAssessmentStep(event) {
  if (!meaningfulEvidence(event.ppo_step)) return 'Assessment network activity';
  const technique = networkField(event, 'technique_id', 'mitre_technique');
  return `Step ${event.ppo_step}${meaningfulEvidence(technique) ? ` · ${technique}` : ''}`;
}
function networkEvidenceMeaning(event) {
  const sourcePort = networkField(event, 'source_port', 'src_port');
  const destinationPort = networkField(event, 'destination_port', 'dest_port', 'dst_port');
  if (isModbusPort(destinationPort)) return 'Request traffic sent to a monitored Modbus/TCP service.';
  if (isModbusPort(sourcePort)) return 'Response traffic associated with the monitored Modbus/TCP communication.';
  if (meaningfulEvidence(event.ppo_step)) return 'Network activity observed during this assessment step.';
  return 'Assessment network activity; no specific attack attribution is established.';
}
async function loadBattle() {
  const sequence = ++battleRefreshSequence, runtimeSequence = runtimeRefreshSequence;
  const visualQuery = battleVisualSignature ? `&visual_signature=${encodeURIComponent(battleVisualSignature)}` : '';
  const data = await api(`/api/live-battle?limit=100${visualQuery}`);
  const campaignStatus = await api('/api/campaign/status');
  if (sequence !== battleRefreshSequence || runtimeSequence !== runtimeRefreshSequence) return;
  latestBattle = data; latestCampaignStatus = campaignStatus;
  byId('battle-run').textContent = activeRunLabel(data.active_run, data.display_identity); byId('battle-network-count').textContent = data.network_event_count; byId('battle-security-count').textContent = data.security_event_count; byId('battle-limit').textContent = data.limit;
  const campaign = data.campaign || {}, campaignRows = data.campaign_display && Object.keys(data.campaign_display).length ? Object.entries(data.campaign_display) : [['Campaign details', 'NONE']];
  setDetails(byId('battle-campaign-meta'), campaignRows);
  if (data.pyvis_html) drawPyvisTopology(byId('battle-topology'), data.pyvis_html);
  battleVisualSignature = data.visual_signature || battleVisualSignature;
  renderEvidenceTable(byId('network-events-body'), data.network_events, [
    {label: 'Time', value: e => readableNetworkTime(e.timestamp)},
    {label: 'Source', value: e => networkField(e, 'source_ip', 'source_node')},
    {label: 'Destination', value: e => networkField(e, 'destination_ip', 'target_node')},
    {label: 'Communication', value: networkCommunication},
    {label: 'Protocol', value: e => e.protocol},
    {label: 'Port', value: networkServicePort},
    {label: 'Related assessment step', value: relatedAssessmentStep},
    {label: 'Evidence meaning', value: networkEvidenceMeaning}
  ], 'No canonical network events available.', 'network-events-head', {containerId: 'network-evidence-scroll'});
  renderEvidenceTable(byId('background-network-body'), data.background_network || [], [
    {label: 'Timestamp', value: e => e.timestamp}, {label: 'Feed', value: e => e.source_type},
    {label: 'Source IP', value: e => e.source_ip}, {label: 'Destination IP', value: e => e.destination_ip},
    {label: 'Protocol', value: e => e.protocol}, {label: 'Source port', value: e => e.source_port}, {label: 'Destination port', value: e => e.destination_port},
    {label: 'Observation / flow', value: e => networkField(e, 'observation', 'flow', 'application_protocol'), payload: true}
  ], 'No background network traffic available.', 'background-network-head');
  renderEvidenceTable(byId('security-events-body'), data.security_events, [
    {label: 'Timestamp', value: e => e.timestamp}, {label: 'Attack step', value: e => e.display_identity?.attack_step, optional: true},
    {label: 'Attack event', value: e => e.display_identity?.attack_event, optional: true},
    {label: 'Action', value: e => e.event_type}, {label: 'Target', value: e => e.target_node},
    {label: 'MITRE', value: e => e.mitre_technique}, {label: 'Result', value: e => e.result},
    {label: 'Detection', value: e => e.technical_details?.['Detection Result'] || 'Detection Not Available / Not Evaluated'}, {label: 'Severity', value: e => attackEventSeverity(e, data.security_events)},
    {label: 'Defense', value: e => e.defense_action, optional: true}
  ], 'No canonical security events available.', 'security-events-head', {containerId: 'security-evidence-scroll'});
  updateControlStates();
  const targets = data.topology.nodes.filter(node => node.id.startsWith('plc')).map(node => node.id); const selector = byId('defense-target');
  if (!selector.options.length) { selector.innerHTML = targets.map(target => `<option value="${escapeHtml(target)}">${escapeHtml(target)}</option>`).join(''); }
  byId('campaign-status-detail').textContent = campaignStatus.error?.message || `Campaign ${campaignStatus.state}; monitoring ${campaignStatus.watcher || latestSystem?.watcher?.state || 'OFFLINE'}; step ${campaignStatus.current_step || 0}.`;
  const runObj = data.active_run?.run || {};
  const assessmentComplete = Boolean(
    runObj.ended_at || ['COMPLETED', 'COMPLETE'].includes(runObj.status) || ['COMPLETED', 'COMPLETE'].includes(runObj.lifecycle_status)
  );
  setElementVisibility(byId('battle-next-bar'), assessmentComplete);
}
let selectedReportRun = null, reportPending = false;
function reportQuery() { return selectedReportRun ? `?scenario_id=${encodeURIComponent(selectedReportRun.scenario_id)}&run_id=${encodeURIComponent(selectedReportRun.run_id)}` : ''; }
async function loadReports() {
  const data = await api('/api/report-summary' + reportQuery());
  selectedReportRun = data.run_id ? {scenario_id: data.scenario_id, run_id: data.run_id} : null;
  byId('report-run').innerHTML = (data.runs || []).map(r => `<option value="${escapeHtml(r.run_id)}" ${r.run_id === data.run_id ? 'selected' : ''}>${escapeHtml(r.display_name || 'Assessment')} (${escapeHtml(r.campaign_state)})</option>`).join('');
  byId('report-run').onchange = async () => {
    selectedReportRun = data.runs.find(r => r.run_id === byId('report-run').value);
    try { await loadReports(); } catch (error) { byId('report-status').textContent = `Report load failed: ${error.message}`; }
  };
  byId('report-generate').disabled = reportPending || !data.normalized_records;
  for (const id of ['report-open', 'report-download']) { byId(id).hidden = !data.available; byId(id).href = data.url ? data.url + (id === 'report-download' ? '&download=1' : '') : ''; }
  byId('report-status').textContent = data.available ? `Existing report available for ${displayName(data.display_identity, 'assessment', 'the selected assessment')}` : (data.reason || 'No report available');
  const summary = data.finding_summary || {};
  const rows = [['Total findings', summary.total_findings], ['Detected', summary.detected],
    ['Failed', summary.failed], ['Timeout', summary.timeout], ['Techniques', summary.techniques], ['Targets', summary.targets]];
  setDetails(byId('report-normalization'), rows);
}
async function generateReport() {
  if (reportPending || !selectedReportRun) return;
  reportPending = true; byId('report-generate').disabled = true; byId('report-run').disabled = true;
  byId('report-status').textContent = 'Generating report from saved run evidence…';
  try {
    const data = await postApi('/api/report/generate', selectedReportRun);
    await loadReports();
    byId('report-status').textContent = `Report generated for ${displayName(data.display_identity, 'assessment', 'the selected assessment')}: ${data.normalized_records} completed attack records.`;
  } catch (error) { byId('report-status').textContent = `Report generation failed: ${error.message}`; }
  finally { reportPending = false; byId('report-generate').disabled = !selectedReportRun; byId('report-run').disabled = false; }
}
function loadRoute(route) { if (route === 'overview') return loadOverview(); if (route === 'network') return loadNetwork(); if (route === 'grid') return loadGridStatus(); if (route === 'runtime') return loadRuntime(); if (route === 'battle') return loadBattle(); if (route === 'reports') return loadReports(); return Promise.resolve(); }
function showPageRefreshError(error) {
  const notice = byId('runtime-refresh-status');
  notice.textContent = 'Page refresh unavailable — displayed information may be stale. Review Technical details.';
  if (byId('overview-status-error')) byId('overview-status-error').textContent = error.message;
  notice.dataset.state = 'stale';
}
async function activateRoute() {
  const sequence = ++routeRefreshSequence, route = location.hash.slice(1) || 'overview';
  document.querySelectorAll('[data-page]').forEach(page => page.classList.toggle('active', page.dataset.page === route));
  document.querySelectorAll('[data-route]').forEach(link => link.classList.toggle('active', link.dataset.route === route));
  setElementVisibility(byId('runtime-refresh-status'), route !== 'overview');
  if (route !== 'overview') await loadStatus();
  if (sequence !== routeRefreshSequence || route !== (location.hash.slice(1) || 'overview') || route === 'runtime') return;
  try { await loadRoute(route); }
  catch (error) { if (sequence === routeRefreshSequence) showPageRefreshError(error); }
}
async function runControl(path, payload, target) {
  const runtimeControl = path.startsWith('/api/runtime/');
  const watcherStart = path === '/api/runtime/watcher/start';
  if (runtimeControl && (runtimeControlPending || (watcherStart && watcherReadiness && (watcherReadiness.remaining > 0 || runtimeRefreshPending)))) return;
  const watcherIdentity = watcherStart ? {sessionId: String(latestSystem?.core?.session_id), generation: latestSystem?.generation} : null;
  if (runtimeControl) {
    watcherReadiness = null;
    runtimeControlPending = true; pendingRuntimePath = path;
    runtimeActionMessage = path === '/api/runtime/start' ? 'Starting CORE…' : 'Runtime request pending…';
    byId(target).textContent = runtimeActionMessage;
    updateControlStates();
  }
  let message;
  try {
    const data = await postApi(path, payload);
    message = path === '/api/runtime/gui' ? `CORE GUI opened for ${displayName(latestSystem?.display_identity, 'core_session', 'the active CORE session')}.` : data.state || data.watcher || 'REQUESTED';
    if (watcherStart) {
      message = 'Monitoring startup accepted; checking readiness…';
      if (data.session_id != null && String(data.session_id) === watcherIdentity.sessionId && watcherIdentity.generation) {
        watcherReadiness = {...watcherIdentity, remaining: WATCHER_READINESS_REFRESH_LIMIT};
      } else {
        message = 'Monitoring startup could not be verified for the current CORE Session and Runtime Generation. Review Technical details.';
      }
    }
  }
  catch (error) { message = error.message; }
  if (runtimeControl) runtimeActionMessage = message;
  try {
    await loadStatus();
    const route = location.hash.slice(1) || 'overview';
    if (route !== 'runtime') await loadRoute(route);
  } catch (error) { showPageRefreshError(error); }
  finally {
    if (runtimeControl) { runtimeControlPending = false; pendingRuntimePath = null; }
    updateControlStates();
    byId(target).textContent = runtimeControl ? (runtimeActionMessage || byId(target).textContent) : message;
  }
}
async function selectTopology() {
  if (topologyControlPending) return;
  const selectedCase = byId('topology-selector').value;
  if (selectedCase === 'custom') {
    topologySetupReady = false;
    updateControlStates();
    setElementVisibility(byId('custom-topology-panel'), true);
    setElementVisibility(byId('network-next-bar'), false);
    resetCustomWorkflow();
    try { resetCustomWorkflow(await api('/api/topology/template')); }
    catch (_) { /* Upload and Advanced JSON remain available. */ }
    byId('topology-selection-status').textContent = 'Create a topology in the builder or upload a JSON file, then validate and apply it.';
    return;
  }
  topologyControlPending = true; updateControlStates();
  const notice = byId('topology-selection-status'); notice.textContent = 'Loading the selected network…';
  try {
    const selected = await postApi('/api/topology/select', {case_name: selectedCase});
    renderNetworkConfiguration(selected.configuration, selected);
    topologySetupReady = true;
    notice.textContent = `Selected ${selected.topology.case_name}; showing ${selected.visual.nodes.length} network components and ${selected.visual.edges.length} connections.`;
    await loadOverview();
  } catch (error) {
    const message = `Topology selection failed: ${error.message}`;
    try { await loadNetwork(); } catch (_) { /* keep the last rendered topology */ }
    notice.textContent = message;
  } finally { topologyControlPending = false; updateControlStates(); }
}
function copySelectedTopology() {
  if (!selectedTopologyDefinition) return;
  const definition = {case_name: selectedTopologyDefinition.case_name.startsWith('custom_') ? selectedTopologyDefinition.case_name : 'custom_grid',
    nodes: selectedTopologyDefinition.nodes, edges: selectedTopologyDefinition.edges};
  byId('custom-topology-json').value = JSON.stringify(definition, null, 2);
  if (byId('custom-preview-case')) byId('custom-preview-case').textContent = definition.case_name;
  if (byId('custom-preview-buses')) byId('custom-preview-buses').textContent = (definition.nodes || []).length;
  if (byId('custom-preview-edges')) byId('custom-preview-edges').textContent = (definition.edges || []).length;
  if (byId('custom-preview-badge')) byId('custom-preview-badge').textContent = 'Valid';
  setElementVisibility(byId('custom-topology-preview'), true);
}
async function handleCustomTopologyUpload(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const errBanner = byId('custom-topology-error');
  const preview = byId('custom-topology-preview');
  setElementVisibility(errBanner, false);
  setElementVisibility(preview, false);
  try {
    const textContent = typeof file.text === 'function' ? await file.text() : await new Promise((res, rej) => {
      const reader = new FileReader();
      reader.onload = () => res(reader.result);
      reader.onerror = () => rej(reader.error);
      reader.readAsText(file);
    });
    let definition;
    try {
      definition = JSON.parse(textContent);
    } catch (parseErr) {
      throw new Error(`Invalid JSON syntax: ${parseErr.message}`);
    }
    await validateAndPreviewCustom(definition);
    renderTopologyBuilder(definition);
  } catch (err) {
    setElementVisibility(preview, false);
    if (errBanner) {
      errBanner.textContent = `Validation Error: ${err.message}`;
      setElementVisibility(errBanner, true);
    }
    byId('topology-selection-status').textContent = `Custom topology validation failed: ${err.message}`;
  }
}
async function saveCustomTopology() {
  if (topologyControlPending || byId('custom-topology-save').disabled) return;
  if (byId('topology-selector').value !== 'custom' && !String(byId('topology-selector').value).startsWith('custom_')) return;
  topologyControlPending = true; updateControlStates();
  const notice = byId('topology-selection-status');
  try {
    const definition = JSON.parse(byId('custom-topology-json').value);
    await validateAndPreviewCustom(definition);
    const selected = await postApi('/api/topology/custom', {definition});
    renderNetworkConfiguration(selected.configuration, selected);
    topologySetupReady = true;
    notice.textContent = `Saved and selected ${selected.topology.case_name}. Start CORE to use this topology.`;
    await loadOverview();
  } catch (error) {
    notice.textContent = `Custom topology failed: ${error.message}`;
    const errBanner = byId('custom-topology-error');
    if (errBanner) {
      errBanner.textContent = `Custom topology failed: ${error.message}`;
      setElementVisibility(errBanner, true);
    }
  }
  finally { topologyControlPending = false; updateControlStates(); }
}
function bindControls() {
  byId('report-generate').addEventListener('click', generateReport);
  byId('core-start').addEventListener('click', () => byId('core-start').disabled ? undefined : runControl('/api/runtime/start', {}, 'runtime-action-status'));
  byId('core-stop').addEventListener('click', () => runControl('/api/runtime/stop', {}, 'runtime-action-status'));
  byId('watcher-start').addEventListener('click', () => runControl('/api/runtime/watcher/start', {}, 'runtime-action-status'));
  byId('core-gui').addEventListener('click', () => runControl('/api/runtime/gui', {}, 'runtime-action-status'));
  byId('topology-selector').addEventListener('change', selectTopology);
  byId('custom-topology-copy').addEventListener('click', copySelectedTopology);
  byId('custom-topology-save').addEventListener('click', saveCustomTopology);
  const fileInput = byId('custom-topology-file');
  if (fileInput) fileInput.addEventListener('change', handleCustomTopologyUpload);
  const applyBtn = byId('custom-topology-apply-btn');
  if (applyBtn) applyBtn.addEventListener('click', saveCustomTopology);
  byId('custom-builder-add-node').addEventListener('click', () => {
    const definition = topologyBuilderDefinition();
    definition.nodes.push({bus_id:definition.nodes.length,name:`Bus ${definition.nodes.length + 1}`,type:definition.nodes.length ? 'pq':'slack',vn_kv:110,voltage:1,pg:0,qg:0,pl:0,ql:0});
    renderTopologyBuilder(definition); validatedCustomDefinition = null;
  });
  byId('custom-builder-add-edge').addEventListener('click', () => {
    const definition = topologyBuilderDefinition();
    definition.edges.push({from:0,to:Math.min(1,Math.max(0,definition.nodes.length-1)),length_km:1,r_ohm_per_km:0.1,x_ohm_per_km:0.1,c_nf_per_km:0,max_i_ka:0.4});
    renderTopologyBuilder(definition); validatedCustomDefinition = null;
  });
  for (const [id, attribute] of [['custom-builder-nodes','removeNode'],['custom-builder-edges','removeEdge']]) byId(id).addEventListener('click', event => {
    const button = event.target.closest(`[data-${attribute.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase())}]`); if (!button) return;
    const definition = topologyBuilderDefinition(), index = Number(button.dataset[attribute]);
    if (attribute === 'removeNode') {
      definition.nodes.splice(index,1); definition.nodes.forEach((node,i)=>node.bus_id=i);
      definition.edges = definition.edges.filter(edge=>edge.from!==index&&edge.to!==index).map(edge=>({...edge,from:edge.from>index?edge.from-1:edge.from,to:edge.to>index?edge.to-1:edge.to}));
    } else definition.edges.splice(index,1);
    renderTopologyBuilder(definition); validatedCustomDefinition = null; setElementVisibility(byId('custom-topology-preview'),false);
  });
  byId('custom-builder-validate').addEventListener('click', async () => {
    try { await validateAndPreviewCustom(topologyBuilderDefinition()); }
    catch (error) { byId('custom-topology-error').textContent = error.message; setElementVisibility(byId('custom-topology-error'),true); setElementVisibility(byId('custom-topology-preview'),false); }
  });
  byId('campaign-start').addEventListener('click', () => runControl('/api/campaign/start', {}, 'campaign-status-detail'));
  byId('campaign-next').addEventListener('click', () => runControl('/api/campaign/next', {}, 'campaign-status-detail'));
  byId('campaign-run').addEventListener('click', () => runControl('/api/campaign/run', {}, 'campaign-status-detail'));
  byId('campaign-isolate').addEventListener('click', () => runControl('/api/campaign/isolate', {target_node: byId('defense-target').value}, 'campaign-status-detail'));
  byId('campaign-restore').addEventListener('click', () => runControl('/api/campaign/restore', {target_node: byId('defense-target').value}, 'campaign-status-detail'));
  refreshTimer = window.setInterval(async () => {
    const route = location.hash.slice(1) || 'overview', battle = route === 'battle';
    const overview = false; // Static sample has no runtime polling dependency.
    const grid = route === 'grid' && ++overviewRefreshTicks % 5 === 0;
    const checkingWatcher = watcherReadiness?.remaining > 0;
    if ((!battle && !overview && !grid && !checkingWatcher) || pageRefreshPending || ((checkingWatcher || overview || grid) && (runtimeControlPending || runtimeRefreshPending))) return;
    pageRefreshPending = true;
    try { await loadStatus(); if (battle) await loadBattle(); else if (overview) await loadOverview(); else if (grid) await loadGridStatus(); }
    catch (error) { showPageRefreshError(error); }
    finally { pageRefreshPending = false; }
  }, 1000);
}
window.addEventListener('hashchange', activateRoute); bindControls(); activateRoute();
