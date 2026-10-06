const byId = id => document.getElementById(id);
const statusText = (label, value) => `${label} — ${value || 'NONE'}`;
const text = value => value === null || value === undefined || value === '' ? 'NONE' : String(value);
const unavailable = value => value === null || value === undefined || value === '' ? 'N/A' : (typeof value === 'object' ? JSON.stringify(value) : String(value));
const escapeHtml = value => unavailable(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
let latestSystem = null, latestActive = null, refreshTimer = null;
let runtimeRefreshSequence = 0, runtimeFresh = false, runtimeRefreshPending = false, runtimeControlPending = false;
let runtimeActionMessage = '', pendingRuntimePath = null;
let topologyControlPending = false;
let selectedTopologyDefinition = null;
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

function updateControlStates() {
  const usable = runtimeFresh && !runtimeControlPending;
  const core = latestSystem?.core, watcher = latestSystem?.watcher;
  const running = usable && core?.state === 'RUNTIME';
  const start = byId('core-start'), starting = pendingRuntimePath === '/api/runtime/start';
  start.disabled = !(usable && !runtimeRefreshPending && !topologyControlPending && core?.state === 'STOPPED' && core?.daemon === 'AVAILABLE');
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
  byId('topology-selector').disabled = !runtimeFresh || running || latestSystem?.runtime_marker || runtimeControlPending || topologyControlPending;
  for (const id of ['custom-topology-json', 'custom-topology-save', 'custom-topology-copy']) byId(id).disabled = byId('topology-selector').disabled;
}
function renderRuntimeState(system) {
  const active = system.active_run;
  const identity = system.display_identity || {};
  const core = system.core.state, watcher = system.watcher.state;
  const environment = core === 'RUNTIME' ? 'Running' : core === 'STOPPED' && system.core.daemon === 'AVAILABLE' ? 'Ready' : 'Unavailable';
  const monitoring = core === 'RUNTIME' && watcher === 'IDLE' ? 'Ready' : core === 'RUNTIME' && watcher === 'BUSY' ? 'Active' : 'Unavailable';
  const assessmentState = assessmentLabel(active);
  const assessment = active?.state === 'ACTIVE' ? displayName(identity, 'assessment', 'Current assessment') : assessmentState;
  byId('core-status').textContent = statusText('Assessment Environment', environment);
  byId('watcher-status').textContent = statusText('Monitoring', monitoring);
  byId('run-status').textContent = active?.state === 'ACTIVE' ? `${assessment} — ${assessmentState.replace('Assessment ', '')}` : assessmentState;
  byId('campaign-status').textContent = text(active?.run?.campaign_request?.state || active?.state);
  byId('generation-status').textContent = displayName(identity, 'runtime_generation');
  byId('overview-core').textContent = environment;
  byId('overview-core-detail').textContent = environment === 'Running' ? 'Assessment environment is active.' : environment === 'Ready' ? 'Environment ready for a security assessment.' : 'Assessment environment is not ready.';
  byId('overview-watcher').textContent = monitoring;
  byId('overview-monitoring-detail').textContent = monitoring === 'Active' ? 'Security monitoring is processing activity.' : monitoring === 'Ready' ? 'Security monitoring is ready.' : 'Security monitoring is unavailable.';
  byId('overview-run').textContent = assessment;
  byId('overview-session').textContent = displayName(identity, 'core_session');
  byId('overview-generation').textContent = displayName(identity, 'runtime_generation');
  byId('overview-run-detail').textContent = active?.state === 'ACTIVE' ? 'Review assessment results and recent security activity below.' : active?.state === 'REJECTED' ? 'Assessment evidence could not be verified. Review Technical details.' : 'Ready to begin a security assessment.';
  setDetails(byId('overview-technical-data'), [
    ['Assessment', displayName(identity, 'assessment')], ['Internal assessment ID', identity.assessment?.internal_id],
    ['Internal scenario ID', active?.run?.scenario_id], ['CORE environment', displayName(identity, 'core_session')],
    ['Internal CORE session ID', identity.core_session?.internal_id], ['Runtime', displayName(identity, 'runtime_generation')],
    ['Internal generation ID', identity.runtime_generation?.internal_id], ['Environment status', core],
    ['Monitoring status', watcher], ['CORE service status', system.core.daemon],
    ['Runtime marker present', system.runtime_marker], ['Evidence diagnostic', active?.integrity_error || 'None']
  ].map(([label,value]) => [label,escapeHtml(text(value))]));
  byId('runtime-daemon').textContent = text(system.core.daemon); byId('runtime-session').textContent = displayName(identity, 'core_session'); byId('runtime-generation').textContent = displayName(identity, 'runtime_generation'); byId('runtime-watcher').textContent = text(watcher);
  const rows = active && active.state === 'ACTIVE' ? [['State', active.state], ['Assessment', displayName(identity, 'assessment')], ['CORE session', displayName(identity, 'core_session')], ['Runtime', displayName(identity, 'runtime_generation')], ['Lifecycle', active.run.lifecycle_status], ['Started', active.run.started_at]] : [['Current assessment', active ? active.state : 'NONE'], ['Details', active?.integrity_error || 'No active assessment']];
  setDetails(byId('runtime-recovery'), rows);
  byId('runtime-action-status').textContent = runtimeActionMessage || (core === 'RUNTIME' ? (watcher === 'IDLE' ? 'Security monitoring is ready.' : watcher === 'BUSY' ? 'Security monitoring is active.' : 'The current CORE Session is ready for security monitoring.') : core === 'STOPPED' ? 'Start CORE prepares the selected network.' : 'The assessment environment is unavailable.');
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
    byId('overview-status-error').textContent = data.core.error || 'None';
    const notice = byId('runtime-refresh-status');
    notice.textContent = data.core.daemon === 'AVAILABLE' ? '' : 'Assessment environment is unavailable. Review Technical details or the environment controls.';
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
    byId('overview-status-error').textContent = error.message;
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
    return `<article class="security-activity-item"><div><strong>${escapeHtml(names[event.event_type])}</strong><time title="${escapeHtml(event.timestamp || 'Time unavailable')}">${escapeHtml(timestamp)}</time></div><p>${escapeHtml(target)}${technique ? ' · ' + escapeHtml(technique) : ''}${step ? ' — ' + escapeHtml(step) : ''}</p><span>${escapeHtml(outcome)}</span></article>`;
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
function renderSeverityDistribution(distribution = {}) {
  const order = ['Critical','High','Medium','Low','Informational'];
  const values = order.map(label => ({label, count: Number.isFinite(Number(distribution[label])) ? Math.max(0, Number(distribution[label])) : 0}));
  const total = values.reduce((sum, item) => sum + item.count, 0), chart = byId('overview-severity-chart');
  byId('overview-severity-total').textContent = total;
  if (!total) {
    chart.classList.add('empty'); chart.removeAttribute('style'); chart.setAttribute('aria-label', 'No attack severity data available');
    byId('overview-severity-legend').innerHTML = '<p>No completed attack findings yet.</p>'; return;
  }
  let cursor = 0;
  const segments = values.filter(item => item.count > 0).map(item => {
    const start = cursor, end = cursor + item.count / total * 360; cursor = end;
    return `${severityPalette[item.label]} ${start.toFixed(2)}deg ${end.toFixed(2)}deg`;
  });
  chart.classList.remove('empty'); chart.setAttribute('style', `background:conic-gradient(${segments.join(',')})`);
  chart.setAttribute('aria-label', `Severity distribution for ${total} findings: ${values.map(item => `${item.label} ${item.count}`).join(', ')}`);
  byId('overview-severity-legend').innerHTML = values.filter(item => item.count > 0).map(item => `<div><i class="severity-swatch" style="background:${severityPalette[item.label]}" aria-hidden="true"></i><span>${item.label}</span><strong>${item.count}</strong></div>`).join('');
}
function renderAttackCatalogue(attacks = []) {
  const target = byId('overview-attack-catalogue');
  if (!attacks.length) { target.innerHTML = '<div class="empty-state">No completed attacks yet.<small>Attack findings will appear after an assessment records completed steps.</small></div>'; return; }
  target.innerHTML = attacks.map(attack => {
    const severity = ['Critical','High','Medium','Low','Informational'].includes(attack.severity) ? attack.severity : 'Unavailable';
    const component = /^plc\d+$/i.test(attack.target || '') ? String(attack.target).toUpperCase() : attack.target || 'Not available';
    const detected = attack.detected === true ? 'Detected' : 'Not detected';
    const dvs = Number.isFinite(attack.finding_dvs) ? `${attack.finding_dvs.toFixed(1)} / 100` : 'Not available';
    return `<details class="attack-card"><summary><span class="attack-severity" style="color:${severityPalette[severity] || '#6f6a62'}">${escapeHtml(severity.toUpperCase())}</span><span class="attack-card-title"><strong>${escapeHtml(attack.title || 'Attack technique')}</strong><span>${escapeHtml(attack.attack_step || 'Attack step unavailable')} · ${escapeHtml(attack.technique_id || 'MITRE ID unavailable')}</span></span><span class="attack-result">${escapeHtml(detected)}</span></summary><div class="attack-card-body"><p>${escapeHtml(attack.description || 'No plain-language description is available.')}</p><div class="attack-facts"><div><span>Target</span><strong>${escapeHtml(component)}</strong></div><div><span>Result</span><strong>${escapeHtml(friendlyResult(attack.result))}</strong></div><div><span>Detection</span><strong>${escapeHtml(detected)}</strong></div><div><span>Detection method</span><strong>${escapeHtml(friendlyDetectionMethod(attack.detection_method))}</strong></div><div><span>Severity</span><strong>${escapeHtml(severity)}</strong></div><div><span>Finding DVS</span><strong>${escapeHtml(dvs)}</strong></div><div><span>MITRE ATT&amp;CK</span><strong>${escapeHtml(attack.technique_id || 'Not available')}</strong></div><div><span>Security event</span><strong>${escapeHtml(attack.attack_event || 'Not available')}</strong></div></div></div></details>`;
  }).join('');
}
function renderAssessmentOverview(counts, overview, assessmentName) {
  const available = counts && overview;
  byId('overview-results-assessment').textContent = available ? assessmentName : 'No assessment results available';
  for (const [id, key] of [['overview-total-findings','total_findings'],['overview-total-detected','detected'],['overview-total-failed','failed'],['overview-total-timeout','timeout']]) byId(id).textContent = available ? counts[key] : 'Not available';
  const dvs = overview?.dvs || {};
  byId('overview-finding-dvs').textContent = dvs.finding_available ? `Available for ${dvs.finding_assessed} finding${dvs.finding_assessed === 1 ? '' : 's'}` : 'Not available';
  byId('overview-campaign-dvs').textContent = dvs.campaign_available && Number.isFinite(dvs.campaign_score) ? `${dvs.campaign_score.toFixed(1)} / 100${dvs.campaign_rating ? ` (${dvs.campaign_rating})` : ''}` : 'Not available';
  renderSeverityDistribution(overview?.severity_distribution || {});
  renderAttackCatalogue(overview?.attacks || []);
  const defense = overview?.defense || {};
  byId('overview-defense-detected').textContent = available ? `${defense.detected} of ${defense.total}` : 'Not available';
  byId('overview-defense-rate').textContent = available && Number.isFinite(defense.detection_rate) ? `${(defense.detection_rate * 100).toFixed(1)}%` : 'Not available';
  const methods = Object.entries(defense.methods || {}).filter(([method, count]) => Number(count) > 0 && !['none','unknown'].includes(String(method).toLowerCase()));
  byId('overview-defense-methods').textContent = methods.length ? methods.map(([method,count]) => `${friendlyDetectionMethod(method)} (${count})`).join(', ') : 'Not available';
}
async function loadOverview() {
  const sequence = ++overviewRefreshSequence, runtimeSequence = runtimeRefreshSequence;
  const [data, activity] = await Promise.all([api('/api/topology'), api('/api/live-battle?limit=10')]);
  const active = activity.active_run;
  let counts = null, assessmentOverview = null, summaryUnavailable = false;
  if (active?.state === 'ACTIVE') {
    try {
      const summary = await api(`/api/report-summary?scenario_id=${encodeURIComponent(active.run.scenario_id)}&run_id=${encodeURIComponent(active.run.run_id)}`);
      if (summary.run_id === active.run.run_id && summary.scenario_id === active.run.scenario_id && summary.finding_summary) { counts = summary.finding_summary; assessmentOverview = summary.assessment_overview || null; }
      else summaryUnavailable = true;
    } catch (_) { summaryUnavailable = true; }
  }
  if (sequence !== overviewRefreshSequence || runtimeSequence !== runtimeRefreshSequence) return;
  const signature = data.visual_signature || JSON.stringify(data.visual);
  if (signature !== overviewVisualSignature) {
    drawPyvisTopology(byId('overview-topology'), data.pyvis_html);
    overviewVisualSignature = signature;
  }
  const caseName = data.topology.case_name || 'Selected network';
  byId('overview-topology-name').textContent = caseName === 'case14' ? 'IEEE-14' : caseName === 'case30' ? 'IEEE-30' : caseName.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
  byId('overview-topology-summary').textContent = `${data.visual.nodes.length} devices · ${data.visual.edges.length} connections`;
  const assessmentState = assessmentLabel(active);
  const assessment = active?.state === 'ACTIVE' ? displayName(activity.display_identity, 'assessment', 'Current assessment') : assessmentState;
  byId('overview-run').textContent = assessment;
  byId('run-status').textContent = active?.state === 'ACTIVE' ? `${assessment} — ${assessmentState.replace('Assessment ', '')}` : assessmentState;
  byId('overview-run-detail').textContent = active?.state === 'ACTIVE' ? 'Review assessment results and recent security activity below.' : active?.state === 'REJECTED' ? 'Assessment evidence could not be verified. Review Technical details.' : 'Ready to begin a security assessment.';
  renderAssessmentOverview(counts, assessmentOverview, assessment);
  if (summaryUnavailable) byId('overview-run-detail').textContent = 'Assessment results are currently unavailable.';
  renderRecentSecurityActivity(activity.security_events || []);
}
async function loadNetwork() {
  const [config, topology] = await Promise.all([api('/api/network-configuration'), api('/api/topology')]);
  renderNetworkConfiguration(config, topology);
}
function gridValue(value, unit = '', digits = 2) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(digits)}${unit ? ' ' + unit : ''}` : 'Not available';
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
  byId('grid-case').textContent = data.case_name === 'case14' ? 'IEEE-14' : data.case_name === 'case30' ? 'IEEE-30' : data.case_name.replaceAll('_',' ').replace(/\b\w/g, letter => letter.toUpperCase());
  byId('grid-components').innerHTML = data.components.map(row => `<tr><td>${escapeHtml(row.name)}</td><td>${escapeHtml(row.type)}</td><td>${gridValue(row.model_voltage_pu,'pu',3)}</td><td>${row.model_generation_mw == null && row.model_load_mw == null ? 'Not available' : `${gridValue(row.model_generation_mw,'MW')} / ${gridValue(row.model_load_mw,'MW')}`}</td><td>${escapeHtml(row.status)}</td></tr>`).join('') || '<tr><td colspan="5" class="table-empty">No components available.</td></tr>';
  setDetails(byId('grid-network'), [['Network devices',gridValue(network.device_count,'',0)],['Communication connections',gridValue(network.connections,'',0)],
    ['Electrical connections',gridValue(grid.electrical_connections,'',0)],['Responding components',gridValue(network.responding_components,'',0)],
    ['Failed component reads',gridValue(network.offline_components,'',0)],['Network monitoring',network.status],
    ['Bandwidth capacity',gridValue(network.bandwidth_capacity_bps,'bit/s')],['Observed flow traffic rate',gridValue(network.observed_traffic.bits_per_second,'bit/s')],
    ['Recent detection notices',gridValue(network.recent_detection_notices,'',0)]]);
  byId('grid-sources').innerHTML = Object.values(data.provenance).map(value => `<p>${escapeHtml(value)}</p>`).join('');
  setDetails(byId('grid-reactive-power'), [['Model reactive generation',gridValue(grid.model_reactive_generation_mvar,'Mvar')],['Model reactive load',gridValue(grid.model_reactive_load_mvar,'Mvar')]]);
  byId('grid-technical-components').innerHTML = data.components.map(row => `<tr><td>${escapeHtml(row.name)}</td><td>${escapeHtml(row.ip)}</td><td>${escapeHtml(row.last_observed || 'Not available')}</td></tr>`).join('');
}
function renderNetworkConfiguration(config, topology) {
  selectedTopologyDefinition = config.definition || null;
  byId('network-nodes').textContent = config.node_count; byId('network-edges').textContent = config.edge_count; byId('network-case').textContent = text(config.case_name || config.topology_version); byId('network-types').textContent = Object.keys(config.node_types).length;
  setDetails(byId('network-metadata'), [['Topology version', config.topology_version], ['Case', config.case_name], ['Node types', Object.entries(config.node_types).map(([k, v]) => `${k}: ${v}`).join(', ')]]);
  const selector = byId('topology-selector'), current = config.selected_case || config.case_name;
  selector.innerHTML = (config.available_topologies || []).map(item => `<option value="${escapeHtml(item.case_name)}">${escapeHtml(item.name)}</option>`).join('');
  selector.value = current;
  selector.disabled = !runtimeFresh || latestSystem?.core?.state === 'RUNTIME' || latestSystem?.runtime_marker || runtimeControlPending || topologyControlPending;
  byId('topology-selection-status').textContent = `Selected backend topology: ${current}. Changes are available before CORE startup.`;
  drawPyvisTopology(byId('network-topology'), topology.pyvis_html);
}
async function loadRuntime() { return refreshRuntimeState(); }
function evidenceValue(value) {
  if (value === 'N/A') return '<span title="Not applicable">—</span>';
  if (value === null || value === undefined) return '<span title="Unavailable">—</span>';
  if (value === '') return '<span title="Empty string">&quot;&quot;</span>';
  return escapeHtml(typeof value === 'object' ? JSON.stringify(value) : String(value));
}
function evidenceDetails(value, label = null) {
  if (value === null || value === undefined || value === 'N/A' || value === '') return evidenceValue(value);
  const compact = typeof value === 'object' ? JSON.stringify(value) : String(value);
  const full = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
  const preview = label || (compact.length > 96 ? compact.slice(0, 96) + '…' : compact);
  return `<details class="evidence-details"><summary><span class="payload-preview">${escapeHtml(preview)}</span></summary><pre>${escapeHtml(full)}</pre></details>`;
}
function meaningfulEvidence(value) { return value !== null && value !== undefined && value !== '' && value !== 'N/A'; }
function attackEventSeverity(event, events) {
  if (!['attack_started', 'attack_finished', 'detection'].includes(event.event_type)) return event.severity;
  const identity = ['scenario_id', 'run_id', 'generation_id', 'correlation_id'];
  const start = event.correlation_id ? events.find(candidate => candidate.event_type === 'attack_started' && identity.every(key => candidate[key] === event[key])) : null;
  return start ? (start.attack_severity ?? start.severity) : (event.attack_severity ?? null);
}
function renderEvidenceTable(target, rows, columns, emptyMessage, headerId) {
  const visible = columns.filter(column => !column.optional || rows.some(row => meaningfulEvidence(column.value(row))));
  byId(headerId).innerHTML = visible.map(column => `<th scope="col">${escapeHtml(column.label)}</th>`).join('') + '<th scope="col">Details</th>';
  if (!rows.length) { target.innerHTML = `<tr><td colspan="${visible.length + 1}" class="table-empty">${escapeHtml(emptyMessage)}</td></tr>`; return; }
  target.innerHTML = rows.map(row => `<tr>${visible.map(column => `<td>${column.payload ? evidenceDetails(column.value(row)) : evidenceValue(column.value(row))}</td>`).join('')}<td>${evidenceDetails(row, 'Technical details')}</td></tr>`).join('');
}
function networkField(event, ...names) { const name = names.find(key => event[key] !== null && event[key] !== undefined && event[key] !== 'N/A'); return name === undefined ? (event[names[0]] ?? null) : event[name]; }
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
    {label: 'Timestamp', value: e => e.timestamp}, {label: 'Source', value: e => networkField(e, 'source_ip', 'source_node')},
    {label: 'Destination', value: e => networkField(e, 'destination_ip', 'target_node')}, {label: 'Protocol', value: e => e.protocol},
    {label: 'Source port', value: e => networkField(e, 'source_port', 'src_port')}, {label: 'Destination port', value: e => networkField(e, 'destination_port', 'dest_port', 'dst_port')},
    {label: 'Packet / flow', value: e => networkField(e, 'packet', 'flow', 'details', 'evidence'), payload: true},
    {label: 'Modbus', value: e => networkField(e, 'modbus', 'modbus_fields', 'modbus_function'), payload: true, optional: true},
    {label: 'IDS', value: e => networkField(e, 'ids', 'ids_metadata', 'suricata'), payload: true, optional: true}
  ], 'No canonical network events available.', 'network-events-head');
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
    {label: 'Detection', value: e => networkField(e, 'detected', 'detection_method'), optional: true}, {label: 'Severity', value: e => attackEventSeverity(e, data.security_events)},
    {label: 'Defense', value: e => e.defense_action, optional: true}
  ], 'No canonical security events available.', 'security-events-head');
  updateControlStates();
  const targets = data.topology.nodes.filter(node => node.id.startsWith('plc')).map(node => node.id); const selector = byId('defense-target');
  if (!selector.options.length) { selector.innerHTML = targets.map(target => `<option value="${escapeHtml(target)}">${escapeHtml(target)}</option>`).join(''); }
  byId('campaign-status-detail').textContent = campaignStatus.error?.message || `Campaign ${campaignStatus.state}; monitoring ${campaignStatus.watcher || latestSystem?.watcher?.state || 'OFFLINE'}; step ${campaignStatus.current_step || 0}.`;
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
  byId('overview-status-error').textContent = error.message;
  notice.dataset.state = 'stale';
}
async function activateRoute() {
  const sequence = ++routeRefreshSequence, route = location.hash.slice(1) || 'overview';
  document.querySelectorAll('[data-page]').forEach(page => page.classList.toggle('active', page.dataset.page === route));
  document.querySelectorAll('[data-route]').forEach(link => link.classList.toggle('active', link.dataset.route === route));
  await loadStatus();
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
  topologyControlPending = true; updateControlStates();
  const notice = byId('topology-selection-status'); notice.textContent = 'Loading the selected network…';
  try {
    const selected = await postApi('/api/topology/select', {case_name: byId('topology-selector').value});
    renderNetworkConfiguration(selected.configuration, selected);
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
}
async function saveCustomTopology() {
  if (topologyControlPending || byId('custom-topology-save').disabled) return;
  topologyControlPending = true; updateControlStates();
  const notice = byId('topology-selection-status');
  try {
    const definition = JSON.parse(byId('custom-topology-json').value);
    const selected = await postApi('/api/topology/custom', {definition});
    renderNetworkConfiguration(selected.configuration, selected);
    notice.textContent = `Saved and selected ${selected.topology.case_name}. Start CORE to use this topology.`;
    await loadOverview();
  } catch (error) { notice.textContent = `Custom topology failed: ${error.message}`; }
  finally { topologyControlPending = false; updateControlStates(); }
}
function bindControls() {
  byId('report-generate').addEventListener('click', generateReport);
  byId('core-start').addEventListener('click', () => runControl('/api/runtime/start', {}, 'runtime-action-status'));
  byId('core-stop').addEventListener('click', () => runControl('/api/runtime/stop', {}, 'runtime-action-status'));
  byId('watcher-start').addEventListener('click', () => runControl('/api/runtime/watcher/start', {}, 'runtime-action-status'));
  byId('core-gui').addEventListener('click', () => runControl('/api/runtime/gui', {}, 'runtime-action-status'));
  byId('topology-selector').addEventListener('change', selectTopology);
  byId('custom-topology-copy').addEventListener('click', copySelectedTopology);
  byId('custom-topology-save').addEventListener('click', saveCustomTopology);
  byId('campaign-start').addEventListener('click', () => runControl('/api/campaign/start', {}, 'campaign-status-detail'));
  byId('campaign-next').addEventListener('click', () => runControl('/api/campaign/next', {}, 'campaign-status-detail'));
  byId('campaign-run').addEventListener('click', () => runControl('/api/campaign/run', {}, 'campaign-status-detail'));
  byId('campaign-isolate').addEventListener('click', () => runControl('/api/campaign/isolate', {target_node: byId('defense-target').value}, 'campaign-status-detail'));
  byId('campaign-restore').addEventListener('click', () => runControl('/api/campaign/restore', {target_node: byId('defense-target').value}, 'campaign-status-detail'));
  refreshTimer = window.setInterval(async () => {
    const route = location.hash.slice(1) || 'overview', battle = route === 'battle';
    const overview = route === 'overview' && ++overviewRefreshTicks % 5 === 0;
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
