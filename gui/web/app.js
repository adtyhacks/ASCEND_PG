const byId = id => document.getElementById(id);
const statusText = (label, value) => `${label} — ${value || 'NONE'}`;
const text = value => value === null || value === undefined || value === '' ? 'NONE' : String(value);
const unavailable = value => value === null || value === undefined || value === '' ? 'N/A' : (typeof value === 'object' ? JSON.stringify(value) : String(value));
const escapeHtml = value => unavailable(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
let latestSystem = null, latestActive = null, refreshTimer = null;
let runtimeRefreshSequence = 0, runtimeFresh = false, runtimeRefreshPending = false, runtimeControlPending = false;
let runtimeActionMessage = '', pendingRuntimePath = null;
let topologyControlPending = false;
const WATCHER_READINESS_REFRESH_LIMIT = 30;
let watcherReadiness = null;
let latestBattle = null, latestCampaignStatus = null, battleVisualSignature = null, battleRefreshSequence = 0, pageRefreshPending = false;
let routeRefreshSequence = 0;

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
function activeRunLabel(active) { return active && active.state === 'ACTIVE' ? active.run.run_id : 'NONE'; }
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
  start.disabled = !(usable && !runtimeRefreshPending && core?.state === 'STOPPED' && core?.daemon === 'AVAILABLE');
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
}
function renderRuntimeState(system) {
  const active = system.active_run;
  const core = system.core.state, watcher = system.watcher.state;
  byId('core-status').textContent = statusText('CORE', core); byId('watcher-status').textContent = statusText('WATCHER', watcher);
  byId('run-status').textContent = statusText('ACTIVE RUN', activeRunLabel(active)); byId('campaign-status').textContent = statusText('CAMPAIGN', active ? active.state : 'NONE'); byId('generation-status').textContent = statusText('GENERATION', system.generation);
  byId('overview-core').textContent = text(core); byId('overview-core-detail').textContent = `Daemon ${text(system.core.daemon)}`;
  byId('overview-watcher').textContent = text(watcher); byId('overview-run').textContent = activeRunLabel(active);
  byId('overview-run-detail').textContent = active && active.state === 'REJECTED' ? 'Integrity check rejected run' : 'Owned-run recovery'; byId('overview-generation').textContent = text(system.generation);
  byId('runtime-daemon').textContent = text(system.core.daemon); byId('runtime-session').textContent = text(system.core.session_id); byId('runtime-generation').textContent = text(system.generation); byId('runtime-watcher').textContent = text(watcher);
  const rows = active && active.state === 'ACTIVE' ? [['State', active.state], ['Scenario ID', active.run.scenario_id], ['Run ID', active.run.run_id], ['Lifecycle', active.run.lifecycle_status], ['Started', active.run.started_at]] : [['Active run', active ? active.state : 'NONE'], ['Details', active?.integrity_error || 'No owned active run']];
  setDetails(byId('runtime-recovery'), rows);
  byId('runtime-action-status').textContent = runtimeActionMessage || (core === 'RUNTIME' ? (watcher === 'IDLE' ? 'Watcher IDLE — verified and ready.' : watcher === 'BUSY' ? 'Watcher BUSY — verified.' : 'Only the existing owned CORE session can be stopped or receive a watcher.') : core === 'STOPPED' ? 'Start CORE generates the canonical topology.' : 'CORE startup requires available runtime diagnostics.');
  updateControlStates();
}
function reconcileWatcherReadiness(system) {
  if (!watcherReadiness) return;
  if (system.core.state !== 'RUNTIME' || String(system.core.session_id) !== watcherReadiness.sessionId || !watcherReadiness.generation || system.generation !== watcherReadiness.generation) {
    watcherReadiness = null;
    runtimeActionMessage = 'Watcher startup could not be verified for the requested CORE session/generation. Review runtime diagnostics.';
  } else if (['IDLE', 'BUSY'].includes(system.watcher.state)) {
    watcherReadiness = null;
    runtimeActionMessage = '';
  } else if (!['UNVERIFIED', 'STARTING', 'UNKNOWN'].includes(system.watcher.state)) {
    watcherReadiness.remaining = 0;
    runtimeActionMessage = `Watcher ${system.watcher.state}; startup readiness is not verified.`;
  } else {
    runtimeActionMessage = watcherReadiness.remaining > 0 ? 'Watcher startup accepted; waiting for a verified heartbeat…' : 'Watcher readiness is not verified after bounded diagnostic refreshes. Review runtime diagnostics.';
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
    const notice = byId('runtime-refresh-status');
    notice.textContent = data.core.daemon === 'AVAILABLE' ? '' : `Runtime unavailable — ${data.core.error || 'CORE daemon is unavailable.'}`;
    notice.dataset.state = data.core.daemon === 'AVAILABLE' ? 'current' : 'stale';
    return data;
  } catch (error) {
    if (sequence !== runtimeRefreshSequence) return null;
    runtimeFresh = false; runtimeRefreshPending = false;
    if (watcherReadiness) {
      watcherReadiness.remaining = 0;
      runtimeActionMessage = 'Watcher startup accepted; readiness unavailable because runtime diagnostics could not be refreshed.';
      byId('runtime-action-status').textContent = runtimeActionMessage;
    }
    const notice = byId('runtime-refresh-status');
    notice.textContent = `${latestSystem ? 'Runtime status stale — showing last known values.' : 'Runtime status unavailable.'} ${error.message}`;
    notice.dataset.state = 'stale';
    updateControlStates();
    return null;
  }
}
async function loadStatus() { return refreshRuntimeState(); }
async function loadOverview() { const data = await api('/api/topology'); drawPyvisTopology(byId('overview-topology'), data.pyvis_html); byId('overview-topology-summary').textContent = `${data.visual.nodes.length} nodes · ${data.visual.edges.length} edges`; }
async function loadNetwork() {
  const [config, topology] = await Promise.all([api('/api/network-configuration'), api('/api/topology')]);
  renderNetworkConfiguration(config, topology);
}
function renderNetworkConfiguration(config, topology) {
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
function renderTable(target, rows, columns, emptyMessage) {
  if (!rows.length) { target.innerHTML = `<tr><td colspan="${columns.length}" class="table-empty">${emptyMessage}</td></tr>`; return; }
  target.innerHTML = rows.map(row => `<tr>${columns.map(column => `<td>${escapeHtml(column(row))}</td>`).join('')}</tr>`).join('');
}
function networkField(event, ...names) { return names.find(name => event[name] !== null && event[name] !== undefined && event[name] !== '') ? event[names.find(name => event[name] !== null && event[name] !== undefined && event[name] !== '')] : null; }
async function loadBattle() {
  const sequence = ++battleRefreshSequence, runtimeSequence = runtimeRefreshSequence;
  const visualQuery = battleVisualSignature ? `&visual_signature=${encodeURIComponent(battleVisualSignature)}` : '';
  const data = await api(`/api/live-battle?limit=100${visualQuery}`);
  const campaignStatus = await api('/api/campaign/status');
  if (sequence !== battleRefreshSequence || runtimeSequence !== runtimeRefreshSequence) return;
  latestBattle = data; latestCampaignStatus = campaignStatus;
  byId('battle-run').textContent = activeRunLabel(data.active_run); byId('battle-network-count').textContent = data.network_event_count; byId('battle-security-count').textContent = data.security_event_count; byId('battle-limit').textContent = data.limit;
  const campaign = data.campaign || {}, campaignRows = campaign && Object.keys(campaign).length ? Object.entries(campaign).filter(([key]) => ['state', 'campaign_id', 'generation_id', 'correlation_id', 'requested_at', 'current_step'].includes(key)).map(([key, value]) => [key.replaceAll('_', ' '), value]) : [['Campaign metadata', 'NONE']];
  setDetails(byId('battle-campaign-meta'), campaignRows);
  if (data.pyvis_html) drawPyvisTopology(byId('battle-topology'), data.pyvis_html);
  battleVisualSignature = data.visual_signature || battleVisualSignature;
  renderTable(byId('network-events-body'), data.network_events, [
    event => event.timestamp, event => event.source_node, event => event.target_node,
    event => networkField(event, 'protocol'), event => networkField(event, 'source_port', 'src_port'), event => networkField(event, 'destination_port', 'dest_port', 'dst_port'),
    event => networkField(event, 'packet', 'flow', 'details', 'evidence'), event => networkField(event, 'modbus', 'modbus_fields', 'modbus_function'), event => networkField(event, 'ids', 'ids_metadata', 'suricata')
  ], 'No canonical network events available.');
  renderTable(byId('background-network-body'), data.background_network || [], [
    event => event.timestamp, event => event.source_type, event => event.source_ip, event => event.destination_ip,
    event => event.protocol, event => event.source_port, event => event.destination_port,
    event => event.observation || [event.application_protocol, event.flow].filter(Boolean).map(value => typeof value === 'object' ? JSON.stringify(value) : value).join(' · ')
  ], 'No background network traffic available.');
  renderTable(byId('security-events-body'), data.security_events, [
    event => event.timestamp, event => networkField(event, 'ppo_step'), event => event.event_type, event => event.target_node,
    event => event.mitre_technique, event => event.result, event => networkField(event, 'detected', 'detection_method'), event => event.severity,
    event => event.defense_action, event => event.correlation_id
  ], 'No canonical security events available.');
  updateControlStates();
  const targets = data.topology.nodes.filter(node => node.id.startsWith('plc')).map(node => node.id); const selector = byId('defense-target');
  if (!selector.options.length) { selector.innerHTML = targets.map(target => `<option value="${escapeHtml(target)}">${escapeHtml(target)}</option>`).join(''); }
  byId('campaign-status-detail').textContent = campaignStatus.error?.message || `Campaign ${campaignStatus.state}; watcher ${campaignStatus.watcher || latestSystem?.watcher?.state || 'OFFLINE'}; step ${campaignStatus.current_step || 0}.`;
}
let selectedReportRun = null, reportPending = false;
function reportQuery() { return selectedReportRun ? `?scenario_id=${encodeURIComponent(selectedReportRun.scenario_id)}&run_id=${encodeURIComponent(selectedReportRun.run_id)}` : ''; }
async function loadReports() {
  const data = await api('/api/report-summary' + reportQuery());
  selectedReportRun = data.run_id ? {scenario_id: data.scenario_id, run_id: data.run_id} : null;
  byId('report-run').innerHTML = (data.runs || []).map(r => `<option value="${escapeHtml(r.run_id)}" ${r.run_id === data.run_id ? 'selected' : ''}>${escapeHtml(r.run_id)} (${escapeHtml(r.campaign_state)})</option>`).join('');
  byId('report-run').onchange = async () => {
    selectedReportRun = data.runs.find(r => r.run_id === byId('report-run').value);
    try { await loadReports(); } catch (error) { byId('report-status').textContent = `Report load failed: ${error.message}`; }
  };
  byId('report-generate').disabled = reportPending || !data.normalized_records;
  for (const id of ['report-open', 'report-download']) { byId(id).hidden = !data.available; byId(id).href = data.url ? data.url + (id === 'report-download' ? '&download=1' : '') : ''; }
  byId('report-status').textContent = data.available ? `Existing report available for ${data.run_id}` : (data.reason || 'No report available');
  const record = data.normalized_events?.[data.normalized_events.length - 1];
  const rows = record ? [['Normalized records', data.normalized_records], ['Technique', record['MITRE ID']], ['Target', record['Target Host']], ['Detected', record.Detected], ['Detection method', record['Detection Method']], ['Confidence', record['Detector Confidence']]] : [['Normalized records', 0], ['Details', 'No normalized report records available.']];
  setDetails(byId('report-normalization'), rows);
}
async function generateReport() {
  if (reportPending || !selectedReportRun) return;
  reportPending = true; byId('report-generate').disabled = true; byId('report-run').disabled = true;
  byId('report-status').textContent = 'Generating report from saved run evidence…';
  try {
    const data = await postApi('/api/report/generate', selectedReportRun);
    await loadReports();
    byId('report-status').textContent = `Report generated for ${data.run_id}: ${data.normalized_records} completed attack records.`;
  } catch (error) { byId('report-status').textContent = `Report generation failed: ${error.message}`; }
  finally { reportPending = false; byId('report-generate').disabled = !selectedReportRun; byId('report-run').disabled = false; }
}
function loadRoute(route) { if (route === 'overview') return loadOverview(); if (route === 'network') return loadNetwork(); if (route === 'runtime') return loadRuntime(); if (route === 'battle') return loadBattle(); if (route === 'reports') return loadReports(); return Promise.resolve(); }
function showPageRefreshError(error) {
  const notice = byId('runtime-refresh-status');
  notice.textContent = `Page refresh unavailable — displayed information may be stale. ${error.message}`;
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
    message = path === '/api/runtime/gui' ? `CORE GUI opened for session ${data.session_id} (PID ${data.gui_pid}).` : data.state || data.watcher || 'REQUESTED';
    if (watcherStart) {
      message = 'Watcher startup accepted; checking runtime diagnostics…';
      if (data.session_id != null && String(data.session_id) === watcherIdentity.sessionId && watcherIdentity.generation) {
        watcherReadiness = {...watcherIdentity, remaining: WATCHER_READINESS_REFRESH_LIMIT};
      } else {
        message = 'Watcher startup could not be verified for the requested CORE session/generation. Review runtime diagnostics.';
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
  const notice = byId('topology-selection-status'); notice.textContent = 'Loading selected topology from the canonical backend…';
  try {
    const selected = await postApi('/api/topology/select', {case_name: byId('topology-selector').value});
    renderNetworkConfiguration(selected.configuration, selected);
    notice.textContent = `Selected ${selected.topology.case_name}; showing ${selected.visual.nodes.length} canonical nodes and ${selected.visual.edges.length} connections.`;
    await loadOverview();
  } catch (error) {
    const message = `Topology selection failed: ${error.message}`;
    try { await loadNetwork(); } catch (_) { /* keep the last rendered topology */ }
    notice.textContent = message;
  } finally { topologyControlPending = false; updateControlStates(); }
}
function bindControls() {
  byId('report-generate').addEventListener('click', generateReport);
  byId('core-start').addEventListener('click', () => runControl('/api/runtime/start', {}, 'runtime-action-status'));
  byId('core-stop').addEventListener('click', () => runControl('/api/runtime/stop', {}, 'runtime-action-status'));
  byId('watcher-start').addEventListener('click', () => runControl('/api/runtime/watcher/start', {}, 'runtime-action-status'));
  byId('core-gui').addEventListener('click', () => runControl('/api/runtime/gui', {}, 'runtime-action-status'));
  byId('topology-selector').addEventListener('change', selectTopology);
  byId('campaign-start').addEventListener('click', () => runControl('/api/campaign/start', {}, 'campaign-status-detail'));
  byId('campaign-next').addEventListener('click', () => runControl('/api/campaign/next', {}, 'campaign-status-detail'));
  byId('campaign-run').addEventListener('click', () => runControl('/api/campaign/run', {}, 'campaign-status-detail'));
  byId('campaign-isolate').addEventListener('click', () => runControl('/api/campaign/isolate', {target_node: byId('defense-target').value}, 'campaign-status-detail'));
  byId('campaign-restore').addEventListener('click', () => runControl('/api/campaign/restore', {target_node: byId('defense-target').value}, 'campaign-status-detail'));
  refreshTimer = window.setInterval(async () => {
    const battle = (location.hash.slice(1) || 'overview') === 'battle';
    const checkingWatcher = watcherReadiness?.remaining > 0;
    if ((!battle && !checkingWatcher) || pageRefreshPending || (checkingWatcher && (runtimeControlPending || runtimeRefreshPending))) return;
    pageRefreshPending = true;
    try { await loadStatus(); if (battle) await loadBattle(); }
    catch (error) { showPageRefreshError(error); }
    finally { pageRefreshPending = false; }
  }, 1000);
}
window.addEventListener('hashchange', activateRoute); bindControls(); activateRoute();
