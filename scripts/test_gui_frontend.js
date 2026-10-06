#!/usr/bin/env node
'use strict';

// Deterministic frontend regressions. All HTTP, DOM, and timers are mocked;
// this script never starts CORE, a watcher, a campaign, or a local server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const appSource = fs.readFileSync(path.join(root, 'gui/web/app.js'), 'utf8');
const htmlSource = fs.readFileSync(path.join(root, 'gui/web/index.html'), 'utf8');
const cssSource = fs.readFileSync(path.join(root, 'gui/web/styles.css'), 'utf8');
const diagnosticsPath = '/api/runtime-diagnostics';
const runtimeControlIds = ['core-start', 'core-stop', 'watcher-start', 'core-gui'];
const campaignControlIds = ['campaign-start', 'campaign-next', 'campaign-run', 'campaign-isolate', 'campaign-restore', 'defense-target'];

function snapshot(state = 'STOPPED', watcher = 'STOPPED', generation = null) {
  const runId = `run-${generation || 'fixture'}`;
  return {
    core: {state, daemon: 'AVAILABLE', session_id: state === 'RUNTIME' ? 7 : null},
    watcher: {state: watcher}, generation, runtime_marker: state === 'RUNTIME',
    display_identity: {
      assessment: {display_name: state === 'RUNTIME' ? 'Assessment 1' : null, internal_id: state === 'RUNTIME' ? runId : null},
      core_session: {display_name: state === 'RUNTIME' ? 'CORE Session 1' : null, internal_id: state === 'RUNTIME' ? 7 : null},
      runtime_generation: {display_name: state === 'RUNTIME' ? 'Runtime Generation 1' : null, internal_id: state === 'RUNTIME' ? generation : null}
    },
    active_run: state === 'RUNTIME' ? {
      state: 'ACTIVE', integrity_validated: false,
      run: {scenario_id: 'scenario-fixture', run_id: runId,
        lifecycle_status: 'RUNNING', started_at: '2026-10-04T10:00:00Z'}
    } : null
  };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

class MockElement {
  constructor(tag, attributes, content = '') {
    this.tagName = tag.toUpperCase();
    this.attributes = {...attributes};
    this.id = attributes.id || '';
    this.disabled = Object.hasOwn(attributes, 'disabled');
    this.value = attributes.value || '';
    this.textContent = content;
    this.dataset = {};
    this.listeners = new Map();
    this._innerHTML = '';
    this.options = [];
    this.children = [];
    for (const [name, value] of Object.entries(attributes)) {
      if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    }
    const classes = new Set((attributes.class || '').split(/\s+/).filter(Boolean));
    this.classList = {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      contains: name => classes.has(name),
      toggle: (name, force) => {
        const add = force === undefined ? !classes.has(name) : Boolean(force);
        if (add) classes.add(name); else classes.delete(name);
        return add;
      },
      replace: (before, after) => { if (!classes.delete(before)) return false; classes.add(after); return true; }
    };
    Object.defineProperty(this, 'className', {
      get: () => [...classes].join(' '),
      set: value => { classes.clear(); String(value).split(/\s+/).filter(Boolean).forEach(name => classes.add(name)); }
    });
  }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(value) {
    this._innerHTML = String(value);
    if (this.tagName === 'SELECT') {
      this.options = [...this._innerHTML.matchAll(/<option\b[^>]*value="([^"]*)"[^>]*>([^<]*)<\/option>/g)]
        .map(match => ({value: match[1], textContent: match[2]}));
      if (this.options.length && !this.value) this.value = this.options[0].value;
    }
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  removeAttribute(name) { delete this.attributes[name]; }
  hasAttribute(name) { return Object.hasOwn(this.attributes, name); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, callback) {
    const callbacks = this.listeners.get(name) || [];
    callbacks.push(callback);
    this.listeners.set(name, callbacks);
  }
  dispatch(name) {
    return Promise.all((this.listeners.get(name) || []).map(callback => callback({type: name, target: this, currentTarget: this})));
  }
}

function mockDocument() {
  const elements = [...htmlSource.matchAll(/<([a-z][\w-]*)\b([^>]*)>([^<]*)/gi)].map(match => {
    const attributes = {};
    for (const attribute of match[2].matchAll(/([\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      attributes[attribute[1]] = attribute[2] ?? attribute[3] ?? attribute[4] ?? '';
    }
    return new MockElement(match[1], attributes, match[3]);
  });
  const ids = new Map(elements.filter(element => element.id).map(element => [element.id, element]));
  return {
    getElementById: id => ids.get(id) || null,
    createElement: tag => new MockElement(tag, {}),
    querySelectorAll: selector => {
      const attribute = /^\[([^\]]+)\]$/.exec(selector);
      if (attribute) return elements.filter(element => element.hasAttribute(attribute[1]));
      throw new Error(`Unimplemented DOM selector in test harness: ${selector}`);
    }
  };
}

async function flush() {
  // No wall-clock sleeps: drain only the finite mocked-fetch promise chain.
  for (let index = 0; index < 30; index += 1) await Promise.resolve();
}

async function harness(initial = snapshot(), {bootstrapError = null} = {}) {
  const document = mockDocument();
  const requests = [], queues = new Map(), intervals = new Map(), timeouts = new Map(), windowListeners = new Map();
  const location = {hash: '#overview'};
  let timerId = 0;
  let defaultDiagnostics = initial;
  let battleActive = initial.active_run;
  let campaignState = 'READY';
  const topology = {topology: {case_name: 'case14', nodes: [{id: 'plc1'}, {id: 'hub'}], links: []}, visual: {nodes: [], edges: []}, pyvis_html: '<html>PyVis case14</html>'};
  const response = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => structuredClone(body)});
  const enqueue = (url, body, {method = 'GET', status = 200, pending = null, error = null} = {}) => {
    const key = `${method} ${url}`;
    const queue = queues.get(key) || [];
    queue.push({body, status, pending, error});
    queues.set(key, queue);
  };
  const fetch = async (url, options = {}) => {
    const method = options.method || 'GET';
    requests.push({url, method, options: {...options}});
    const entry = queues.get(`${method} ${url}`)?.shift();
    if (entry) {
      if (entry.error) throw entry.error;
      if (entry.pending) return entry.pending.promise;
      return response(entry.body, entry.status);
    }
    if (method !== 'GET') throw new Error(`Unexpected mocked POST: ${url}`);
    if (url === diagnosticsPath) return response(defaultDiagnostics);
    // The dashboard fixture allows an old implementation to reach an assertion
    // instead of failing inside bootstrap. Tests still require diagnostics GETs.
    if (url === '/api/dashboard') return response({system: defaultDiagnostics, active_run: defaultDiagnostics.active_run});
    if (url === '/api/topology') return response(topology);
    if (url === '/api/network-configuration') return response({node_count: 2, edge_count: 0, case_name: 'case14', selected_case: 'case14',
      available_topologies: [{case_name: 'case14', name: 'IEEE 14 Bus'}, {case_name: 'case30', name: 'IEEE 30 Bus'}],
      topology_version: 'topology-fixture', node_types: {plc: 1, hub: 1}});
    if (url.startsWith('/api/live-battle?limit=')) return response({...topology,
      pyvis_html: url.includes('visual_signature=fixture-visual') ? null : topology.pyvis_html,
      visual_signature: 'fixture-visual', active_run: battleActive,
      display_identity: defaultDiagnostics.display_identity, campaign_display: {},
      network_events: [], security_events: [], background_network: [], network_event_count: 0, security_event_count: 0, limit: 100, campaign: null});
    if (url.startsWith('/api/report-summary')) return response({run_id:battleActive?.run?.run_id,scenario_id:battleActive?.run?.scenario_id,
      finding_summary:{total_findings:0,detected:0,failed:0,timeout:0,techniques:0,targets:0}});
    if (url === '/api/campaign/status') return response({state: campaignState, watcher: defaultDiagnostics.watcher.state, current_step: 0});
    throw new Error(`Unexpected mocked GET: ${url}`);
  };
  const window = {
    addEventListener: (name, callback) => windowListeners.set(name, callback),
    setInterval: (callback, delay) => { const id = ++timerId; intervals.set(id, {callback, delay}); return id; },
    clearInterval: id => intervals.delete(id),
    setTimeout: (callback, delay) => { const id = ++timerId; timeouts.set(id, {callback, delay}); return id; },
    clearTimeout: id => timeouts.delete(id)
  };
  const context = vm.createContext({document, window, location, fetch, console,
    setTimeout: window.setTimeout, clearTimeout: window.clearTimeout,
    setInterval: window.setInterval, clearInterval: window.clearInterval});
  if (bootstrapError) enqueue(diagnosticsPath, null, {error: bootstrapError});
  vm.runInContext(appSource, context, {filename: 'gui/web/app.js'});
  await flush();
  return {
    requests, enqueue, response, intervals, location,
    element: id => {
      const element = document.getElementById(id);
      assert.ok(element, `Expected DOM element #${id}`);
      return element;
    },
    call: (name, ...args) => {
      assert.equal(typeof context[name], 'function', `Expected app function ${name}`);
      return context[name](...args);
    },
    refresh: () => (context.refreshRuntimeState || context.loadStatus)(),
    click: id => document.getElementById(id).dispatch('click'),
    navigate: hash => { location.hash = hash; return windowListeners.get('hashchange')(); },
    setDiagnostics: value => { defaultDiagnostics = value; },
    setBattle: (active, state = 'READY') => { battleActive = active; campaignState = state; },
    tickIntervals: async () => { for (const {callback} of intervals.values()) await callback(); await flush(); }
  };
}

function countRequests(env, method, url) {
  return env.requests.filter(request => request.method === method && (!url || request.url === url)).length;
}

function assertRuntimeControls(env, startEnabled, stopEnabled, watcherEnabled) {
  for (const [id, enabled] of [['core-start', startEnabled], ['core-stop', stopEnabled], ['watcher-start', watcherEnabled]]) {
    assert.equal(env.element(id).disabled, !enabled, `${id} should be ${enabled ? 'enabled' : 'disabled'}`);
  }
}

function assertCampaignControls(env, {coreReady, campaignReady}) {
  for (const id of campaignControlIds) {
    const enabled = ['campaign-next', 'campaign-run'].includes(id) ? campaignReady : coreReady;
    assert.equal(env.element(id).disabled, !enabled, `${id} must preserve its existing prerequisite gate`);
  }
}

function styleRules(selectorPattern) {
  return [...cssSource.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
    .filter(match => selectorPattern.test(match[1])).map(match => match[2]).join(';');
}

async function testStoppedAndStyles() {
  const env = await harness(snapshot());
  assert.equal(env.element('core-status').textContent, 'Assessment Environment — Ready');
  assert.equal(env.element('overview-core').textContent, 'Ready');
  assertRuntimeControls(env, true, false, false);
  assert.equal(env.element('core-gui').disabled, true, 'CORE GUI requires a running owned session');
  assert.ok(countRequests(env, 'GET', diagnosticsPath) >= 1, 'bootstrap must obtain a unified runtime diagnostics snapshot');
  assert.equal(countRequests(env, 'GET', '/api/dashboard'), 0, 'header and Runtime controls must use the same read endpoint');
  assert.equal(countRequests(env, 'POST'), 0, 'rendering STOPPED must never auto-start CORE');
  const unavailable = {...snapshot(), core: {state: 'STOPPED', daemon: 'UNAVAILABLE', session_id: null}};
  env.setDiagnostics(unavailable);
  await env.refresh();
  assertRuntimeControls(env, false, false, false);
  const enabledStyle = styleRules(/button:(?:enabled|not\(\s*:disabled\s*\))/);
  const disabledStyle = styleRules(/button:disabled/);
  assert.ok(enabledStyle, 'enabled buttons need an explicit style');
  assert.ok(disabledStyle, 'disabled buttons need an explicit style');
  assert.notEqual(enabledStyle.replace(/\s/g, ''), disabledStyle.replace(/\s/g, ''), 'enabled and disabled controls must look different');
  assert.match(enabledStyle, /cursor\s*:\s*pointer/, 'enabled controls must advertise clickability');
}

async function testRuntimeSnapshot() {
  const env = await harness(snapshot());
  const running = snapshot('RUNTIME', 'STOPPED', 'generation-B');
  env.setDiagnostics(running);
  const before = countRequests(env, 'GET', diagnosticsPath);
  await env.call('loadRuntime');
  assert.equal(countRequests(env, 'GET', diagnosticsPath), before + 1, 'opening Runtime uses one unified snapshot');
  assert.equal(env.element('core-status').textContent, 'Assessment Environment — Running');
  assert.equal(env.element('overview-core').textContent, 'Running');
  assert.equal(env.element('runtime-session').textContent, 'CORE Session 1');
  assert.equal(env.element('runtime-generation').textContent, 'Runtime Generation 1');
  assert.equal(env.element('generation-status').textContent, 'Runtime Generation 1');
  assert.equal(env.element('run-status').textContent, 'Assessment 1 — in progress');
  assert.equal(env.element('runtime-watcher').textContent, 'STOPPED');
  assertRuntimeControls(env, false, true, true);
  assert.equal(env.element('core-gui').disabled, false, 'CORE GUI is available for the running owned session');
  assert.equal(countRequests(env, 'POST'), 0);
  for (const watcher of ['IDLE', 'BUSY']) {
    env.setDiagnostics(snapshot('RUNTIME', watcher, 'generation-B'));
    await env.refresh();
    assertRuntimeControls(env, false, true, false);
  }
}

async function testStartConflictAndPending() {
  const env = await harness(snapshot());
  env.location.hash = '#runtime';
  const pending = deferred();
  env.enqueue('/api/runtime/start', null, {method: 'POST', pending});
  const firstClick = env.click('core-start');
  await flush();
  assert.equal(countRequests(env, 'POST', '/api/runtime/start'), 1);
  assert.equal(env.element('core-start').disabled, true, 'pending Start must disable the button');
  assert.equal(env.element('core-start').getAttribute('aria-busy'), 'true', 'pending Start must expose aria-busy');
  // A programmatic event can bypass native disabled-button hit testing. The
  // handler must still reject it, including during a status refresh.
  await env.click('core-start');
  await env.refresh();
  await env.click('core-start');
  assert.equal(countRequests(env, 'POST', '/api/runtime/start'), 1, 'pending Start must not submit a duplicate');
  assert.equal(env.element('core-start').getAttribute('aria-busy'), 'true');
  const running = snapshot('RUNTIME', 'IDLE', 'generation-conflict');
  env.setDiagnostics(running);
  const beforeRefresh = countRequests(env, 'GET', diagnosticsPath);
  const backendMessage = 'An ASCEND-owned CORE session is already active.';
  pending.resolve(env.response({ok: false, error: {code: 'core_already_running', message: backendMessage}}, 409));
  await firstClick;
  await flush();
  assert.ok(countRequests(env, 'GET', diagnosticsPath) > beforeRefresh, 'a rejected POST must refresh runtime diagnostics');
  assert.equal(env.element('runtime-action-status').textContent, backendMessage, 'refresh must preserve the backend conflict message');
  assert.equal(env.element('core-status').textContent, 'Assessment Environment — Running');
  assertRuntimeControls(env, false, true, false);
  assert.notEqual(env.element('core-start').getAttribute('aria-busy'), 'true', 'settled Start clears aria-busy');
  assert.equal(countRequests(env, 'POST'), 1, 'a backend conflict must not trigger retries or automatic controls');
  const request = env.requests.find(item => item.method === 'POST');
  assert.deepEqual(JSON.parse(request.options.body), {}, 'Start delegates XML selection to the existing backend');

  const successful = await harness(snapshot());
  successful.location.hash = '#runtime';
  const acceptedPost = deferred(), confirmingRefresh = deferred();
  successful.enqueue('/api/runtime/start', null, {method: 'POST', pending: acceptedPost});
  successful.enqueue(diagnosticsPath, null, {pending: confirmingRefresh});
  const successClick = successful.click('core-start');
  const beforeSuccessRefresh = countRequests(successful, 'GET', diagnosticsPath);
  acceptedPost.resolve(successful.response({ok: true, state: 'RUNTIME', session_id: 7}, 202));
  await flush();
  assert.equal(countRequests(successful, 'GET', diagnosticsPath), beforeSuccessRefresh + 1, 'a successful POST must refresh diagnostics');
  assert.equal(successful.element('core-start').getAttribute('aria-busy'), 'true', 'Start remains busy until the confirming refresh finishes');
  await successful.click('core-start');
  assert.equal(countRequests(successful, 'POST'), 1, 'confirmation refresh must not permit a duplicate Start');
  confirmingRefresh.resolve(successful.response(snapshot('RUNTIME', 'STOPPED', 'generation-success')));
  await successClick;
  assert.equal(successful.element('runtime-action-status').textContent, 'RUNTIME', 'refresh must retain the successful POST outcome');
  assertRuntimeControls(successful, false, true, true);
  assert.notEqual(successful.element('core-start').getAttribute('aria-busy'), 'true');

  const superseded = await harness(snapshot());
  superseded.location.hash = '#runtime';
  const conflictedPost = deferred(), oldConfirmation = deferred(), newestSnapshot = deferred();
  superseded.enqueue('/api/runtime/start', null, {method: 'POST', pending: conflictedPost});
  superseded.enqueue(diagnosticsPath, null, {pending: oldConfirmation});
  const conflictedClick = superseded.click('core-start');
  const beforeConflictRefresh = countRequests(superseded, 'GET', diagnosticsPath);
  conflictedPost.resolve(superseded.response({ok: false, error: {code: 'core_already_running', message: backendMessage}}, 409));
  await flush();
  assert.equal(countRequests(superseded, 'GET', diagnosticsPath), beforeConflictRefresh + 1, 'the conflict confirmation GET must be in flight');
  superseded.enqueue(diagnosticsPath, null, {pending: newestSnapshot});
  const newestRefresh = superseded.refresh();
  await flush();
  oldConfirmation.resolve(superseded.response(snapshot()));
  await conflictedClick;
  await flush();
  assert.equal(superseded.element('core-start').disabled, true, 'a superseded confirmation must not re-enable Start while the newest snapshot is pending');
  assert.equal(superseded.element('runtime-action-status').textContent, backendMessage);
  assert.equal(countRequests(superseded, 'POST'), 1, 'a superseded confirmation must never retry Start');
  newestSnapshot.resolve(superseded.response(snapshot('RUNTIME', 'IDLE', 'generation-confirmation-winner')));
  await newestRefresh;
  assert.equal(superseded.element('core-status').textContent, 'Assessment Environment — Running');
  assert.equal(superseded.element('runtime-action-status').textContent, backendMessage, 'the newest snapshot must preserve the original 409 message');
  assertRuntimeControls(superseded, false, true, false);
  assert.equal(countRequests(superseded, 'POST'), 1);
}

async function testStaleRefresh() {
  const env = await harness(snapshot('RUNTIME', 'IDLE', 'generation-last-known'));
  const retained = Object.fromEntries(['core-status', 'overview-core', 'runtime-session', 'runtime-generation', 'generation-status', 'runtime-watcher']
    .map(id => [id, env.element(id).textContent]));
  env.enqueue(diagnosticsPath, null, {error: new Error('fixture connection unavailable')});
  await env.refresh();
  for (const [id, value] of Object.entries(retained)) assert.equal(env.element(id).textContent, value, `${id} must retain its last known value`);
  assert.match(env.element('runtime-refresh-status').textContent, /stale|failed|unavailable|error/i, 'failed refresh must be visible');
  assertRuntimeControls(env, false, false, false);
  assert.equal(countRequests(env, 'POST'), 0, 'a failed GET must never send a control request');
  await env.refresh();
  assertRuntimeControls(env, false, true, false);
  assert.doesNotMatch(env.element('runtime-refresh-status').textContent, /stale|failed/i, 'a successful snapshot clears stale feedback');

  const initiallyUnavailable = await harness(snapshot(), {bootstrapError: new Error('initial connection unavailable')});
  assert.equal(initiallyUnavailable.element('core-status').textContent, 'Assessment Environment — Unavailable', 'initial failure must never fabricate STOPPED');
  assert.match(initiallyUnavailable.element('runtime-refresh-status').textContent, /stale|failed|unavailable|error/i);
  assertRuntimeControls(initiallyUnavailable, false, false, false);
  assert.equal(countRequests(initiallyUnavailable, 'POST'), 0);
}

async function testOutOfOrderRefreshes() {
  const env = await harness(snapshot());
  const older = deferred(), newer = deferred();
  env.enqueue(diagnosticsPath, null, {pending: older});
  env.enqueue(diagnosticsPath, null, {pending: newer});
  const oldRefresh = env.refresh();
  const newRefresh = env.refresh();
  newer.resolve(env.response(snapshot('RUNTIME', 'IDLE', 'generation-new')));
  await newRefresh;
  older.resolve(env.response(snapshot()));
  await oldRefresh;
  assert.equal(env.element('core-status').textContent, 'Assessment Environment — Running', 'older response must not overwrite the header');
  assert.equal(env.element('runtime-generation').textContent, 'Runtime Generation 1', 'older response must not overwrite Runtime diagnostics');
  assertRuntimeControls(env, false, true, false);

  const oldFailure = deferred(), latest = deferred();
  env.enqueue(diagnosticsPath, null, {pending: oldFailure});
  env.enqueue(diagnosticsPath, null, {pending: latest});
  const failureRefresh = env.refresh();
  const latestRefresh = env.refresh();
  latest.resolve(env.response(snapshot('RUNTIME', 'STOPPED', 'generation-newest')));
  await latestRefresh;
  oldFailure.reject(new Error('obsolete connection failure'));
  await failureRefresh;
  assert.equal(env.element('runtime-generation').textContent, 'Runtime Generation 1');
  assertRuntimeControls(env, false, true, true);
  assert.doesNotMatch(env.element('runtime-refresh-status').textContent, /stale|failed/i, 'obsolete failure must not invalidate the latest snapshot');
  assert.equal(countRequests(env, 'POST'), 0);
}

async function testCanonicalXmlContract() {
  assert.doesNotMatch(htmlSource, /\bid\s*=\s*["']core-xml["']/i, 'the unused editable XML path must be removed');
  assert.doesNotMatch(appSource, /byId\(["']core-xml["']\)/, 'frontend must not read a removed XML field');
  assert.doesNotMatch(htmlSource, /core_topology\.xml/, 'backend filenames should not be prominent in the professional UI');
  assert.doesNotMatch(htmlSource, /data\/core-runtime\/campaign\.xml/, 'the misleading unused XML default must be removed');
  const campaignSource = fs.readFileSync(path.join(root, 'gui/campaign.py'), 'utf8');
  const serverSource = fs.readFileSync(path.join(root, 'gui/server.py'), 'utf8');
  assert.match(campaignSource, /generate_core_xml\(output_path=str\(ROOT \/ "core_topology\.xml"\), topology=topology\)/,
    'CORE must generate the selected canonical model at the existing output path');
  assert.match(serverSource, /self\.path == "\/api\/runtime\/start":\s*payload, status = CAMPAIGNS\.start_core\(\)/,
    'runtime Start must keep using the existing ownership-aware backend launch');
}

async function testProfessionalOverviewUsesExistingData() {
  const system = snapshot('RUNTIME','IDLE','generation-professional');
  system.active_run.run.campaign_request = {state:'COMPLETED'}; // only a step completion
  const original = JSON.stringify(system);
  const env = await harness(system);
  const events = [
    {event_type:'attack_finished',target_node:'plc14',mitre_technique:'T0881',timestamp:'2026-10-06T15:11:00Z',
      correlation_id:'hidden-correlation',evidence:{step_name:'service_stop',return_status:'FAILED'}},
    {event_type:'detection',target_node:'plc3',mitre_technique:'T0835',timestamp:'2026-10-06T15:12:00Z',
      evidence:{step_name:'manipulate_io_image',detection_method:'ml'}}
  ];
  const eventOriginal = JSON.stringify(events);
  const reportUrl = '/api/report-summary?scenario_id=scenario-fixture&run_id=run-generation-professional';
  env.enqueue('/api/live-battle?limit=10', {active_run:system.active_run,display_identity:system.display_identity,security_events:events});
  env.enqueue(reportUrl, {run_id:system.active_run.run.run_id,scenario_id:'scenario-fixture',
    finding_summary:{total_findings:19,detected:11,failed:7,timeout:1,techniques:8,targets:14},
    assessment_overview:{severity_distribution:{Critical:0,High:8,Medium:5,Low:6,Informational:0},
      attacks:[{finding_id:'ASCEND-PG-001',attack_step:'Attack Step 1',attack_event:'Attack Event 1',title:'Manipulate I/O Image',
        description:'Attempts to alter information exchanged with an industrial controller.',technique_id:'T0835',target:'plc3',
        result:'SUCCESS',detected:true,detection_method:'ml',severity:'High',finding_dvs:15}],
      defense:{detected:11,total:19,detection_rate:11/19,methods:{ml:6,suricata:3,both:2,none:8}},
      dvs:{finding_available:true,finding_assessed:19,finding_total:19,campaign_available:true,campaign_score:64.25,campaign_rating:'MODERATE'}}});
  await env.call('loadOverview');
  assert.equal(env.element('overview-core').textContent,'Running');
  assert.equal(env.element('overview-watcher').textContent,'Ready');
  assert.equal(env.element('overview-run').textContent,'Assessment 1');
  assert.equal(env.element('overview-session').textContent,'CORE Session 1');
  assert.equal(env.element('overview-generation').textContent,'Runtime Generation 1');
  assert.equal(env.element('overview-total-findings').textContent,19);
  assert.equal(env.element('overview-total-detected').textContent,11);
  assert.equal(env.element('overview-total-failed').textContent,7);
  assert.equal(env.element('overview-total-timeout').textContent,1);
  assert.equal(env.element('overview-finding-dvs').textContent,'Available for 19 findings');
  assert.equal(env.element('overview-campaign-dvs').textContent,'64.3 / 100 (MODERATE)');
  assert.equal(env.element('overview-severity-total').textContent,19);
  assert.match(env.element('overview-severity-legend').innerHTML,/High.*8.*Medium.*5.*Low.*6/);
  assert.match(env.element('overview-attack-catalogue').innerHTML,/Manipulate I\/O Image.*Attack Step 1.*T0835.*PLC3.*15\.0 \/ 100/s);
  assert.equal(env.element('overview-defense-detected').textContent,'11 of 19');
  assert.equal(env.element('overview-defense-rate').textContent,'57.9%');
  assert.match(env.element('overview-defense-methods').textContent,/ML \(6\).*Network monitoring \(3\).*Combined monitoring \(2\)/);
  assert.equal(env.element('overview-topology-name').textContent,'IEEE-14');
  assert.match(env.element('overview-topology-summary').textContent,/devices · .* connections/);
  const activity = env.element('overview-activity').innerHTML;
  for (const value of ['Detection','PLC3','T0835','Detected by ML','PLC14','Failed']) assert.ok(activity.includes(value),value);
  assert.doesNotMatch(activity,/hidden-correlation|evidence|return_status|\{"/);
  assert.ok(activity.indexOf('PLC3') < activity.indexOf('PLC14'),'newest activity first');
  for (const id of ['core-status','watcher-status','run-status','overview-run','overview-core','overview-watcher']) {
    assert.doesNotMatch(env.element(id).textContent,/run-|generation-|RUNTIME|WATCHER|DAEMON|OWNERSHIP/);
  }
  assert.match(env.element('overview-technical-data').innerHTML,/Internal assessment ID.*run-generation-professional/);
  assert.match(env.element('overview-technical-data').innerHTML,/Internal generation ID.*generation-professional/);
  assert.equal(env.element('generation-status').textContent,'Runtime Generation 1');
  const disclosure = htmlSource.match(/<details[^>]*id="overview-technical"[^>]*>(.*?)<\/details>/s);
  assert.ok(disclosure); assert.doesNotMatch(disclosure[0].split('>')[0],/\bopen\b/);
  assert.match(disclosure[1],/Technical details|Runtime generation/);
  assert.doesNotMatch(htmlSource,/Bounded read model|No event history is scanned|CORE ownership marker/);
  assert.match(cssSource,/\.technical-details strong\{[^}]*white-space:nowrap/);
  assert.equal(JSON.stringify(system),original);
  assert.equal(JSON.stringify(events),eventOriginal);
  assert.equal(countRequests(env,'POST'),0);
  assert.equal(countRequests(env,'GET','/api/campaign/status'),0,'overview must not invoke the result-consuming campaign status path');
  const busy = await harness(snapshot('RUNTIME','BUSY','processing'));
  assert.equal(busy.element('overview-watcher').textContent,'Active');
  const unavailable = snapshot('UNKNOWN','UNKNOWN'); unavailable.core.daemon = 'UNAVAILABLE';
  const offline = await harness(unavailable);
  assert.equal(offline.element('overview-core').textContent,'Unavailable');
  assert.equal(offline.element('overview-watcher').textContent,'Unavailable');
  const stopped = await harness(snapshot());
  assert.equal(stopped.element('overview-run').textContent,'No assessment running');
  assert.match(stopped.element('overview-activity').innerHTML,/No security activity yet/);
  const finished = {...system.active_run,run:{...system.active_run.run,status:'COMPLETED'}};
  assert.equal(await env.call('assessmentLabel',finished),'Assessment completed');
  const liveReads = countRequests(stopped,'GET','/api/live-battle?limit=10');
  for(let tick=0;tick<5;tick++) await stopped.tickIntervals();
  assert.equal(countRequests(stopped,'GET','/api/live-battle?limit=10'),liveReads+1,'overview refreshes its existing read-only stream every five ticks');
  assert.equal(countRequests(stopped,'POST'),0);
}

async function testOverviewIntroductionAndEmptyState() {
  for (const phrase of [
    'Cybersecurity Assessment for Power Grid Systems',
    'ASCEND-PG safely simulates cyber attacks against a power-grid environment',
    'WHAT ARE WE PROTECTING?', 'Power Grid', 'HOW IS IT MONITORED?', 'PLC &amp; SCADA', 'Cyber Attacks', 'Security Detection', 'Security Assessment',
    'ATTACK LIFECYCLE', 'Attacker', 'Target', 'Network Activity', 'Detection', 'Result', 'ATTACKS USED IN THE ASSESSMENT', 'DEFENSE MONITORING', 'Technical concepts'
  ]) assert.match(htmlSource, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const concept of ['Programmable Logic Controller', 'Supervisory Control and Data Acquisition', 'MITRE ATT&amp;CK', 'PPO / AI', 'Suricata', 'Defense Vulnerability Score', 'CORE']) assert.match(htmlSource, new RegExp(concept));
  assert.match(htmlSource, /href="#runtime">Start Assessment/);
  assert.match(htmlSource, /href="#grid">Explore the System/);
  assert.match(htmlSource, /class="hero-flow"[\s\S]*?Power Grid[\s\S]*?Monitoring[\s\S]*?Cyber Attacks[\s\S]*?Defense \/ Detection[\s\S]*?Evidence[\s\S]*?Security Assessment/);
  const env = await harness(snapshot());
  assert.equal(env.element('overview-results-assessment').textContent, 'No assessment results available');
  assert.equal(env.element('overview-total-findings').textContent, 'Not available');
  assert.equal(env.element('overview-finding-dvs').textContent, 'Not available');
  assert.equal(env.element('overview-campaign-dvs').textContent, 'Not available');
  assert.match(env.element('overview-attack-catalogue').innerHTML, /No completed attacks yet/);
  assert.equal(env.element('overview-severity-chart').getAttribute('aria-label'), 'No attack severity data available');
  assert.equal(countRequests(env, 'POST'), 0);
}

async function testOverviewCustomTopologyPreview() {
  const env = await harness(snapshot());
  const custom = {topology:{case_name:'custom_laboratory_network'},
    visual:{nodes:Array.from({length:8},(_,index)=>({id:`plc${index+1}`})),edges:Array.from({length:9},(_,index)=>({from:index,to:index+1}))},
    visual_signature:'custom-overview',pyvis_html:'<html>Custom Laboratory Network</html>'};
  env.enqueue('/api/topology', custom);
  env.enqueue('/api/live-battle?limit=10', {active_run:null,display_identity:{},security_events:[]});
  await env.call('loadOverview');
  assert.equal(env.element('overview-topology-name').textContent, 'Custom Laboratory Network');
  assert.equal(env.element('overview-topology-summary').textContent, '8 devices · 9 connections');
  assert.match(env.element('overview-topology').children[0].srcdoc, /Custom Laboratory Network/);
  assert.equal(countRequests(env, 'POST'), 0);
}

async function testOtherControlGating() {
  const env = await harness(snapshot('RUNTIME', 'IDLE', 'generation-campaign'));
  await env.call('loadBattle');
  assertCampaignControls(env, {coreReady: true, campaignReady: true});
  env.setBattle(snapshot('RUNTIME', 'IDLE', 'generation-campaign').active_run, 'RUNNING');
  await env.call('loadBattle');
  assertCampaignControls(env, {coreReady: true, campaignReady: false});
  for (const watcher of ['BUSY', 'STOPPED']) {
    env.setDiagnostics(snapshot('RUNTIME', watcher, 'generation-campaign'));
    await env.refresh();
    await env.call('loadBattle');
    assertCampaignControls(env, {coreReady: false, campaignReady: false});
  }
  env.setDiagnostics(snapshot('RUNTIME', 'IDLE', 'generation-campaign'));
  env.setBattle(null, 'READY');
  await env.refresh();
  await env.call('loadBattle');
  assertCampaignControls(env, {coreReady: false, campaignReady: false});
  env.setDiagnostics(snapshot());
  await env.refresh();
  await env.call('loadBattle');
  assertRuntimeControls(env, true, false, false);
  assertCampaignControls(env, {coreReady: false, campaignReady: false});
  assert.equal(countRequests(env, 'POST'), 0, 'checking prerequisites must remain read-only');
}

async function testObsoleteRouteFailure() {
  for (const oldRoute of ['overview', 'network']) {
    for (const navigateBack of [false, true]) {
      const env = await harness(snapshot());
      const pending = deferred();
      const delayedPath = oldRoute === 'overview' ? '/api/topology' : '/api/network-configuration';
      const before = countRequests(env, 'GET', delayedPath);
      env.enqueue(delayedPath, null, {pending});
      const oldNavigation = env.navigate(`#${oldRoute}`);
      await flush();
      assert.equal(countRequests(env, 'GET', delayedPath), before + 1, 'the obsolete route GET must already be in flight');
      env.setDiagnostics(snapshot('RUNTIME', 'IDLE', 'generation-route-current'));
      await env.navigate('#runtime');
      if (navigateBack) await env.navigate(`#${oldRoute}`);
      const notice = env.element('runtime-refresh-status');
      const currentNotice = notice.textContent, currentState = notice.dataset.state;
      assert.equal(env.element('core-status').textContent, 'Assessment Environment — Running');
      assert.equal(currentState, 'current');
      pending.reject(new Error(`obsolete ${oldRoute} fixture failure`));
      await oldNavigation;
      await flush();
      assert.equal(notice.textContent, currentNotice, 'an obsolete route failure must not overwrite the fresh global notice');
      assert.equal(notice.dataset.state, currentState, 'an obsolete route failure must not mark current diagnostics stale');
      assert.equal(env.element('runtime-generation').textContent, 'Runtime Generation 1');
      assertRuntimeControls(env, false, true, false);
      assert.equal(countRequests(env, 'POST'), 0, 'navigation and obsolete route errors must remain read-only');
    }
  }
}

function assertWatcherReady(env) {
  assert.equal(env.element('watcher-status').textContent, 'Monitoring — Ready');
  assert.equal(env.element('runtime-watcher').textContent, 'IDLE');
  assert.equal(env.element('runtime-action-status').textContent, 'Security monitoring is ready.', 'matching diagnostics must replace the transient acknowledgement with verified readiness');
  for (const id of ['watcher-status', 'runtime-watcher', 'runtime-action-status']) {
    assert.doesNotMatch(env.element(id).textContent, /UNVERIFIED/, `${id} must no longer display the transient acknowledgement`);
  }
}

async function testWatcherImmediateReadiness() {
  const env = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-immediate'));
  env.location.hash = '#runtime';
  env.setDiagnostics(snapshot('RUNTIME', 'IDLE', 'generation-watcher-immediate'));
  env.enqueue('/api/runtime/watcher/start', {ok: true, session_id: 7, watcher: 'UNVERIFIED'}, {method: 'POST', status: 202});
  await env.click('watcher-start');
  assertWatcherReady(env);
  assertRuntimeControls(env, false, true, false);
  const reads = countRequests(env, 'GET', diagnosticsPath);
  for (let tick = 0; tick < 3; tick += 1) await env.tickIntervals();
  assert.equal(countRequests(env, 'GET', diagnosticsPath), reads, 'verified readiness must stop the temporary diagnostic observation');
  assert.equal(countRequests(env, 'POST'), 1);

  const busy = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-busy'));
  busy.location.hash = '#runtime';
  busy.setDiagnostics(snapshot('RUNTIME', 'BUSY', 'generation-watcher-busy'));
  busy.enqueue('/api/runtime/watcher/start', {ok: true, session_id: 7, watcher: 'UNVERIFIED'}, {method: 'POST', status: 202});
  await busy.click('watcher-start');
  assert.equal(busy.element('runtime-watcher').textContent, 'BUSY');
  assert.equal(busy.element('runtime-action-status').textContent, 'Security monitoring is active.');
  assertRuntimeControls(busy, false, true, false);
  assert.equal(countRequests(busy, 'POST'), 1);
}

async function testWatcherDeferredReadinessAndDuplicates() {
  const env = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-later'));
  env.location.hash = '#runtime';
  env.setDiagnostics(snapshot('RUNTIME', 'UNVERIFIED', 'generation-watcher-later'));
  const post = deferred();
  env.enqueue('/api/runtime/watcher/start', null, {method: 'POST', pending: post});
  const firstClick = env.click('watcher-start');
  await flush();
  assert.equal(env.element('watcher-start').disabled, true, 'a pending watcher POST must disable its button');
  await env.click('watcher-start');
  assert.equal(countRequests(env, 'POST'), 1, 'pending watcher POST must reject duplicate programmatic clicks');
  post.resolve(env.response({ok: true, session_id: 7, watcher: 'UNVERIFIED'}, 202));
  await firstClick;
  assert.equal(env.element('runtime-watcher').textContent, 'UNVERIFIED');
  assert.match(env.element('runtime-action-status').textContent, /waiting|pending|verif|starting/i);
  assertRuntimeControls(env, false, true, false);
  await env.click('watcher-start');
  assert.equal(countRequests(env, 'POST'), 1, 'active readiness observation must reject duplicate watcher POSTs');
  const beforeTick = env.requests.length;
  await env.tickIntervals();
  assert.deepEqual(env.requests.slice(beforeTick).map(request => [request.method, request.url]), [['GET', diagnosticsPath]],
    'outside Battle, the existing timer must observe readiness with one diagnostics GET only');
  env.setDiagnostics(snapshot('RUNTIME', 'IDLE', 'generation-watcher-later'));
  await env.tickIntervals();
  assertWatcherReady(env);
  assertRuntimeControls(env, false, true, false);
  const reads = countRequests(env, 'GET', diagnosticsPath);
  for (let tick = 0; tick < 3; tick += 1) await env.tickIntervals();
  assert.equal(countRequests(env, 'GET', diagnosticsPath), reads, 'later readiness must stop observation');
  assert.equal(countRequests(env, 'POST'), 1, 'readiness observation must never retry the watcher POST');

  const superseded = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-superseded'));
  superseded.location.hash = '#runtime';
  const olderConfirmation = deferred();
  superseded.enqueue('/api/runtime/watcher/start', {ok: true, session_id: 7, watcher: 'UNVERIFIED'}, {method: 'POST', status: 202});
  superseded.enqueue(diagnosticsPath, null, {pending: olderConfirmation});
  const pendingClick = superseded.click('watcher-start');
  await flush();
  superseded.enqueue(diagnosticsPath, snapshot('RUNTIME', 'IDLE', 'generation-watcher-superseded'));
  await superseded.refresh();
  assertWatcherReady(superseded);
  olderConfirmation.resolve(superseded.response(snapshot('RUNTIME', 'UNVERIFIED', 'generation-watcher-superseded')));
  await pendingClick;
  assertWatcherReady(superseded);
  assert.equal(countRequests(superseded, 'POST'), 1, 'an obsolete confirmation must not repeat the watcher POST');
  const supersededReads = countRequests(superseded, 'GET', diagnosticsPath);
  await superseded.tickIntervals();
  assert.equal(countRequests(superseded, 'GET', diagnosticsPath), supersededReads, 'an obsolete UNVERIFIED response must not restart readiness observation');
}

async function testWatcherRefreshFailureAndPostError() {
  const env = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-failure'));
  env.location.hash = '#runtime';
  env.enqueue('/api/runtime/watcher/start', {ok: true, session_id: 7, watcher: 'UNVERIFIED'}, {method: 'POST', status: 202});
  env.enqueue(diagnosticsPath, null, {error: new Error('watcher confirmation fixture unavailable')});
  await env.click('watcher-start');
  assert.match(env.element('runtime-refresh-status').textContent, /stale|failed|unavailable/i);
  assert.doesNotMatch(env.element('runtime-action-status').textContent, /\bIDLE\b|verified and ready/i, 'a failed confirmation GET must not fabricate readiness');
  assertRuntimeControls(env, false, false, false);
  const requests = env.requests.length;
  for (let tick = 0; tick < 4; tick += 1) await env.tickIntervals();
  assert.equal(env.requests.length, requests, 'a failed readiness GET must stop observation without GET or POST retries');
  assert.equal(countRequests(env, 'POST'), 1);
  env.setDiagnostics(snapshot('RUNTIME', 'IDLE', 'generation-watcher-failure'));
  await env.refresh();
  assertWatcherReady(env);
  assertRuntimeControls(env, false, true, false);
  assert.equal(countRequests(env, 'POST'), 1, 'a later explicit refresh can reconcile readiness without retrying the POST');

  const denied = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-denied'));
  denied.location.hash = '#runtime';
  denied.setDiagnostics(snapshot('RUNTIME', 'IDLE', 'generation-watcher-denied'));
  const backendMessage = 'Watcher startup denied by the ownership check.';
  denied.enqueue('/api/runtime/watcher/start', {ok: false, error: {code: 'watcher_denied', message: backendMessage}}, {method: 'POST', status: 409});
  await denied.click('watcher-start');
  assert.equal(denied.element('runtime-action-status').textContent, backendMessage, 'a watcher POST error must remain visible after the diagnostics refresh');
  const deniedRequests = denied.requests.length;
  for (let tick = 0; tick < 3; tick += 1) await denied.tickIntervals();
  assert.equal(denied.requests.length, deniedRequests, 'a rejected watcher POST must not start readiness observation');
  assert.equal(countRequests(denied, 'POST'), 1);
}

async function testWatcherIdentityAndBoundedObservation() {
  for (const mismatch of ['post-session', 'diagnostic-session', 'generation']) {
    const env = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-owner'));
    env.location.hash = '#runtime';
    const current = snapshot('RUNTIME', 'IDLE', mismatch === 'generation' ? 'generation-other-owner' : 'generation-watcher-owner');
    if (mismatch !== 'generation') current.core.session_id = 99;
    env.setDiagnostics(current);
    env.enqueue('/api/runtime/watcher/start', {ok: true, session_id: mismatch === 'post-session' ? 99 : 7, watcher: 'UNVERIFIED'}, {method: 'POST', status: 202});
    await env.click('watcher-start');
    assert.match(env.element('runtime-action-status').textContent, /not(?: be)? verified|changed|mismatch|unverif/i,
      `${mismatch} must not be declared a verified watcher start`);
    assert.doesNotMatch(env.element('runtime-action-status').textContent, /verified and ready/i);
    const reads = countRequests(env, 'GET', diagnosticsPath);
    await env.tickIntervals();
    assert.equal(countRequests(env, 'GET', diagnosticsPath), reads, 'ownership mismatch must stop observation');
    assert.equal(countRequests(env, 'POST'), 1);
  }

  const pending = await harness(snapshot('RUNTIME', 'STOPPED', 'generation-watcher-bounded'));
  pending.location.hash = '#runtime';
  pending.setDiagnostics(snapshot('RUNTIME', 'UNVERIFIED', 'generation-watcher-bounded'));
  pending.enqueue('/api/runtime/watcher/start', {ok: true, session_id: 7, watcher: 'UNVERIFIED'}, {method: 'POST', status: 202});
  const initialReads = countRequests(pending, 'GET', diagnosticsPath);
  await pending.click('watcher-start');
  for (let tick = 0; tick < 28; tick += 1) await pending.tickIntervals();
  assert.equal(countRequests(pending, 'GET', diagnosticsPath) - initialReads, 29, 'confirmation plus twenty-eight timer reads must leave the final budget read');
  const finalRead = deferred();
  pending.enqueue(diagnosticsPath, null, {pending: finalRead});
  const finalTick = pending.tickIntervals();
  await flush();
  assert.equal(countRequests(pending, 'GET', diagnosticsPath) - initialReads, 30, 'the final diagnostics GET must be in flight');
  assert.equal(pending.element('watcher-start').disabled, true, 'the final budget GET must retain the watcher button gate until it settles');
  await pending.click('watcher-start');
  assert.equal(countRequests(pending, 'POST'), 1, 'a duplicate watcher event during the final budget GET must be suppressed');
  finalRead.resolve(pending.response(snapshot('RUNTIME', 'UNVERIFIED', 'generation-watcher-bounded')));
  await finalTick;
  const boundedReads = countRequests(pending, 'GET', diagnosticsPath);
  assert.equal(boundedReads - initialReads, 30, 'unsuccessful readiness observation must be bounded to thirty diagnostics snapshots including confirmation');
  assert.match(pending.element('runtime-action-status').textContent, /not verified|could not be verified|unverified|timed out|limit/i);
  assert.doesNotMatch(pending.element('runtime-action-status').textContent, /verified and ready/i);
  for (let tick = 0; tick < 5; tick += 1) await pending.tickIntervals();
  assert.equal(countRequests(pending, 'GET', diagnosticsPath), boundedReads, 'exhausted readiness budget must stop the GET loop');
  assert.equal(countRequests(pending, 'POST'), 1, 'exhausted readiness budget must never retry the watcher POST');
  pending.setDiagnostics(snapshot('RUNTIME', 'IDLE', 'generation-watcher-bounded'));
  await pending.refresh();
  assertWatcherReady(pending);
  assert.equal(countRequests(pending, 'POST'), 1, 'a later explicit refresh can reconcile an exhausted observation without another POST');
}

async function testBackgroundTrafficIsSeparate() {
  const env = await harness(snapshot());
  const canonical = [{timestamp: 'run-time', source_node: 'attacker', target_node: 'plc1', protocol: 'TCP'}];
  const background = [{timestamp: 'observed-time', source_type: 'Suricata EVE flow', source_ip: '10.0.0.100',
    destination_ip: '10.0.0.8', protocol: 'TCP', destination_port: 502, flow: {alerted: false}}];
  env.enqueue('/api/live-battle?limit=100', {...snapshot('RUNTIME', 'IDLE', 'generation-background'), ...{
    ...{topology: {nodes: [{id: 'plc1'}], links: []}, visual: {nodes: [], edges: []}},
    network_events: canonical, security_events: [], background_network: background,
    network_event_count: 1, security_event_count: 0, campaign: null, limit: 100
  }});
  await env.navigate('#battle');
  assert.match(env.element('network-events-body').innerHTML, /attacker/);
  assert.doesNotMatch(env.element('network-events-body').innerHTML, /10\.0\.0\.100/);
  const backgroundHtml = env.element('background-network-body').innerHTML;
  assert.match(backgroundHtml, /Suricata EVE flow/);
  assert.match(backgroundHtml, /10\.0\.0\.100/);
  assert.match(backgroundHtml, /10\.0\.0\.8/);
  assert.match(htmlSource, /not associated with a specific attack step/);
  assert.equal(countRequests(env, 'GET', '/api/live-battle?limit=100'), 1);
}

async function testTopologySelectionUsesCanonicalApiAndPyvis() {
  const env = await harness(snapshot());
  await env.navigate('#network');
  assert.equal(env.element('topology-selector').options.length, 2, 'selector uses the available backend presets');
  assert.equal(env.element('topology-selector').value, 'case14');
  assert.match(env.element('network-topology').children[0].srcdoc, /PyVis case14/);
  const selected = {configuration: {node_count: 3, edge_count: 2, case_name: 'case30', selected_case: 'case30',
    available_topologies: [{case_name: 'case14', name: 'IEEE 14 Bus'}, {case_name: 'case30', name: 'IEEE 30 Bus'}],
    topology_version: 'case30:3', node_types: {plc: 2, hub: 1}}, topology: {case_name: 'case30'},
    visual: {nodes: [{id: 'plc1'}, {id: 'plc2'}, {id: 'hub'}], edges: [{from: 'hub', to: 'plc1'}, {from: 'hub', to: 'plc2'}]},
    pyvis_html: '<html>PyVis case30</html>'};
  env.element('topology-selector').value = 'case30';
  env.enqueue('/api/topology/select', selected, {method: 'POST'});
  env.enqueue('/api/topology', {...selected, ...selected}, {});
  await env.element('topology-selector').dispatch('change');
  const request = env.requests.find(item => item.method === 'POST' && item.url === '/api/topology/select');
  assert.ok(request, 'selection is sent to the canonical topology API');
  assert.equal(JSON.parse(request.options.body).case_name, 'case30');
  assert.equal(env.element('network-nodes').textContent, 3);
  assert.equal(env.element('network-edges').textContent, 2);
  assert.match(env.element('network-topology').children[0].srcdoc, /PyVis case30/);
  assert.match(env.element('topology-selection-status').textContent, /Selected case30/);
}

async function testTopologySelectionFailureIsVisible() {
  const env = await harness(snapshot());
  await env.navigate('#network');
  env.element('topology-selector').value = 'case30';
  env.enqueue('/api/topology/select', {ok: false, error: {code: 'topology_conflict', message: 'CORE is running'}}, {method: 'POST', status: 409});
  await env.element('topology-selector').dispatch('change');
  assert.match(env.element('topology-selection-status').textContent, /Topology selection failed: CORE is running/);
  assert.equal(env.element('topology-selector').value, 'case14', 'failure restores the authoritative selected preset');
  assert.equal(countRequests(env, 'POST', '/api/topology/select'), 1);
}

async function testCustomTopologyEditorAndGuards() {
  const env = await harness(snapshot());
  await env.navigate('#network');
  const definition = {case_name:'custom_lab', nodes:[{bus_id:0,name:'Generator',type:'slack'}], edges:[]};
  const selected = {configuration:{node_count:5,edge_count:4,case_name:'custom_lab',selected_case:'custom_lab',
    available_topologies:[{case_name:'case14',name:'IEEE 14'},{case_name:'custom_lab',name:'custom_lab'}],
    node_types:{plc:1,hub:1,scada:1,attacker:1,ids:1},definition},topology:{case_name:'custom_lab'},
    visual:{nodes:[{id:'plc1'}],edges:[]},pyvis_html:'<html>Custom PyVis plc1</html>'};
  env.element('custom-topology-json').value = JSON.stringify(definition);
  env.enqueue('/api/topology/custom', selected, {method:'POST'});
  await env.click('custom-topology-save');
  assert.equal(env.element('topology-selector').value, 'custom_lab');
  assert.match(env.element('network-topology').children[0].srcdoc, /Custom PyVis plc1/);
  const posted = env.requests.find(r=>r.method==='POST' && r.url==='/api/topology/custom');
  assert.deepEqual(JSON.parse(posted.options.body), {definition});
  await env.click('custom-topology-copy');
  assert.deepEqual(JSON.parse(env.element('custom-topology-json').value), definition);
  env.element('custom-topology-json').value = 'invalid JSON';
  await env.click('custom-topology-save');
  assert.match(env.element('topology-selection-status').textContent, /Custom topology failed/);
  assert.equal(countRequests(env,'POST','/api/topology/custom'),1);
  const running = await harness(snapshot('RUNTIME','IDLE','custom-generation'));
  for(const id of ['custom-topology-json','custom-topology-save','custom-topology-copy']) assert.equal(running.element(id).disabled,true);
  await running.click('custom-topology-save');
  assert.equal(countRequests(running,'POST'),0);
}

async function testOpenCoreGuiUsesExistingRuntimeHelperRoute() {
  const env = await harness(snapshot('RUNTIME', 'IDLE', 'gui-session'));
  env.location.hash = '#runtime';
  await env.refresh();
  env.enqueue('/api/runtime/gui', {session_id: 7, gui_pid: 321}, {method: 'POST'});
  await env.click('core-gui');
  assert.equal(countRequests(env, 'POST', '/api/runtime/gui'), 1);
  assert.match(env.element('runtime-action-status').textContent, /CORE GUI opened for CORE Session 1/);
  assert.doesNotMatch(env.element('runtime-action-status').textContent, /session 7|PID 321/);
  assert.equal(countRequests(env, 'GET', diagnosticsPath) >= 2, true, 'successful GUI launch refreshes authoritative runtime diagnostics');
  const failed = await harness(snapshot('RUNTIME', 'IDLE', 'gui-failure'));
  failed.location.hash = '#runtime'; await failed.refresh();
  failed.enqueue('/api/runtime/gui', {error: {code: 'gui_unavailable', message: 'WSLg is unavailable'}}, {method: 'POST', status: 503});
  await failed.click('core-gui');
  assert.match(failed.element('runtime-action-status').textContent, /WSLg is unavailable/, 'runtime helper failures remain visible');
  assert.equal(countRequests(failed, 'POST', '/api/runtime/gui'), 1);
}

async function testBattleOnlyRefreshesPyvisWhenStateChanges() {
  const env = await harness(snapshot('RUNTIME', 'IDLE', 'pyvis-live'));
  await env.navigate('#battle');
  const initialFrame = env.element('battle-topology').children[0];
  assert.match(initialFrame.srcdoc, /PyVis case14/);
  await env.call('loadBattle');
  assert.equal(env.element('battle-topology').children[0], initialFrame, 'unchanged visual state must retain its interactive PyVis frame');
  const battleReads = env.requests.filter(request => request.url.startsWith('/api/live-battle?limit=100'));
  assert.ok(battleReads.some(request => request.url.includes('visual_signature=fixture-visual')),
    'live refresh asks the backend to omit unchanged PyVis HTML');
}

async function testHumanReadableIdentifiersKeepRawValuesTechnical() {
  const system = snapshot('RUNTIME', 'IDLE', 'opaque-generation-value');
  const env = await harness(system);
  const correlation = 'step-1-d2294dea07c1';
  env.enqueue('/api/live-battle?limit=100', {
    topology: {nodes: [{id: 'plc14'}], links: []}, visual: {nodes: [], edges: []},
    visual_signature: 'identity-visual', pyvis_html: '<html>identity</html>', active_run: system.active_run,
    display_identity: system.display_identity,
    campaign: {state: 'READY', campaign_id: system.active_run.run.run_id, generation_id: system.generation, correlation_id: correlation},
    campaign_display: {Assessment: 'Assessment 1', State: 'READY', Runtime: 'Runtime Generation 1', 'Attack step': 'Attack Step 1', 'Attack event': 'Attack Event 1'},
    network_events: [], background_network: [], network_event_count: 0, security_event_count: 1, limit: 100,
    security_events: [{timestamp: '2026-10-06T12:00:00Z', event_type: 'attack_started', target_node: 'plc14',
      mitre_technique: 'T0835', correlation_id: correlation, run_id: system.active_run.run.run_id,
      generation_id: system.generation, severity: 'HIGH',
      display_identity: {attack_step: 'Attack Step 1', attack_event: 'Attack Event 1'}}]
  });
  await env.navigate('#battle');
  assert.equal(env.element('battle-run').textContent, 'Assessment 1');
  const campaign = env.element('battle-campaign-meta').innerHTML;
  for (const value of ['Assessment 1', 'Runtime Generation 1', 'Attack Step 1', 'Attack Event 1']) assert.match(campaign, new RegExp(value));
  assert.doesNotMatch(campaign, /run-opaque|opaque-generation|step-1-d229/);
  const attackLog = env.element('security-events-body').innerHTML;
  const primary = attackLog.split('<details')[0];
  for (const value of ['Attack Step 1', 'Attack Event 1', 'plc14', 'T0835']) assert.match(primary, new RegExp(value));
  assert.doesNotMatch(primary, /step-1-d229/);
  assert.match(attackLog, /Technical details/);
  assert.match(attackLog, /step-1-d2294dea07c1/, 'raw correlation remains available in the expanded technical event');
  assert.match(env.element('overview-technical-data').innerHTML, /Internal assessment ID.*run-opaque-generation-value/);
}

const tests = [
  ['A: STOPPED state and enabled/disabled styles', testStoppedAndStyles],
  ['B: coherent RUNTIME snapshot and watcher rules', testRuntimeSnapshot],
  ['C: pending Start deduplication and preserved 409 diagnostics', testStartConflictAndPending],
  ['D: stale refresh retains last known diagnostics', testStaleRefresh],
  ['E: out-of-order snapshots cannot overwrite newer results', testOutOfOrderRefreshes],
  ['F: canonical XML markup and backend contract', testCanonicalXmlContract],
  ['F2: professional overview, canonical counts, recent activity and collapsed diagnostics', testProfessionalOverviewUsesExistingData],
  ['F3: visual introduction, verified concepts and understandable empty state', testOverviewIntroductionAndEmptyState],
  ['F4: overview network preview uses the selected custom topology', testOverviewCustomTopologyPreview],
  ['G: existing campaign and defense prerequisite gates', testOtherControlGating],
  ['H: obsolete route failures preserve fresh runtime diagnostics', testObsoleteRouteFailure],
  ['I: accepted watcher start uses immediate authoritative readiness', testWatcherImmediateReadiness],
  ['J: deferred watcher readiness and duplicate suppression', testWatcherDeferredReadinessAndDuplicates],
  ['K: watcher refresh failure and backend errors remain visible', testWatcherRefreshFailureAndPostError],
  ['L: watcher ownership identity and bounded GET-only observation', testWatcherIdentityAndBoundedObservation]
  ,['M: background traffic remains a separate refreshed table', testBackgroundTrafficIsSeparate]
  ,['N: canonical topology selection refreshes a real PyVis view', testTopologySelectionUsesCanonicalApiAndPyvis]
  ,['N2: topology selection errors remain visible and restore selection', testTopologySelectionFailureIsVisible]
  ,['N3: custom topology editor, API, PyVis and runtime guards', testCustomTopologyEditorAndGuards]
  ,['O: Open CORE GUI uses the existing runtime helper route', testOpenCoreGuiUsesExistingRuntimeHelperRoute]
  ,['P: Live Battle reuses unchanged PyVis state', testBattleOnlyRefreshesPyvisWhenStateChanges]
  ,['Q: identifier aliases are shared while raw IDs remain technical', testHumanReadableIdentifiersKeepRawValuesTechnical]
];

(async () => {
  let failed = 0;
  for (const [name, test] of tests) {
    try { await test(); console.log(`PASS ${name}`); }
    catch (error) { failed += 1; console.error(`FAIL ${name}\n${error.stack}`); }
  }
  if (failed) process.exitCode = 1;
  else console.log('GUI frontend regression: PASS (all requests mocked; no runtime controls executed)');
})();
