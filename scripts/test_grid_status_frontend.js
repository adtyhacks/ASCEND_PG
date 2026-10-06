// Native grid page rendering, mocked API only; no services or telemetry collection.
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm'), path = require('node:path');
const elements = new Map();
const element = id => { if (!elements.has(id)) elements.set(id,{innerHTML:'',textContent:''}); return elements.get(id); };
let fixture;
const calls=[];
const context=vm.createContext({document:{getElementById:element},console,fetch:async(url,options)=>{
  calls.push({url,options}); assert.equal(url,'/api/grid-status'); assert.equal(options.method,undefined);
  return {ok:true,json:async()=>fixture};
}});
const source=fs.readFileSync(path.join(__dirname,'../gui/web/app.js'),'utf8');
vm.runInContext(source.replace(/window.addEventListener\('hashchange', activateRoute\); bindControls\(\); activateRoute\(\);/,''),context);
(async()=>{
  for(const [name,count] of [['case14',14],['case30',30],['custom_lab',3]]) {
    fixture={case_name:name,components:Array.from({length:count},(_,i)=>({name:`Component ${i+1}`,type:'Load',model_voltage_pu:i===0?null:1.04,
      model_generation_mw:null,model_load_mw:0,status:'Not available',ip:`10.0.0.${i+1}`,last_observed:null})),
      grid:{component_count:count,healthy:null,warning:null,critical:null,model_average_voltage_pu:1.04,model_generation_mw:null,model_load_mw:0,
        model_reactive_generation_mvar:0,model_reactive_load_mvar:17,measured_voltage_pu:null,measured_power_mw:null,electrical_connections:count-1},
      network:{device_count:count+4,connections:count+3,responding_components:null,offline_components:null,status:'Not available',
        bandwidth_capacity_bps:null,observed_traffic:{bits_per_second:null},recent_detection_notices:null},
      provenance:{electrical:'Model values, not live measurements.'},runtime_available:false};
    const before=JSON.stringify(fixture);
    await vm.runInContext("loadRoute('grid')",context);
    assert.equal(element('grid-count').textContent,String(count));
    assert.equal((element('grid-components').innerHTML.match(/<tr>/g)||[]).length,count);
    assert.doesNotMatch(element('grid-components').innerHTML,/Not available|Unknown|Unverified/);
    assert.equal(element('grid-voltage').textContent,'1.040 pu');
    assert.equal(element('grid-live-voltage').textContent,'Not available');
    assert.equal(element('grid-generation').textContent,'Not available');
    assert.equal(element('grid-load').textContent,'0.00 MW');
    assert.equal(element('grid-reactive-generation').textContent,'0.00 Mvar');
    assert.equal(element('grid-reactive-load').textContent,'17.00 Mvar');
    assert.equal(element('grid-live-network-panel').hidden,true);
    assert.equal(element('grid-network').innerHTML,'');
    assert.doesNotMatch(element('grid-components').innerHTML,/10\.0\.0\./);
    assert.equal(JSON.stringify(fixture),before);
  }
  fixture.network.observed_traffic.bits_per_second=1200;
  fixture.runtime_available=true;
  fixture.baseline_grid = {
    case_name: 'case14',
    summary: {
      electrical_buses: 14,
      voltage_range: '1.010–1.090 pu',
      lines: 15,
      max_line_loading_pct: '1.5%'
    },
    bus_voltages: [
      {bus_id: 0, voltage_pu: 1.06, voltage_angle_deg: 0.0},
      {bus_id: 1, voltage_pu: 1.045, voltage_angle_deg: -4.98}
    ],
    line_loadings: [
      {line_id: 0, loading_percent: 1.51},
      {line_id: 1, loading_percent: 0.72}
    ],
    telemetry: [
      {timestamp: '2026-01-01 00:00:02', src_bus: 12, dst_bus: 11, packet_size_bytes: 280, voltage_pu: 0.9963}
    ]
  };
  await vm.runInContext('loadGridStatus()',context);
  assert.match(element('grid-network').innerHTML,/1200\.00 bit\/s/);
  assert.equal(element('grid-baseline-buses').textContent, '14');
  assert.equal(element('grid-baseline-voltage-range').textContent, '1.010–1.090 pu');
  assert.equal(element('grid-baseline-lines').textContent, '15');
  assert.equal(element('grid-baseline-max-loading').textContent, '1.5%');
  assert.match(element('grid-bus-voltage-table').innerHTML, /Bus 0/);
  assert.match(element('grid-line-loading-table').innerHTML, /Line 0/);
  assert.match(element('grid-telemetry-table').innerHTML, /2026-01-01 00:00:02/);
  assert.equal(element('grid-next-bar').hidden, false);
  const html=fs.readFileSync(path.join(__dirname,'../gui/web/index.html'),'utf8');
  assert.match(html,/data-route="grid" href="#grid">Network &amp; Grid Status/);
  assert.match(html,/data-page="grid"/);
  assert.match(html,/Mvar means megavolt-ampere reactive, the unit used for reactive power/);
  assert.match(html,/Reactive power supplied by the modeled generators/);
  assert.match(html,/Reactive power consumed by the modeled electrical loads/);
  const details = html.match(/<details class="panel technical-details" id="grid-technical-details"([^>]*)>[\s\S]*?<\/details>/);
  assert.ok(details, 'technical data-source explanations remain available in details');
  assert.doesNotMatch(details[1],/\bopen\b/, 'technical details are collapsed by default');
  assert.match(details[0],/id="grid-sources"/);
  assert.match(html,/aria-label="Component status"/);
  assert.equal(calls.length,4);
  console.log('Grid status frontend: PASS (14/30/custom, baseline grid simulation, tables/charts, honest missing data, model/live distinction, observed rate, immutable inputs)');
})().catch(error=>{console.error(error);process.exitCode=1;});
