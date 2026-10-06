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
        measured_voltage_pu:null,measured_power_mw:null,electrical_connections:count-1},
      network:{device_count:count+4,connections:count+3,responding_components:null,offline_components:null,status:'Not available',
        bandwidth_capacity_bps:null,observed_traffic:{bits_per_second:null},recent_detection_notices:null},
      provenance:{electrical:'Model values, not live measurements.'}};
    const before=JSON.stringify(fixture);
    await vm.runInContext("loadRoute('grid')",context);
    assert.equal(element('grid-count').textContent,String(count));
    assert.equal((element('grid-components').innerHTML.match(/<tr>/g)||[]).length,count);
    assert.match(element('grid-components').innerHTML,/Not available/);
    assert.equal(element('grid-voltage').textContent,'1.040 pu');
    assert.equal(element('grid-live-voltage').textContent,'Not available');
    assert.equal(element('grid-generation').textContent,'Not available');
    assert.equal(element('grid-load').textContent,'0.00 MW');
    assert.match(element('grid-network').innerHTML,/<span>Bandwidth capacity<\/span><strong>Not available/);
    assert.doesNotMatch(element('grid-components').innerHTML,/10\.0\.0\./);
    assert.equal(JSON.stringify(fixture),before);
  }
  fixture.network.observed_traffic.bits_per_second=1200;
  await vm.runInContext('loadGridStatus()',context);
  assert.match(element('grid-network').innerHTML,/1200\.00 bit\/s/);
  const html=fs.readFileSync(path.join(__dirname,'../gui/web/index.html'),'utf8');
  assert.match(html,/data-route="grid" href="#grid">Network &amp; Grid Status/);
  assert.match(html,/data-page="grid"/);
  assert.match(html,/Model values describe configured\/baseline conditions, not live measurements/);
  assert.match(html,/aria-label="Component status"/);
  assert.equal(calls.length,4);
  console.log('Grid status frontend: PASS (14/30/custom, honest missing data, model/live distinction, observed rate, immutable inputs)');
})().catch(error=>{console.error(error);process.exitCode=1;});
