"""One readiness-synchronised verification campaign; removed after use."""
import json, time
from pathlib import Path
from testbed.generate_core_topo import generate_core_xml
from testbed.core_runtime import core_request
from testbed.topology import load_case
from testbed.run_store import create_run, append_event, metrics, read_events, update_run
from reports.pentest_report import generate_report, render_html
R=Path(__file__).resolve().parents[1]; D=R/'data'; P=D/'pending_step.json'; Q=D/'step_result.json'; H=D/'watcher_heartbeat.json'
def main():
 t=load_case(14).canonical_snapshot(); run=create_run(t,attack_config={'technique':'T0836','target':'plc1'}); session=None
 try:
  xml=generate_core_xml(14,str(D/'core-runtime'/'campaign.xml')); session=core_request('start',xml=xml); update_run(run['scenario_id'],run['run_id'],core_session_id=session['session_id']); generation=json.loads((D/'core-runtime'/'session.json').read_text())['generation_id']
  core_request('watcher'); until=time.time()+60
  while time.time()<until:
   try:
    h=json.loads(H.read_text());
    if h.get('status')=='IDLE' and str(h.get('session_id'))==str(session['session_id']) and h.get('generation_id')==generation: break
   except Exception: pass
   time.sleep(.25)
  else: raise RuntimeError('watcher never reached IDLE')
  P.unlink(missing_ok=True); Q.unlink(missing_ok=True); tmp=P.with_suffix('.tmp'); tmp.write_text(json.dumps({'technique_id':'T0836','step_name':'fdi_attack','target_ip':'10.0.0.1','register_address':40000,'value_magnitude':9999,'target_bus':0,'generation_id':generation,'campaign_id':run['run_id']})); tmp.replace(P)
  until=time.time()+180
  while time.time()<until and not Q.exists(): time.sleep(.25)
  if not Q.exists(): raise RuntimeError('watcher did not return a result')
  x=json.loads(Q.read_text()); common={'mitre_technique':'T0836','attack_stage':2,'correlation_id':run['run_id'],'evidence':x}; a=x['start_time']; b=x['end_time']
  append_event(run['scenario_id'],run['run_id'],category='security',event_type='attack_started',source_node='attacker',target_node='plc1',severity='HIGH',result='started',timestamp=a,**common)
  append_event(run['scenario_id'],run['run_id'],category='security',event_type='attack_finished',source_node='attacker',target_node='plc1',severity='CRITICAL' if x.get('evaded') else 'INFO',result='compromised' if x.get('evaded') else x['status'],timestamp=b,**common)
  if x.get('detected'): append_event(run['scenario_id'],run['run_id'],category='security',event_type='detection',source_node='ids_monitor',target_node='plc1',severity='HIGH',result='detected',timestamp=b,**common)
  de=core_request('defend',target_node='plc1',defense_action='isolate'); append_event(run['scenario_id'],run['run_id'],category='security',event_type='defense_action',source_node='ids_monitor',target_node='plc1',severity='ACTION',defense_action='isolate',result='applied',evidence=de)
  es=read_events(run['scenario_id'],run['run_id'],'security'); m=metrics(run['scenario_id'],run['run_id']); rep=generate_report([{'Timestamp':e['timestamp'],'MITRE ID':e.get('mitre_technique',''),'Technique Name':e['event_type'],'Target Host':e.get('target_node',''),'Status':e.get('result',''),'Detected':e['event_type']=='detection'} for e in es],{'scenario_id':run['scenario_id'],'run_id':run['run_id'],'metrics':m}); out=Path(run['path'])/'report.html'; out.write_text(render_html(rep)); print(json.dumps({'run':run,'session':session,'watcher_ready':h,'attack':x,'defense':de,'metrics':m,'report':str(out)}))
 finally:
  P.unlink(missing_ok=True); Q.unlink(missing_ok=True)
  try: core_request('stop')
  except Exception: pass
if __name__=='__main__': main()
