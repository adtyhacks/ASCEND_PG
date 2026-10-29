import sys
from pathlib import Path
def main():
    scenario, run=sys.argv[1:3]; text=(Path(__file__).resolve().parents[1]/'data'/'runs'/scenario/run/'report.html').read_text(encoding='utf-8')
    checks={'run_id':run in text,'technique':'T0836' in text,'target':'plc1' in text,'detection':'DETECTED' in text,'confidence':'0.999' in text,'method':'both' in text.lower(),'zero_detections':'zero detections' not in text.lower(),'evasion':'EVADED' not in text,'defense':'isolate' in text.lower(),'cross_run':'run-61c27d26e569' not in text}
    for key,value in checks.items(): print(f'{key}: {"PASS" if value else "FAIL"}')
    if not all(checks.values()): raise SystemExit(1)
if __name__=='__main__': main()
