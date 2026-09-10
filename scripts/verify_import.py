import sys
sys.path.insert(0, '/home/adty17/ascend-pg-webapp')
from scripts.testbed_executor import TECHNIQUE_TO_STEP_NAME
print(f'OK, techniques: {len(TECHNIQUE_TO_STEP_NAME)}')
for k, v in TECHNIQUE_TO_STEP_NAME.items():
    print(f'  {k} -> {v}')
