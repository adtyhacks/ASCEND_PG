import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from scripts.testbed_executor import TECHNIQUE_TO_STEP_NAME
print(f'OK, techniques: {len(TECHNIQUE_TO_STEP_NAME)}')
for k, v in TECHNIQUE_TO_STEP_NAME.items():
    print(f'  {k} -> {v}')
