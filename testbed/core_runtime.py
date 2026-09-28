"""Small process boundary between the app environment and CORE's Python environment."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def core_request(action, **arguments):
    if os.name != "posix":
        raise RuntimeError("Run Streamlit inside WSL2; CORE namespaces require Linux.")
    python = os.environ.get("ASCEND_CORE_PYTHON", "/opt/core/venv/bin/python")
    request = {"action": action, **arguments}
    try:
        result = subprocess.run(
            [python, str(ROOT / "scripts/core_session.py")],
            input=json.dumps(request), capture_output=True, text=True,
            cwd=ROOT, timeout=360,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"CORE helper failed: {exc}") from exc
    try:
        response = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError(f"CORE helper returned invalid output: {result.stderr or result.stdout}") from exc
    if result.returncode or not response.get("ok"):
        raise RuntimeError(response.get("error", result.stderr))
    return response
