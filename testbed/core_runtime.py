"""Small process boundary between the app environment and CORE's Python environment."""
import json
import os
from pathlib import Path
import subprocess
import threading

ROOT = Path(__file__).resolve().parents[1]
CORE_REQUEST_LOCK_TIMEOUT_SECONDS = 30.0
_CORE_REQUEST_LOCK = threading.Lock()


def core_request(action, **arguments):
    if os.name != "posix":
        raise RuntimeError("Run Streamlit inside WSL2; CORE namespaces require Linux.")
    python = os.environ.get("ASCEND_CORE_PYTHON", str(ROOT / ".venv-wsl/bin/python"))
    request = {"action": action, **arguments}
    if not _CORE_REQUEST_LOCK.acquire(timeout=CORE_REQUEST_LOCK_TIMEOUT_SECONDS):
        raise RuntimeError("Timed out waiting for another GUI CORE helper operation.")
    try:
        try:
            result = subprocess.run(
                [python, str(ROOT / "scripts/core_session.py")],
                input=json.dumps(request), capture_output=True, text=True,
                cwd=ROOT, timeout=360,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"CORE helper failed: {exc}") from exc
    finally:
        _CORE_REQUEST_LOCK.release()
    try:
        response = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError(f"CORE helper returned invalid output: {result.stderr or result.stdout}") from exc
    if result.returncode or not response.get("ok"):
        raise RuntimeError(response.get("error", result.stderr))
    return response
