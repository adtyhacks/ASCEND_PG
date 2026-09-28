"""WSL smoke test for the HTTP server and every existing Streamlit page."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from streamlit.testing.v1 import AppTest
    for path in [ROOT / "app/Home.py", *sorted((ROOT / "app/pages").glob("*.py"))]:
        app = AppTest.from_file(str(path), default_timeout=120).run()
        failures = [e.message for e in app.exception]
        if failures:
            raise AssertionError(f"{path.name}: {failures}")
        print(f"PASS page: {path.name}", flush=True)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "app/Home.py",
             "--server.headless=true", "--server.address=127.0.0.1", f"--server.port={port}"],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/_stcore/health", timeout=2) as response:
                        assert response.read() == b"ok"
                    print("PASS HTTP startup and health", flush=True)
                    break
                except OSError:
                    time.sleep(0.5)
            else:
                raise TimeoutError("Streamlit HTTP startup timed out")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
