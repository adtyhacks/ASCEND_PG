"""Dedicated GUI startup regression with legacy UI imports explicitly blocked."""
import importlib.abc
from pathlib import Path
import sys
import tempfile
import threading
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

class NoLegacyUI(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"streamlit", "app"}:
            raise ImportError(f"Legacy UI dependency forbidden: {fullname}")
        return None

def main():
    blocker = NoLegacyUI()
    sys.meta_path.insert(0, blocker)
    try:
        from gui.server import GuiHandler
        from gui import reporting
        from testbed import run_store
        original_runs = run_store.RUNS
        with tempfile.TemporaryDirectory() as temporary:
            run_store.RUNS = Path(temporary)
            server = ThreadingHTTPServer(("127.0.0.1", 0), GuiHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                for route, expected in (("/", b"report-generate"), ("/app.js", b"/api/report/generate"), ("/styles.css", b"sidebar"), ("/api/report-summary", b'"runs": []')):
                    with urllib.request.urlopen(base + route, timeout=10) as response:
                        assert response.status == 200 and expected in response.read(), route
                    print(f"PASS dedicated GUI HTTP: {route}", flush=True)
                assert reporting.saved_runs() == []
                assert not any(name == "streamlit" or name.startswith("streamlit.") or name == "app" or name.startswith("app.") for name in sys.modules)
                print("GUI startup and legacy dependency isolation: PASS", flush=True)
            finally:
                server.shutdown(); server.server_close(); thread.join()
                run_store.RUNS = original_runs
    finally:
        sys.meta_path.remove(blocker)

if __name__ == "__main__": main()
