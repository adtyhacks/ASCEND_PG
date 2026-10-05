"""Local host for ASCEND-PG's dedicated Phase 3B GUI."""
from __future__ import annotations

import json
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from gui import adapter
from gui.campaign import CampaignController, CampaignError

WEB_ROOT = Path(__file__).resolve().parent / "web"
CAMPAIGNS = CampaignController()


class GuiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path == "/api/dashboard":
                payload = {"system": adapter.get_system_status(), "active_run": adapter.get_active_run()}
            elif parsed.path == "/api/active-run-integrity":
                payload = adapter.get_displayable_active_run()
            elif parsed.path == "/api/topology":
                payload = adapter.get_topology()
            elif parsed.path == "/api/network-configuration":
                payload = adapter.get_network_configuration()
            elif parsed.path == "/api/runtime-diagnostics":
                payload = adapter.get_runtime_diagnostics()
            elif parsed.path == "/api/report-summary":
                payload = adapter.get_report_summary()
            elif parsed.path == "/api/live-battle":
                payload = adapter.get_live_battle_snapshot(
                    int(query.get("limit", ["100"])[0]), query.get("visual_signature", [None])[0]
                )
            elif parsed.path == "/api/campaign/status":
                payload = CAMPAIGNS.status()
            else:
                return super().do_GET()
            body = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ValueError, FileNotFoundError) as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": {"code": "invalid_request", "message": str(exc)}})
        except Exception as exc:  # Preserve API diagnostics for optional PPO/runtime dependencies.
            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": {"code": "backend_exception", "message": str(exc)}})

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64 * 1024:
            raise CampaignError("request_too_large", "JSON request body exceeds 64 KiB.", 413)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise CampaignError("invalid_json", "Request body must be JSON.", 400) from exc
        if not isinstance(body, dict):
            raise CampaignError("invalid_json", "Request body must be a JSON object.", 400)
        return body

    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        try:
            data = self._json_body()
            if self.path == "/api/runtime/start":
                payload, status = CAMPAIGNS.start_core(), HTTPStatus.ACCEPTED
            elif self.path == "/api/runtime/gui":
                payload, status = adapter.core_request("gui"), HTTPStatus.OK
            elif self.path == "/api/runtime/stop":
                payload, status = CAMPAIGNS.stop_core(), HTTPStatus.OK
            elif self.path == "/api/runtime/watcher/start":
                payload, status = adapter.core_request("watcher"), HTTPStatus.ACCEPTED
            elif self.path == "/api/campaign/start":
                payload, status = CAMPAIGNS.start(), HTTPStatus.CREATED
            elif self.path == "/api/campaign/next":
                payload, status = CAMPAIGNS.next_step(), HTTPStatus.ACCEPTED
            elif self.path == "/api/campaign/run":
                payload, status = CAMPAIGNS.run_full(int(data.get("max_steps", 20))), HTTPStatus.ACCEPTED
            elif self.path == "/api/campaign/isolate":
                payload, status = CAMPAIGNS.defend("isolate", str(data.get("target_node", ""))), HTTPStatus.OK
            elif self.path == "/api/campaign/restore":
                payload, status = CAMPAIGNS.defend("restore", str(data.get("target_node", ""))), HTTPStatus.OK
            elif self.path == "/api/topology/select":
                payload, status = adapter.select_topology(str(data.get("case_name", ""))), HTTPStatus.OK
            else:
                self._write_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": {"code": "not_found", "message": "Unknown API endpoint."}})
                return
            self._write_json(status, {"ok": True, **payload})
        except CampaignError as exc:
            self._write_json(exc.status, {"ok": False, "error": {"code": exc.code, "message": str(exc)}})
        except RuntimeError as exc:
            self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": {"code": "backend_exception", "message": str(exc)}})
        except (ValueError, FileNotFoundError) as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": {"code": "invalid_request", "message": str(exc)}})
        except Exception as exc:
            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": {"code": "backend_exception", "message": str(exc)}})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), GuiHandler)
    print("ASCEND-PG Phase 3B GUI available at http://127.0.0.1:8765")
    server.serve_forever()


if __name__ == "__main__":
    main()
