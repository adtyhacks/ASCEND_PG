"""Local host for ASCEND-PG's dedicated Phase 3B GUI."""
from __future__ import annotations

import json
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from gui import adapter, reporting, grid_status, imports
from gui.campaign import CampaignController, CampaignError

WEB_ROOT = Path(__file__).resolve().parent / "web"
CAMPAIGNS = CampaignController()


def _event_limit(query: dict[str, list[str]]) -> int:
    values = query.get("limit", ["100"])
    if len(values) != 1:
        raise ValueError(f"limit must be an integer between 1 and {adapter.MAX_EVENT_LIMIT}")
    try:
        limit = int(values[0])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"limit must be an integer between 1 and {adapter.MAX_EVENT_LIMIT}") from exc
    if not 1 <= limit <= adapter.MAX_EVENT_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {adapter.MAX_EVENT_LIMIT}")
    return limit


class GuiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path == "/api/topology/source":
                payload = imports.active()
            elif parsed.path == "/api/topology/imported":
                payload = imports.workspace()
            elif parsed.path == "/api/topology/import-sample":
                payload = json.loads((WEB_ROOT.parent.parent / "examples" / "ascend_exchange.json").read_text(encoding="utf-8"))
            elif parsed.path == "/api/dashboard":
                payload = {"system": adapter.get_system_status(), "active_run": adapter.get_active_run()}
            elif parsed.path == "/api/active-run-integrity":
                payload = adapter.get_displayable_active_run()
            elif parsed.path == "/api/topology":
                payload = adapter.get_topology()
            elif parsed.path == "/api/attack-catalogue":
                payload = adapter.get_attack_catalogue()
            elif parsed.path == "/api/network-configuration":
                payload = adapter.get_network_configuration()
            elif parsed.path == "/api/grid-status":
                payload = grid_status.snapshot()
            elif parsed.path == "/api/runtime-diagnostics":
                payload = adapter.get_runtime_diagnostics()
            elif parsed.path == "/api/report-summary":
                payload = reporting.summary(query.get("scenario_id", [None])[0], query.get("run_id", [None])[0])
            elif parsed.path == "/api/report-file":
                path = reporting.report_path(query.get("scenario_id", [None])[0], query.get("run_id", [None])[0])
                body = path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'")
                disposition = "attachment" if query.get("download") == ["1"] else "inline"
                self.send_header("Content-Disposition", f'{disposition}; filename="{path.parent.name}-report.html"')
                self.end_headers()
                self.wfile.write(body)
                return
            elif parsed.path == "/api/live-battle":
                payload = adapter.get_live_battle_snapshot(
                    _event_limit(query), query.get("visual_signature", [None])[0]
                )
            elif parsed.path == "/api/topology/template":
                body = json.dumps(adapter.get_custom_topology_template(), indent=2).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", 'attachment; filename="custom_topology_template.json"')
                self.end_headers()
                self.wfile.write(body)
                return
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
        limit = 2 * 1024 * 1024 if self.path == "/api/topology/import" else 64 * 1024
        if length < 0 or length > limit:
            raise CampaignError("request_too_large", f"JSON request body exceeds {limit} bytes.", 413)
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
            if self.path == "/api/runtime/start" and not adapter.canonical_topology().core_compatible:
                raise ValueError(adapter.canonical_topology().capability_status()["reason"])
            if self.path == "/api/topology/use-imported":
                payload, status = imports.use_imported(data), HTTPStatus.OK
            elif self.path == "/api/topology/import":
                payload, status = imports.import_document(data), HTTPStatus.OK
            elif self.path == "/api/firewall/evaluate":
                payload, status = imports.decision(data), HTTPStatus.OK
            elif self.path == "/api/report/generate":
                payload, status = reporting.create_report(data.get("scenario_id"), data.get("run_id")), HTTPStatus.OK
            elif self.path == "/api/runtime/start":
                payload, status = CAMPAIGNS.start_core(), HTTPStatus.ACCEPTED
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
                imports.use_canonical()
            elif self.path == "/api/topology/validate":
                payload, status = adapter.validate_custom_topology(data.get("definition")), HTTPStatus.OK
            elif self.path == "/api/topology/custom":
                payload, status = adapter.save_custom_topology(data.get("definition")), HTTPStatus.OK
                imports.use_canonical()
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
