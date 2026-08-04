from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def write_json(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


class Sub2APIHandler(QuietHandler):
    server_version = "fake-sub2api/1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            write_json(self, 200, {"status": "ok"})
            return
        if self.headers.get("x-api-key") != os.getenv("FAKE_SUB2API_API_KEY", "test-admin-key"):
            write_json(self, 401, {"code": 401, "message": "invalid admin credential"})
            return
        if parsed.path == "/api/v1/admin/system/version":
            write_json(self, 200, {"code": 0, "message": "success", "data": {"version": "v0.5-fixture"}})
            return
        if parsed.path == "/api/v1/admin/accounts":
            params = parse_qs(parsed.query)
            page = int(params.get("page", ["1"])[0])
            page_size = int(params.get("page_size", ["100"])[0])
            accounts = self.accounts()
            start = (page - 1) * page_size
            write_json(self, 200, {"code": 0, "message": "success", "data": {"items": accounts[start:start + page_size], "total": len(accounts), "page": page, "page_size": page_size, "pages": max(1, (len(accounts) + page_size - 1) // page_size)}})
            return
        match = re.fullmatch(r"/api/v1/admin/accounts/(\d+)/usage", parsed.path)
        if match:
            if parse_qs(parsed.query).get("source", ["active"])[0] != "passive":
                write_json(self, 409, {"code": 409, "message": "fake only permits passive usage"})
                return
            account_id = int(match.group(1))
            if account_id == 3:
                write_json(self, 404, {"code": 404, "message": "passive usage unavailable"})
                return
            now = datetime.now(timezone.utc)
            remaining = 8.0 if account_id == 2 else 72.0
            write_json(self, 200, {"code": 0, "message": "success", "data": {"updated_at": now.isoformat(), "five_hour": {"utilization": 100 - remaining, "resets_at": (now + timedelta(hours=2)).isoformat()}}})
            return
        write_json(self, 404, {"code": 404, "message": "not found"})

    @staticmethod
    def accounts() -> list[dict[str, object]]:
        now = datetime.now(timezone.utc).isoformat()
        return [
            {"id": 1, "name": "anthropic-primary", "platform": "anthropic", "type": "oauth", "status": "active", "schedulable": True, "created_at": now, "updated_at": now},
            {"id": 2, "name": "anthropic-low-quota", "platform": "anthropic", "type": "oauth", "status": "active", "schedulable": True, "created_at": now, "updated_at": now},
            {"id": 3, "name": "openai-disabled", "platform": "openai", "type": "api_key", "status": "disabled", "schedulable": False, "created_at": now, "updated_at": now},
        ]


class NtfyHandler(QuietHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            write_json(self, 200, {"status": "ok"})
            return
        if self.path == "/messages":
            path = Path(os.getenv("FAKE_NTFY_STORE", "/tmp/fake-ntfy.jsonl"))
            messages = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            write_json(self, 200, {"items": messages})
            return
        write_json(self, 404, {"message": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = min(int(self.headers.get("content-length", "0")), 1_000_000)
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {"message": raw.decode(errors="replace")}
        record = {"topic": self.path.strip("/"), "payload": payload, "authorization": bool(self.headers.get("authorization"))}
        path = Path(os.getenv("FAKE_NTFY_STORE", "/tmp/fake-ntfy.jsonl"))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        write_json(self, 200, {"id": "fake-message", "time": int(datetime.now(timezone.utc).timestamp()), "event": "message", "topic": record["topic"]})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("sub2api", "ntfy"))
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    handler = Sub2APIHandler if args.mode == "sub2api" else NtfyHandler
    ThreadingHTTPServer(("0.0.0.0", args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
