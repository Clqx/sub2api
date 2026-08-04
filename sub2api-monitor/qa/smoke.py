from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

BASE_URL = os.getenv("MONITOR_SMOKE_URL", "http://127.0.0.1:18081/api/v1")
USERNAME = os.getenv("MONITOR_SMOKE_USERNAME", "admin")
PASSWORD = os.environ["MONITOR_SMOKE_PASSWORD"]


def request(path: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {path} failed: HTTP {exc.code} {exc.read()!r}") from exc
    return json.loads(raw) if raw else None


token = ""
token = request("/auth/login", method="POST", body={"username": USERNAME, "password": PASSWORD})[
    "access_token"
]

targets = request("/targets")
target = next((item for item in targets if item["name"] == "QA Fixture"), None)
if target is None:
    target = request(
        "/targets",
        method="POST",
        body={
            "name": "QA Fixture",
            "base_url": "http://fake-sub2api:8090",
            "mode": "api_only",
            "enabled": False,
            "collection_interval_seconds": 60,
            "credential": {"auth_type": "x_api_key", "api_key": "test-admin-key"},
        },
    )

target_id = target["id"]
probe = request(f"/targets/{target_id}/probe", method="POST")
if probe["target"]["monitoring_readiness"] != "ready":
    raise RuntimeError(f"fixture target did not become ready: {probe!r}")
request(f"/targets/{target_id}", method="PATCH", body={"enabled": True})
for collection_attempt in range(2):
    run = request(f"/targets/{target_id}/collect", method="POST")
    for _ in range(180):
        current = next(
            item for item in request(f"/runs?target_id={target_id}") if item["id"] == run["id"]
        )
        if current["status"] in {"succeeded", "failed"}:
            break
        time.sleep(0.5)
    if current["status"] == "succeeded":
        break
    if collection_attempt == 1:
        raise RuntimeError(f"collection failed after retry: {current!r}")

channels = request("/notification-channels")
channel = next((item for item in channels if item["name"] == "QA ntfy"), None)
if channel is None:
    channel = request(
        "/notification-channels",
        method="POST",
        body={
            "name": "QA ntfy",
            "server_url": "http://fake-ntfy:8090",
            "topic": "sub2api-monitor-qa",
            "enabled": True,
        },
    )
delivery = request(f"/notification-channels/{channel['id']}/test", method="POST")
for _ in range(30):
    current_delivery = next(
        item for item in request("/outbox?limit=100") if item["id"] == delivery["id"]
    )
    if current_delivery["status"] in {"sent", "dead"}:
        break
    time.sleep(0.5)
if current_delivery["status"] != "sent":
    raise RuntimeError(f"ntfy delivery failed: {current_delivery!r}")

dashboard = request("/dashboard")
system = request("/system/status")
if not system["ready"] or dashboard["accounts_total"] < 3:
    raise RuntimeError(f"monitor did not reach expected state: {dashboard!r} {system!r}")
print(
    json.dumps(
        {
            "target": probe["target"]["monitoring_readiness"],
            "run": current["status"],
            "delivery": current_delivery["status"],
            "dashboard": dashboard,
        },
        sort_keys=True,
    )
)
