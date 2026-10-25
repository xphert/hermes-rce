"""hermes-rce dashboard backend.

Routes mounted at /api/plugins/hermes-rce/ behind the dashboard auth gate.
Proxies the PoC PTY transport (SSE stream + REST input) so the tab can drive
real sessions. Handlers must not block the gateway event loop: every blocking
urllib call runs via asyncio.to_thread.

Transport target: HERMES_RCE_BASE_URL (default http://127.0.0.1:8899).
"""
from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request

from fastapi import APIRouter, HTTPException

router = APIRouter()

BASE_URL = os.environ.get("HERMES_RCE_BASE_URL", "http://127.0.0.1:8899").rstrip("/")
PREFIX = os.environ.get("HERMES_RCE_TRANSPORT_PREFIX", "/terminal")
TIMEOUT_S = float(os.environ.get("HERMES_RCE_HTTP_TIMEOUT", "10"))


def _req(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + PREFIX + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            payload = resp.read()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"transport {method} {path} -> {e.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise HTTPException(status_code=502, detail=f"transport {method} {path} failed: {e}") from None


@router.get("/sessions")
async def list_sessions():
    return await asyncio.to_thread(_req, "GET", "/sessions")


@router.post("/sessions")
async def open_session(body: dict):
    opts = {
        "cols": int(body.get("cols", 80)),
        "rows": int(body.get("rows", 24)),
    }
    if body.get("shell"):
        opts["shell"] = str(body["shell"])
    return await asyncio.to_thread(_req, "POST", "/sessions", opts)


@router.post("/sessions/{sid}/input")
async def send_input(sid: str, body: dict):
    text = str(body.get("text", ""))
    if not text:
        raise HTTPException(status_code=400, detail="text is empty")
    return await asyncio.to_thread(_req, "POST", f"/sessions/{sid}/input", {"bytes": text})


@router.get("/sessions/{sid}/output")
async def read_output(sid: str, cursor: int = 0):
    return await asyncio.to_thread(_req, "GET", f"/sessions/{sid}/output?cursor={int(cursor)}")


@router.post("/sessions/{sid}/exec")
async def exec_command(sid: str, body: dict):
    command = str(body.get("command", "")).strip()
    if not command:
        raise HTTPException(status_code=400, detail="command is empty")
    # server-side newline; the UI never has to remember it
    return await asyncio.to_thread(_req, "POST", f"/sessions/{sid}/input", {"bytes": command + "\n"})


@router.post("/sessions/{sid}/resize")
async def resize(sid: str, body: dict):
    return await asyncio.to_thread(
        _req, "POST", f"/sessions/{sid}/resize",
        {"cols": int(body.get("cols", 80)), "rows": int(body.get("rows", 24))},
    )


@router.delete("/sessions/{sid}")
async def close_session(sid: str):
    return await asyncio.to_thread(_req, "DELETE", f"/sessions/{sid}")
