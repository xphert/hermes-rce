"""REST+SSE transport adapter. The only module that touches the network.

PoC wire contract (paths configurable via `prefix`):
  POST   {base}/sessions              {shell?, cols, rows, env?} -> {session_id}
  DELETE {base}/sessions/{id}
  POST   {base}/sessions/{id}/input   {bytes}
  GET    {base}/sessions/{id}/output?cursor=N -> {data, cursor, truncated}
  POST   {base}/sessions/{id}/resize  {cols, rows}
Any transport error raises PtyError -> the engine maps it to PTY_DEAD.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class PtyError(RuntimeError):
    pass


class RestHost:
    def __init__(self, base_url: str = "http://127.0.0.1:8899", prefix: str = "/terminal", timeout: float = 10.0) -> None:
        self.base = base_url.rstrip("/") + prefix
        self.timeout = timeout

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as e:
            raise PtyError(f"transport {method} {path} -> {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise PtyError(f"transport {method} {path} failed: {e}") from None

    def new_session(self, opts: dict) -> dict:
        return self._req("POST", "/sessions", opts)

    def close_session(self, sid: str) -> None:
        self._req("DELETE", f"/sessions/{sid}")

    def send_input(self, sid: str, data: str) -> None:
        self._req("POST", f"/sessions/{sid}/input", {"bytes": data})

    def read_output(self, sid: str, cursor: int) -> dict:
        return self._req("GET", f"/sessions/{sid}/output?cursor={int(cursor)}")

    def resize(self, sid: str, cols: int, rows: int) -> None:
        self._req("POST", f"/sessions/{sid}/resize", {"cols": cols, "rows": rows})
