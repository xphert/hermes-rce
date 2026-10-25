"""Shared helpers + terminal engine. Stdlib only; no network, no eval, no fs writes.

Validation-failure -> error-code mapping (spec's 5 codes are fixed):
  unknown/missing session_id -> SESSION_NOT_FOUND
  unsafe args (shell chars, ReDoS/oversized regex, empty command) -> BLOCKED_BY_POLICY
  host primitive raised -> PTY_DEAD
  output > max_bytes -> TRUNCATED (exec) / truncated=true (read)
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------- constants

TIMEOUT = "TIMEOUT"
SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
TRUNCATED = "TRUNCATED"
PTY_DEAD = "PTY_DEAD"

DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 300_000
DEFAULT_MAX_BYTES = 8 * 1024
HARD_MAX_BYTES = 64 * 1024
POLL_MIN_S = 0.02
POLL_MAX_S = 0.4
WINDOW_BYTES = 256 * 1024          # wait_for scan window
MAX_PATTERN_LEN = 512

# ---------------------------------------------------------------- envelope

Envelope = Dict[str, Any]


def ok(data: Any = None, cursor: Optional[int] = None, truncated: Optional[bool] = None) -> Envelope:
    env: Envelope = {"ok": True}
    if data is not None:
        env["data"] = data
    if cursor is not None:
        env["cursor"] = cursor
    if truncated is not None:
        env["truncated"] = truncated
    return env


def err(code: str, message: str, hint: Optional[str] = None) -> Envelope:
    e: Dict[str, Any] = {"code": code, "message": message}
    if hint:
        e["hint"] = hint
    return {"ok": False, "error": e}


# ---------------------------------------------------------------- text

ANSI_RE = re.compile(
    r"[\x1b\x9b](?:\][^\x07\x1b]*(?:\x07|\x1b\\)|[\[\]()#;?][0-9;?]*[A-Za-z@~]|[@-Z\\-_])"
)
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def strip_ansi(s: str) -> str:
    return CTRL_RE.sub("", ANSI_RE.sub("", s).replace("\r\n", "\n").replace("\r", "\n"))


SECRET_RE = re.compile(
    r"((?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY|ACCESS_?KEY)\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|\S+)",
    re.IGNORECASE,
)


def redact(s: str) -> str:
    """Unconditional - never echo secrets, not even with raw=True."""
    return SECRET_RE.sub(r"\1***REDACTED***", s)


def byte_len(s: str) -> int:
    return len(s.encode("utf-8"))


def cap_bytes(s: str, max_bytes: int) -> Tuple[str, bool]:
    """Byte-accurate clip; partial trailing code points are dropped, never leaked."""
    raw = s.encode("utf-8")
    if len(raw) <= max_bytes:
        return s, False
    return raw[:max_bytes].decode("utf-8", errors="ignore"), True


# ---------------------------------------------------------------- numbers

def clamp_timeout(v: Any, fallback: int = DEFAULT_TIMEOUT_MS) -> int:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return fallback
    if n <= 0:
        return fallback
    return min(int(n), MAX_TIMEOUT_MS)


def clamp_bytes(v: Any, fallback: int = DEFAULT_MAX_BYTES) -> int:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return fallback
    if n <= 0:
        return fallback
    return min(int(n), HARD_MAX_BYTES)


def clamp_dim(v: Any, fallback: int) -> int:
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        n = fallback
    return max(2, min(1000, n))


def to_int(v: Any, fallback: int) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return fallback


def to_str(v: Any) -> str:
    return v if isinstance(v, str) else ""


# ---------------------------------------------------------------- policy

BUILTIN_DENY_SOURCES = [
    r"\brm\s+(-[a-z]*\s+)*-?[a-z]*r[a-z]*f[a-z]*\s+/(?:\s|$)",
    r"\brm\s+-[rf]{1,3}[a-z]*\b[^|;&]*\s/(?:\s|$)",
    r"\bmkfs(\.\w+)?\b",
    r"\bdd\b[^|;&]*\bof=/dev/",
    r"\b(shutdown|reboot|halt|poweroff)\b",
    r"\bchmod\s+777\s+/(?:\s|$)",
    r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(\w+)?sh\b",
    r">\s*/etc/passwd",
    r"~/\.ssh|\$\{?HOME\}?/\.ssh|/\.ssh\b",
    r"~/\.aws|\$\{?HOME\}?/\.aws|\.aws\b",
]

UNSAFE_PATTERN = re.compile(r"\([^()]{0,64}[+*]\)[+*{]|\(\.[+*]\)[+*]|\{\d{3,}\}")
SHELL_UNSAFE = re.compile(r"[;|&`$><\n\\]")

# Python re has no variable-width lookbehind, so the default prompt regex uses
# re.MULTILINE instead of (?<=^|\n).
DEFAULT_PROMPT_SOURCE = r"^[^\n]{0,80}[$#%>][ \t]*$|\u276f[ \t]*$"


def compile_patterns(sources: List[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for s in (sources or [])[:256]:
        if not isinstance(s, str) or len(s) > MAX_PATTERN_LEN:
            continue
        try:
            out.append(re.compile(s, re.IGNORECASE))
        except re.error:
            continue  # skip unparsable host pattern rather than crashing a tool call
    return out


BUILTIN_DENY_RE = compile_patterns(BUILTIN_DENY_SOURCES)


def decide(policy: dict, session_id: str, action: str) -> Tuple[bool, Optional[str]]:
    """approve() hook the host can override; trusted when present (fail closed on raise)."""
    approve = policy.get("approve") if isinstance(policy, dict) else None
    if callable(approve):
        try:
            return bool(approve(session_id, action)), None
        except Exception as e:  # noqa: BLE001 - hook failure must not widen access
            return False, f"approve() hook failed: {e}"
    allow = policy.get("allow") or []
    deny = policy.get("deny") or []
    if not allow and not deny:
        # spec: allowlist AND denylist empty => deny-all for exec/write
        return False, "host policy has empty allow[] and deny[]; set one of them"
    allow_re = compile_patterns(allow)
    if allow_re and not any(r.search(action) for r in allow_re):
        return False, f"command not in allowlist ({len(allow_re)} entries)"
    for r in BUILTIN_DENY_RE + compile_patterns(deny):
        if r.search(action):
            return False, f"blocked by denylist rule /{r.pattern}/"
    return True, None


# ---------------------------------------------------------------- cursors

class CursorStore:
    """Per-instance session registry. Presence == session is known-open here."""

    def __init__(self) -> None:
        self.sessions: Dict[str, int] = {}
        self.dead: set[str] = set()

    def open(self, sid: str) -> None:
        self.sessions[sid] = 0
        self.dead.discard(sid)

    def has(self, sid: str) -> bool:
        return sid in self.sessions

    def is_dead(self, sid: str) -> bool:
        return sid in self.dead

    def get(self, sid: str) -> int:
        return self.sessions.get(sid, 0)

    def set(self, sid: str, cursor: int) -> None:
        if sid in self.sessions:
            self.sessions[sid] = cursor

    def kill(self, sid: str) -> None:
        self.dead.add(sid)

    def close(self, sid: str) -> None:
        self.sessions.pop(sid, None)
        self.dead.discard(sid)


# ---------------------------------------------------------------- engine

class TerminalTools:
    """All state lives on the instance; handlers are pure functions of (self, args)."""

    def __init__(
        self,
        host: Any,
        policy: Optional[dict] = None,
        logger: Optional[Callable[[dict], None]] = None,
        default_timeout_ms: int = DEFAULT_TIMEOUT_MS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        if host is None:
            raise ValueError("TerminalTools: host primitives are required")
        self.host = host
        # default: allow everything the built-in blocklist does not catch
        self.policy = policy if policy is not None else {"allow": [".*"], "deny": []}
        self.logger = logger
        self.default_timeout_ms = clamp_timeout(default_timeout_ms, DEFAULT_TIMEOUT_MS)
        self.max_bytes = clamp_bytes(max_bytes, DEFAULT_MAX_BYTES)
        self.now = now or time.monotonic
        self.reg = CursorStore()
        self._table = {
            "open": self._open,
            "write": self._write,
            "read": self._read,
            "wait_for": self._wait_for,
            "exec": self._exec,
            "resize": self._resize,
            "close": self._close,
        }

    # ------------------------------------------------------------ dispatch

    def call(self, tool: str, args: Optional[dict] = None) -> Envelope:
        args = dict(args or {})
        name = tool
        for prefix in ("terminal.", "terminal_"):
            if tool.startswith(prefix):
                name = tool[len(prefix):]
                break
        fn = self._table.get(name)
        sid = to_str(args.get("session_id")) or None
        cursor = self.reg.get(sid) if sid and self.reg.has(sid) else None
        t0 = self.now()
        res: Envelope
        if fn is None:
            res = err(SESSION_NOT_FOUND, f'unknown tool "{tool}"', "see the plugin manifest for tool names")
        else:
            try:
                res = fn(args)
            except Exception as e:  # noqa: BLE001 - host io failure == PTY_DEAD
                if sid:
                    self.reg.kill(sid)  # PTY gone: keep the record, refuse further io
                res = err(PTY_DEAD, f"pty io failed: {e}", "re-open the session; this one is unusable")
        out_cursor = res.get("cursor") if res.get("ok") else None
        if out_cursor is not None and sid:
            cursor = out_cursor
        if self.logger is not None:
            rec = {
                "tool": tool,
                "session_id": sid,
                "cursor": cursor,
                "duration_ms": round((self.now() - t0) * 1000, 3),
                "ok": bool(res.get("ok")),
            }
            if not res.get("ok"):
                rec["error"] = res["error"]["code"]
            try:
                self.logger(rec)
            except Exception:  # noqa: BLE001 - a broken logger must not break tools
                pass
        return res

    # ------------------------------------------------------------ tools

    def _open(self, a: dict) -> Envelope:
        shell = None if a.get("shell") is None else to_str(a.get("shell"))
        if shell is not None and SHELL_UNSAFE.search(shell):
            return err(
                BLOCKED_BY_POLICY,
                f"shell is not a plain executable: {json_quote(shell)}",
                "pass a bare path such as /bin/bash or pwsh.exe",
            )
        env_ok, env = _parse_env(a.get("env"))
        if not env_ok:
            return err(
                BLOCKED_BY_POLICY,
                "env must be a flat object of string values",
                "drop nested/oversized env values",
            )
        # open is gated by the host hook only: allow[]/deny[] filter *commands*, not session creation
        if callable(self.policy.get("approve")):
            allowed, hint = decide(self.policy, "", f"open:{shell or 'default'}")
            if not allowed:
                return err(BLOCKED_BY_POLICY, "session creation denied", hint)
        opts: Dict[str, Any] = {"cols": clamp_dim(a.get("cols"), 80), "rows": clamp_dim(a.get("rows"), 24)}
        if shell is not None:
            opts["shell"] = shell
        if env is not None:
            opts["env"] = env
        result = self.host.new_session(opts)
        session_id = (result or {}).get("session_id")
        if not session_id:
            raise RuntimeError("host returned no session_id")
        self.reg.open(session_id)
        return ok({"session_id": session_id})

    def _write(self, a: dict) -> Envelope:
        sid = to_str(a.get("session_id"))
        guard = self._guard(sid)
        if guard:
            return guard
        text = to_str(a.get("text"))
        if not text:
            return err(BLOCKED_BY_POLICY, "text is empty", "nothing to send; provide the bytes to type")
        allowed, hint = decide(self.policy, sid, text)
        if not allowed:
            return err(BLOCKED_BY_POLICY, "input denied by policy", hint)
        self.host.send_input(sid, text)
        return ok({"bytes": byte_len(text)}, self.reg.get(sid))

    def _read(self, a: dict) -> Envelope:
        sid = to_str(a.get("session_id"))
        guard = self._guard(sid)
        if guard:
            return guard
        cursor = self.reg.get(sid) if a.get("cursor") is None else to_int(a.get("cursor"), self.reg.get(sid))
        max_bytes = clamp_bytes(a.get("max_bytes"), self.max_bytes)
        r = self.host.read_output(sid, cursor)
        self.reg.set(sid, r["cursor"])
        text, truncated = cap_bytes(self._visible(r.get("data", ""), a), max_bytes)
        return ok(text, r["cursor"], truncated or bool(r.get("truncated")))

    def _wait_for(self, a: dict) -> Envelope:
        sid = to_str(a.get("session_id"))
        guard = self._guard(sid)
        if guard:
            return guard

        use_default = a.get("pattern") is None
        source = DEFAULT_PROMPT_SOURCE if use_default else to_str(a.get("pattern"))
        if not source or len(source) > MAX_PATTERN_LEN:
            return err(BLOCKED_BY_POLICY, f"pattern must be 1..{MAX_PATTERN_LEN} chars", "shrink the regex")
        if UNSAFE_PATTERN.search(source):
            return err(
                BLOCKED_BY_POLICY,
                "pattern looks like a nested quantifier (ReDoS risk)",
                "rewrite without (x+)+ style groups",
            )
        # the default prompt regex needs MULTILINE to anchor per line (Python has no
        # variable-width lookbehind); user patterns opt in via multiline=true
        flags = re.MULTILINE if (use_default or a.get("multiline") is True) else 0
        try:
            rx = re.compile(source, flags)
        except re.error as e:
            return err(
                BLOCKED_BY_POLICY,
                f"invalid regex: {e}",
                "fix pattern syntax, or omit it to wait for a shell prompt",
            )

        timeout_ms = clamp_timeout(a.get("timeout_ms"), self.default_timeout_ms)
        max_bytes = clamp_bytes(a.get("max_bytes"), self.max_bytes)
        deadline = self.now() + timeout_ms / 1000.0
        cursor = self.reg.get(sid) if a.get("since_cursor") is None else to_int(a.get("since_cursor"), self.reg.get(sid))
        acc = ""
        delay = POLL_MIN_S

        while True:
            r = self.host.read_output(sid, cursor)
            cursor = r["cursor"]
            self.reg.set(sid, cursor)
            if r.get("data"):
                acc += r["data"]
                delay = POLL_MIN_S
                # ponytail: fixed 256KiB window; ring buffer per session if you need unbounded scans
                if byte_len(acc) > WINDOW_BYTES:
                    acc = acc[-WINDOW_BYTES // 2:]
            hay = self._visible(acc, a)
            m = rx.search(hay)
            if m:
                text, truncated = cap_bytes(hay, max_bytes)
                waited = timeout_ms - max(0.0, (deadline - self.now()) * 1000)
                return ok({"text": text, "match": m.group(0), "waited_ms": round(waited, 3)}, cursor, truncated)
            left = deadline - self.now()
            if left <= 0:
                text, _ = cap_bytes(self._visible(acc, a), max_bytes)
                return err(
                    TIMEOUT,
                    f"no match for /{source}/ within {timeout_ms}ms",
                    f"resume with since_cursor={cursor}; partial output: {json_quote(text[-200:])}",
                )
            time.sleep(min(delay, left))  # non-blocking, exponential backoff
            delay = min(delay * 2, POLL_MAX_S)

    def _exec(self, a: dict) -> Envelope:
        """write + wait_for + read. Appends the newline server-side; never forks a shell."""
        sid = to_str(a.get("session_id"))
        guard = self._guard(sid)
        if guard:
            return guard
        command = re.sub(r"[\r\n]+$", "", to_str(a.get("command")))
        if not command:
            return err(
                BLOCKED_BY_POLICY,
                "command is empty",
                "provide the command text without a trailing newline",
            )
        max_bytes = clamp_bytes(a.get("max_bytes"), self.max_bytes)

        # drain anything buffered before the command, so we only see this command's output
        pre = self.host.read_output(sid, self.reg.get(sid))
        self.reg.set(sid, pre["cursor"])

        w = self._write({"session_id": sid, "text": command + "\n"})
        if not w.get("ok"):
            return w

        waited = self._wait_for(
            {
                "session_id": sid,
                "timeout_ms": a.get("timeout_ms"),
                "since_cursor": pre["cursor"],
                "max_bytes": max_bytes,
                "raw": a.get("raw"),
            }
        )
        if not waited.get("ok"):
            e = waited["error"]
            return err(e["code"], e["message"], f"{e.get('hint', '')} (command was: {json_quote(command)})")
        wd = waited["data"]
        if waited.get("truncated"):
            return err(
                TRUNCATED,
                f"output exceeded max_bytes={max_bytes}",
                f"advance the cursor: terminal_read(session_id, cursor={self.reg.get(sid)})",
            )
        text = wd["text"]

        tail = self._read({"session_id": sid, "max_bytes": max_bytes, "raw": a.get("raw")})
        if tail.get("ok") and isinstance(tail.get("data"), str):
            text += tail["data"]

        # drop the shell's echo of the command (first line) - the model already knows it
        nl = text.find("\n")
        if nl != -1 and text[:nl].strip() == command.strip():
            text = text[nl + 1:]
        # drop the prompt wait_for synched on - it is transport noise, not output
        match = wd["match"]
        if match and text.endswith(match):
            text = text[: -len(match)]
        text = text.strip(" \t\r\n")

        text, truncated = cap_bytes(text, max_bytes)
        if truncated:
            return err(
                TRUNCATED,
                f"output exceeded max_bytes={max_bytes}",
                f"advance the cursor: terminal_read(session_id, cursor={self.reg.get(sid)})",
            )
        return ok(text, self.reg.get(sid))

    def _resize(self, a: dict) -> Envelope:
        sid = to_str(a.get("session_id"))
        guard = self._guard(sid)
        if guard:
            return guard
        cols = clamp_dim(a.get("cols"), 80)
        rows = clamp_dim(a.get("rows"), 24)
        self.host.resize(sid, cols, rows)
        return ok({"cols": cols, "rows": rows}, self.reg.get(sid))

    def _close(self, a: dict) -> Envelope:
        sid = to_str(a.get("session_id"))
        if not self.reg.has(sid):
            return err(
                SESSION_NOT_FOUND,
                f'unknown session "{sid}"',
                "already closed, or open it with terminal_open first",
            )
        self.host.close_session(sid)
        self.reg.close(sid)
        return ok({"session_id": sid})

    # ------------------------------------------------------------ internals

    def _visible(self, data: str, a: dict) -> str:
        """raw=True only skips ANSI stripping; redaction is always applied."""
        stripped = data if a.get("raw") is True else strip_ansi(data)
        return redact(stripped)

    def _guard(self, sid: str) -> Optional[Envelope]:
        if not sid:
            return err(SESSION_NOT_FOUND, "session_id is required", "call terminal_open first")
        if not self.reg.has(sid):
            return err(
                SESSION_NOT_FOUND,
                f'unknown session "{sid}"',
                "call terminal_open first, or terminal_close it when done",
            )
        if self.reg.is_dead(sid):
            return err(PTY_DEAD, f'session "{sid}" pty is gone', "re-open the session; this one is unusable")
        return None


# ---------------------------------------------------------------- misc

def _parse_env(v: Any) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Returns (valid, env). Absent env is valid-and-absent; malformed env is invalid."""
    if v is None:
        return True, None
    if not isinstance(v, dict):
        return False, None
    out: Dict[str, str] = {}
    for k, val in list(v.items())[:64]:
        if not isinstance(val, str) or len(k) > 256 or len(val) > 4096 or "=" in k:
            return False, None
        out[k] = val
    return True, out


def json_quote(s: str) -> str:
    import json

    return json.dumps(s)
