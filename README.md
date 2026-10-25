# hermes-rce

Native **Hermes agent plugin** (`plugin.yaml` + `register(ctx)`) exposing 7 small PTY
terminal tools over the SSE+REST PoC transport. Python 3.11+, stdlib only.

```
hermes-rce/
├── plugin.yaml      # manifest: name, version, provides_tools, config_schema
├── __init__.py      # register(ctx) — wires schemas to handlers
├── schemas.py       # tool schemas (what the LLM reads)
├── tools.py         # handlers (JSON-string wrappers over the engine)
├── _core.py         # engine: envelope, cursor store, ANSI strip, redact, policy
├── host.py          # REST+SSE transport adapter (the only network-touching module)
└── tests/           # unittest, FakeHost transport
```

## Install

```bash
cp -r hermes-rce ~/.hermes/plugins/hermes-rce
hermes plugins enable hermes-rce
hermes plugins doctor hermes-rce --ci     # validate
```

## Configure

- `plugin.yaml` `config_schema` keys (via `plugins.entries.hermes-rce.settings`) or env:
  `HERMES_RCE_BASE_URL` (default `http://127.0.0.1:8899`), `HERMES_RCE_DEFAULT_TIMEOUT_MS`,
  `HERMES_RCE_MAX_BYTES`.
- Policy via `HERMES_RCE_POLICY` JSON: `{"allow": [regex...], "deny": [regex...]}`.
  Empty allow[] AND empty deny[] = deny-all. Built-in blocklist always applies
  (`rm -rf /`, `mkfs`, `dd of=/dev/*`, `shutdown`/`reboot`, `chmod 777 /`, `curl|sh`,
  `wget|sh`, `> /etc/passwd`, `~/.ssh`, `~/.aws`). For a programmatic
  `approve(session_id, action)` hook, construct `TerminalTools(policy={"approve": fn, ...})`.

## Tools

`terminal_open`, `terminal_write`, `terminal_read`, `terminal_wait_for`,
`terminal_exec`, `terminal_resize`, `terminal_close`. See `schemas.py` for
when-to-use descriptions. Envelope: `{ok, data?, cursor?, truncated?, error?{code,message,hint?}}`;
codes: `TIMEOUT`, `SESSION_NOT_FOUND`, `BLOCKED_BY_POLICY`, `TRUNCATED`, `PTY_DEAD`.

Guarantees: every call logged `{tool, session_id, cursor, duration_ms, ok}`; reads capped
(default 8 KiB, hard cap 64 KiB) and idempotent per cursor; ANSI stripped unless `raw:true`;
`PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY` values redacted unconditionally;
timeouts default 30 s, cap 300 s, never block forever; `exec` = `write` + `wait_for` + `read`,
appends the newline itself and never forks a shell.

## Usage transcript (sudo flow)

```jsonc
→ terminal_open        {"cols": 120}
← {"ok": true, "data": {"session_id": "s1"}}

→ terminal_exec        {"session_id": "s1", "command": "whoami"}
← {"ok": true, "data": "devuser", "cursor": 122}          // echo + prompt stripped

→ terminal_exec        {"session_id": "s1", "command": "sudo id"}   // sudo returns no prompt
← {"ok": false, "error": {"code": "TIMEOUT",
     "hint": "resume with since_cursor=178; partial output: \"...[sudo] password for user: \""}}

→ terminal_write       {"session_id": "s1", "text": "sudo id\n"}
→ terminal_wait_for    {"session_id": "s1", "pattern": "password for"}
← {"ok": true, "data": {"match": "[sudo] password for user: "}, "cursor": 190}
→ terminal_write       {"session_id": "s1", "text": "hunter2\n"}
→ terminal_wait_for    {"session_id": "s1"}                         // default shell prompt
← {"ok": true, "data": {"match": "user@host:~$ ", "text": "...uid=0(root)..."}, "cursor": 259}

→ terminal_exec        {"session_id": "s1", "command": "rm -rf /"}
← {"ok": false, "error": {"code": "BLOCKED_BY_POLICY", "hint": "blocked by denylist rule /.../"}}   // nothing typed

→ terminal_close       {"session_id": "s1"}
← {"ok": true, "data": {"session_id": "s1"}}
```

## Verify

```bash
python hermes-rce/tests/test_tools.py -v     # 28 tests, FakeHost transport
hermes plugins validate ~/.hermes/plugins/hermes-rce
```

Skipped: `terminal_upload`/`terminal_download` — PoC transport has no file channel. ReDoS:
pattern length cap + nested-quantifier rejection + 256 KiB scan window; upgrade path is a
regex engine with a hard timeout (`regex` package) if hostile patterns matter.
