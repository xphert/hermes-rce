"""Tool schemas - what the LLM reads to decide when to call each tool.

Names are registered with toolset "terminal"; descriptions explain *when* to
call, not just *what*.
"""
from __future__ import annotations

SESSION_ID = {
    "type": "string",
    "description": "Session handle returned by terminal_open. Required.",
}
TIMEOUT_MS = {
    "type": "integer",
    "minimum": 1,
    "maximum": 300000,
    "default": 30000,
    "description": (
        "How long to block, in milliseconds, before giving up. Default 30000, hard cap 300000. "
        "Never blocks forever; on expiry you get TIMEOUT plus a cursor you can resume from."
    ),
}
MAX_BYTES = {
    "type": "integer",
    "minimum": 1,
    "maximum": 65536,
    "default": 8192,
    "description": (
        "Byte ceiling for returned text. Default 8192. When the output is longer you get "
        "truncated=true and must call terminal_read again with the returned cursor to continue."
    ),
}
RAW = {
    "type": "boolean",
    "default": False,
    "description": (
        "Escape hatch: true returns the bytes verbatim with ANSI/VT escape sequences left in. "
        "Use only when escape codes carry meaning (colour-driven TUIs). Secrets are redacted either way."
    ),
}

ORDER = [
    "terminal_open",
    "terminal_write",
    "terminal_read",
    "terminal_wait_for",
    "terminal_exec",
    "terminal_resize",
    "terminal_close",
]

SCHEMAS = {
    "terminal_open": {
        "name": "terminal_open",
        "description": (
            "Start a new interactive terminal session (a real PTY, not a one-shot command runner). "
            "Call this FIRST, once, before any other terminal tool, and keep the returned session_id "
            "for the rest of the task. Use it when you need to interact with something stateful: an "
            "installer prompt, a REPL, a database shell, an ssh-like wizard, a sudo password prompt. "
            "Do NOT call it per command - reuse one session for a whole workflow."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "shell": {
                    "type": "string",
                    "description": (
                        "Bare executable or path to run as the session shell, e.g. '/bin/bash', "
                        "'pwsh.exe'. Must be a plain executable: shell metacharacters are rejected. "
                        "Omit to use the host default."
                    ),
                },
                "cols": {"type": "integer", "minimum": 2, "maximum": 1000, "default": 80,
                         "description": "Initial terminal width in columns."},
                "rows": {"type": "integer", "minimum": 2, "maximum": 1000, "default": 24,
                         "description": "Initial terminal height in rows."},
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": (
                        "Extra environment variables for the session. Flat string map, max 64 entries. "
                        "Never put credentials here if the session will echo its environment; prefer "
                        "letting the program prompt and answering with terminal_write."
                    ),
                },
            },
        },
    },
    "terminal_write": {
        "name": "terminal_write",
        "description": (
            "Send raw keystrokes/text to a session exactly as typed, with no newline added. Use it to "
            "answer an interactive prompt (sudo password, y/n confirmation, TUI navigation), to send "
            "control keys like '\\u0003' (Ctrl-C) or '\\u001b[B' (arrow down), or to type a partial "
            "command you intend to complete later. It does NOT wait for output - follow it with "
            "terminal_wait_for to see what happened. If you want a command run and its output collected, "
            "call terminal_exec instead of write."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id", "text"],
            "properties": {
                "session_id": SESSION_ID,
                "text": {
                    "type": "string",
                    "description": (
                        "Exact bytes to send. Append '\\n' yourself only when you truly mean to press "
                        "Enter; terminal_exec appends the newline for you."
                    ),
                },
            },
        },
    },
    "terminal_read": {
        "name": "terminal_read",
        "description": (
            "Non-blocking peek at everything the session produced since a cursor. Use it to collect "
            "output after terminal_write, to drain a chatty program, or to page through output that "
            "was clipped by max_bytes. Returns immediately even if nothing new arrived (empty string), "
            "so never call it in a loop to wait for something - use terminal_wait_for for that. Call "
            "it twice with the same cursor and you get identical bytes, so it is safe to re-read after "
            "a failure."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id"],
            "properties": {
                "session_id": SESSION_ID,
                "cursor": {
                    "type": "integer",
                    "description": (
                        "Resume point. Omit to continue from the last cursor you were given (normal "
                        "case); pass an older cursor to re-read, or the cursor from a truncated/error "
                        "result to page forward."
                    ),
                },
                "max_bytes": MAX_BYTES,
                "raw": RAW,
            },
        },
    },
    "terminal_wait_for": {
        "name": "terminal_wait_for",
        "description": (
            "Block until the session output matches a regex, or until timeout_ms elapses. This is the "
            "correct way to wait for anything: a shell prompt, 'Password:', 'Are you sure? [y/N]', "
            "'Do you want to continue?', an install progress line. ALWAYS prefer this over repeatedly "
            "calling terminal_read, which spins. Omit the pattern to wait for a common shell prompt "
            "($, #, %, >, \u276f), which is what you want at the end of a command. After a match you get "
            "the matched text plus the cursor, so you can read the rest."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id"],
            "properties": {
                "session_id": SESSION_ID,
                "pattern": {
                    "type": "string",
                    "description": (
                        "Python-style regex matched against the session output. Omit to use the "
                        "shell-prompt default (^[^\\n]{0,80}[$#%>][ \\t]*$|\u276f[ \\t]*$, multiline). "
                        "Keep it simple and specific, e.g. 'Password:' or '\\[y/N\\]'. Nested "
                        "quantifiers are rejected."
                    ),
                },
                "timeout_ms": TIMEOUT_MS,
                "since_cursor": {
                    "type": "integer",
                    "description": (
                        "Start scanning from this cursor instead of the last known one. Use the cursor "
                        "from a previous result to look for a second occurrence."
                    ),
                },
                "multiline": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set true to make '^'/'$' match at line boundaries instead of only at the ends of the buffer.",
                },
                "max_bytes": MAX_BYTES,
                "raw": RAW,
            },
        },
    },
    "terminal_exec": {
        "name": "terminal_exec",
        "description": (
            "Run one command in an existing session and return its output: it appends the newline, "
            "waits for the next shell prompt, and hands back the text. This is the default tool for "
            "ordinary commands (ls, whoami, git status, cat file). It is a convenience built on "
            "terminal_write + terminal_wait_for + terminal_read - it does not create a shell. Use "
            "terminal_write/terminal_wait_for instead when the command is interactive (a password "
            "prompt, a pager, a TUI) or when you need fine control over when to press keys - those do "
            "not return a prompt and exec will TIME OUT. The command is subject to the host policy "
            "hook and will be refused with BLOCKED_BY_POLICY if it matches the denylist."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id", "command"],
            "properties": {
                "session_id": SESSION_ID,
                "command": {
                    "type": "string",
                    "description": (
                        "Command line WITHOUT a trailing newline - one is appended for you. Single line "
                        "only: drive multi-line interactive programs with terminal_write instead."
                    ),
                },
                "timeout_ms": TIMEOUT_MS,
                "max_bytes": MAX_BYTES,
                "raw": RAW,
            },
        },
    },
    "terminal_resize": {
        "name": "terminal_resize",
        "description": (
            "Change the PTY window size. Use it when a program's output is wrapping badly, when a TUI "
            "refuses to draw correctly, or when a pager truncates columns, and also before you read "
            "output you intend to parse column-wise. Purely cosmetic for line-oriented commands - skip "
            "it if plain output already reads fine."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id", "cols", "rows"],
            "properties": {
                "session_id": SESSION_ID,
                "cols": {"type": "integer", "minimum": 2, "maximum": 1000,
                         "description": "Width in columns (clamped to 2..1000)."},
                "rows": {"type": "integer", "minimum": 2, "maximum": 1000,
                         "description": "Height in rows (clamped to 2..1000)."},
            },
        },
    },
    "terminal_close": {
        "name": "terminal_close",
        "description": (
            "Terminate a session and release its PTY. Call it when you are finished with a session - "
            "especially before opening another one - so credentials-bearing shells and background "
            "processes do not linger. Do not call it if you still expect to run more commands; "
            "reopening loses all session state (cwd, env, sudo timestamp). Closing an already-closed "
            "session returns SESSION_NOT_FOUND."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id"],
            "properties": {"session_id": SESSION_ID},
        },
    },
}
