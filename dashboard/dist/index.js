/* hermes-rce dashboard tab — IIFE, no build step, React comes from the SDK. */
(function () {
  "use strict";

  const SDK = window.__HERMES_PLUGIN_SDK__;
  if (!SDK) return; // dashboard without plugin support
  const { React } = SDK;
  const hooks = SDK.hooks;
  const { Card, CardHeader, CardTitle, CardContent, Button, Input, Badge } = SDK.components;
  const cn = SDK.utils.cn;

  const API = "/api/plugins/hermes-rce";

  function SessionsPanel({ sessions, active, onOpen, onClose, onSelect }) {
    return React.createElement(Card, null,
      React.createElement(CardHeader, null,
        React.createElement(CardTitle, { className: "text-sm" }, "Sessions"),
      ),
      React.createElement(CardContent, { className: "space-y-2" },
        React.createElement(OpenForm, { onOpen: onOpen }),
        sessions.length === 0
          ? React.createElement("p", { className: "text-xs text-muted-foreground" }, "No open sessions.")
          : React.createElement("ul", { className: "space-y-1" },
              sessions.map((s) =>
                React.createElement("li", { key: s, className: "flex items-center gap-2" },
                  React.createElement(Button, {
                    variant: "ghost", className: cn("h-7 px-2 text-xs font-mono", active === s && "underline"),
                    onClick: () => onSelect(s), title: "select",
                  }, s),
                  React.createElement(Button, {
                    variant: "ghost", className: "h-7 px-2 text-xs text-destructive",
                    onClick: () => onClose(s), title: "close session",
                  }, "close"),
                ),
              ),
            ),
      ),
    );
  }

  function OpenForm({ onOpen }) {
    const [shell, setShell] = hooks.useState("");
    const [busy, setBusy] = hooks.useState(false);
    const open = async () => {
      setBusy(true);
      try { await onOpen(shell.trim()); } finally { setBusy(false); }
    };
    return React.createElement("div", { className: "flex gap-2" },
      React.createElement(Input, {
        placeholder: "shell (optional, e.g. /bin/bash)",
        value: shell, onChange: (e) => setShell(e.target.value), className: "h-8 text-xs font-mono",
      }),
      React.createElement(Button, { size: "sm", className: "h-8", disabled: busy, onClick: open }, "open"),
    );
  }

  function OutputViewer({ sid }) {
    const [text, setText] = hooks.useState("");
    const [truncated, setTruncated] = hooks.useState(false);
    const cursorRef = hooks.useRef(0);
    const boxRef = hooks.useRef(null);

    hooks.useEffect(() => { // reset when the active session changes
      cursorRef.current = 0;
      setText("");
    }, [sid]);

    hooks.useEffect(() => {
      if (!sid) return undefined;
      let alive = true;
      const poll = async () => {
        try {
          const r = await SDK.fetchJSON(`${API}/sessions/${encodeURIComponent(sid)}/output?cursor=${cursorRef.current}`);
          if (!alive || !r || typeof r.data !== "string") return;
          if (r.data) {
            cursorRef.current = r.cursor;
            setText((prev) => (prev + r.data).slice(-64 * 1024));
            setTruncated(Boolean(r.truncated));
            const box = boxRef.current;
            if (box) box.scrollTop = box.scrollHeight;
          }
        } catch (e) { /* transport down; keep polling */ }
      };
      poll();
      const id = setInterval(poll, 1500);
      return () => { alive = false; clearInterval(id); };
    }, [sid]);

    return React.createElement("pre", {
      ref: boxRef,
      className: "h-80 overflow-auto rounded-md border bg-card p-3 font-mono text-xs whitespace-pre-wrap",
    }, text || "— no output yet —",
      truncated ? React.createElement(Badge, { className: "ml-2" }, "clipped: old lines dropped") : null);
  }

  function CommandBar({ sid, onSent }) {
    const [cmd, setCmd] = hooks.useState("");
    const [busy, setBusy] = hooks.useState(false);
    const send = async (mode) => {
      if (!sid || !cmd.trim()) return;
      setBusy(true);
      try {
        if (mode === "exec") {
          await SDK.fetchJSON(`${API}/sessions/${encodeURIComponent(sid)}/exec`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ command: cmd }),
          });
        } else {
          await SDK.fetchJSON(`${API}/sessions/${encodeURIComponent(sid)}/input`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: cmd }),
          });
        }
        setCmd("");
        onSent();
      } finally { setBusy(false); }
    };
    const onKey = (e) => { if (e.key === "Enter") send("exec"); };
    return React.createElement("div", { className: "flex gap-2" },
      React.createElement(Input, {
        placeholder: sid ? "command (Enter = exec, newline appended server-side)" : "open a session first",
        value: cmd, onChange: (e) => setCmd(e.target.value), onKeyDown: onKey,
        disabled: !sid || busy, className: "h-8 font-mono text-xs",
      }),
      React.createElement(Button, { size: "sm", className: "h-8", disabled: !sid || busy, onClick: () => send("exec") }, "exec"),
      React.createElement(Button, { size: "sm", variant: "outline", className: "h-8", disabled: !sid || busy, onClick: () => send("write"), title: "raw write, no newline" }, "write"),
    );
  }

  function HermesRcePage() {
    const [sessions, setSessions] = hooks.useState([]);
    const [active, setActive] = hooks.useState(null);
    const [error, setError] = hooks.useState("");

    const refresh = hooks.useCallback(async () => {
      try {
        const r = await SDK.fetchJSON(`${API}/sessions`);
        const ids = Array.isArray(r) ? r : (r.sessions || []);
        setSessions(ids.map((s) => (typeof s === "string" ? s : s.session_id || s.id)).filter(Boolean));
        setError("");
      } catch (e) { setError(String(e && e.message ? e.message : e)); }
    }, []);

    hooks.useEffect(() => { refresh(); }, [refresh]);

    const openSession = async (shell) => {
      const r = await SDK.fetchJSON(`${API}/sessions`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(shell ? { shell } : {}),
      });
      await refresh();
      if (r && r.session_id) setActive(r.session_id);
    };

    const closeSession = async (sid) => {
      try { await SDK.fetchJSON(`${API}/sessions/${encodeURIComponent(sid)}`, { method: "DELETE" }); } finally { await refresh(); }
    };

    return React.createElement("div", { className: "space-y-4" },
      React.createElement(Card, null,
        React.createElement(CardHeader, null,
          React.createElement(CardTitle, { className: "flex items-center gap-2 text-sm" },
            "hermes-rce",
            active ? React.createElement(Badge, { variant: "outline", className: "font-mono text-xs" }, active) : null,
          ),
        ),
        React.createElement(CardContent, { className: "space-y-3" },
          error ? React.createElement("p", { className: "text-xs text-destructive" }, `transport error: ${error}`) : null,
          React.createElement(CommandBar, { sid: active, onSent: () => {} }),
        ),
      ),
      React.createElement("div", { className: "grid gap-4 md:grid-cols-[1fr_280px]" },
        React.createElement(Card, null,
          React.createElement(CardHeader, null,
            React.createElement(CardTitle, { className: "text-sm" }, "Output"),
          ),
          React.createElement(CardContent, null, React.createElement(OutputViewer, { sid: active })),
        ),
        React.createElement(SessionsPanel, {
          sessions, active, onSelect: setActive,
          onOpen: openSession, onClose: closeSession,
        }),
      ),
    );
  }

  window.__HERMES_PLUGINS__.register("hermes-rce", HermesRcePage);
})();
