"""hermes-rce - PTY terminal tools for Hermes (SSE + REST PoC transport).

Install: copy this directory to ~/.hermes/plugins/hermes-rce, then:
  hermes plugins enable hermes-rce
  hermes plugins doctor hermes-rce --ci
"""
from __future__ import annotations

import json
import logging
import os

from . import schemas, tools
from ._core import TerminalTools
from .host import RestHost

logger = logging.getLogger("hermes.plugins.hermes-rce")

DEFAULT_POLICY = {"allow": [".*"], "deny": []}


def _policy_from_env() -> dict:
    """HERMES_RCE_POLICY is a JSON object: {"allow": [regex...], "deny": [regex...]}.

    Empty allow[] AND empty deny[] => deny-all. The built-in blocklist
    (rm -rf /, mkfs, dd of=/dev/*, shutdown/reboot, chmod 777 /, curl|sh,
    wget|sh, > /etc/passwd, ~/.ssh, ~/.aws) is always applied.
    A Python callable can be passed programmatically as policy["approve"].
    """
    raw = os.environ.get("HERMES_RCE_POLICY", "")
    if not raw:
        return dict(DEFAULT_POLICY)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {
                "allow": list(parsed.get("allow") or []),
                "deny": list(parsed.get("deny") or []),
            }
    except ValueError:
        logger.warning("HERMES_RCE_POLICY is not valid JSON; using default policy")
    return dict(DEFAULT_POLICY)


def register(ctx) -> None:
    settings = getattr(ctx, "settings", None) or {}

    def cfg(key: str, env: str, default):
        val = settings.get(key)
        if val in (None, ""):
            val = os.environ.get(env, default)
        return val

    host = RestHost(base_url=str(cfg("base_url", "HERMES_RCE_BASE_URL", "http://127.0.0.1:8899")))
    t = TerminalTools(
        host=host,
        policy=_policy_from_env(),
        logger=lambda r: logger.info("terminal %s", json.dumps(r)),
        default_timeout_ms=int(cfg("default_timeout_ms", "HERMES_RCE_DEFAULT_TIMEOUT_MS", 30000)),
        max_bytes=int(cfg("max_bytes", "HERMES_RCE_MAX_BYTES", 8192)),
    )
    handlers = tools.make_handlers(t)
    for name in schemas.ORDER:
        ctx.register_tool(name=name, toolset="terminal", schema=schemas.SCHEMAS[name], handler=handlers[name])
    logger.info("hermes-rce registered %d tools", len(schemas.ORDER))
