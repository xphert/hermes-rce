"""Tool handlers - thin JSON wrappers over the engine.

Handler rules (Hermes contract):
1. receive args (dict) - the parameters the LLM passed
2. do the work
3. return a JSON string - ALWAYS, even on error
4. accept **kwargs for forward compatibility
"""
from __future__ import annotations

import json
from typing import Callable, Dict

from ._core import TerminalTools


def make_handlers(t: TerminalTools) -> Dict[str, Callable[[dict], str]]:
    def wrap(name: str) -> Callable[[dict], str]:
        def handler(args: dict, **kwargs) -> str:
            return json.dumps(t.call(name, dict(args or {})), default=str)

        handler.__name__ = name
        return handler

    return {name: wrap(name) for name in (
        "terminal_open",
        "terminal_write",
        "terminal_read",
        "terminal_wait_for",
        "terminal_exec",
        "terminal_resize",
        "terminal_close",
    )}
