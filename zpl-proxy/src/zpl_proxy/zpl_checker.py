"""Re-export of the shared ZPL engine.

The engine + live-call adapter moved to the framework-free **`zpl-engine`**
package — one source of truth, shared with the Defender (was a drifting copy).
Existing `from .zpl_checker import …` / `from zpl_proxy.zpl_checker import …`
call sites keep working. See `zpl_engine.checker` for the implementation.
"""
from __future__ import annotations

from zpl_engine.checker import *  # noqa: F401,F403
from zpl_engine.checker import (  # explicit re-exports the watcher imports
    VERB,
    CompiledRuleSet,
    Decision,
    ZPLCompileError,
    check,
    compile_rules,
    lint_rules,
    verb_for_method,
)
