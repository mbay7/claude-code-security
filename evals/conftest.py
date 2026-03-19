"""
Shared fixtures and module loaders for claude-code-security evals.

Hook files use hyphens in their names, so we use importlib to load them
rather than standard imports.
"""

import importlib.util
import os
import sys

HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")


def load_hook(filename: str):
    """Load a hook module by filename (supports hyphenated names)."""
    name = filename.replace("-", "_").replace(".py", "")
    path = os.path.join(HOOKS_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
