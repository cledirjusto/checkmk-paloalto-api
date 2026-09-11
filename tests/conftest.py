#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Shared test fixtures.

The special agent is installed without a ``.py`` suffix, so it is loaded from
its path. It imports ``requests`` and ``urllib3`` at module level; both ship
with an OMD site but are not needed for the pure parsing functions the tests
exercise, so minimal stand-ins are installed when they are missing.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_PATH = (
    REPO_ROOT / "local/lib/python3/cmk_addons/plugins/paloalto_api/libexec/agent_paloalto_api"
)
PLUGIN_ROOT = REPO_ROOT / "local/lib/python3/cmk_addons/plugins/paloalto_api"


def _install_stubs() -> None:
    """Provide just enough of requests/urllib3 to import the agent."""
    if "requests" not in sys.modules:
        try:
            import requests  # noqa: F401
        except ImportError:
            requests_stub = types.ModuleType("requests")

            class _Session:
                def __init__(self) -> None:
                    self.headers: dict[str, str] = {}

                def get(self, *args, **kwargs):  # pragma: no cover - never called
                    raise RuntimeError("network access is not available in the test stub")

            requests_stub.Session = _Session
            sys.modules["requests"] = requests_stub

    if "urllib3" not in sys.modules:
        try:
            import urllib3  # noqa: F401
        except ImportError:
            urllib3_stub = types.ModuleType("urllib3")
            exceptions = types.ModuleType("urllib3.exceptions")
            exceptions.InsecureRequestWarning = type("InsecureRequestWarning", (Warning,), {})
            urllib3_stub.exceptions = exceptions
            urllib3_stub.disable_warnings = lambda *a, **k: None
            sys.modules["urllib3"] = urllib3_stub
            sys.modules["urllib3.exceptions"] = exceptions


def _load_agent() -> types.ModuleType:
    _install_stubs()
    spec = importlib.util.spec_from_loader(
        "agent_paloalto_api",
        importlib.machinery.SourceFileLoader("agent_paloalto_api", str(AGENT_PATH)),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_paloalto_api"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def agent() -> types.ModuleType:
    """The special agent, imported as a module."""
    return _load_agent()


def load_check_plugin(name: str) -> types.ModuleType:
    """Import one agent_based plug-in against the cmk API stand-in.

    Lets the check functions be exercised outside a site. The stand-in keeps
    the validation rules of the real API, so mistakes that only surface at
    check time are caught here instead of on a firewall.
    """
    import cmk_stub

    cmk_stub.install()
    path = PLUGIN_ROOT / "agent_based" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"plugin_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"plugin_{name}"] = module
    spec.loader.exec_module(module)
    return module
