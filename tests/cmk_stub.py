#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""A minimal stand-in for ``cmk.agent_based.v2``.

The check plug-ins can only be imported inside a Checkmk site, so their check
functions were never exercised by the test suite - a Result built with both
``summary`` and ``notice`` reached a production firewall before anything
complained. This module reproduces the parts of the API the plug-ins use,
*including its validation rules*, so the check functions can be run here.

It is a test aid, not a reimplementation: where Checkmk raises, this raises.
"""

from __future__ import annotations

import enum
import sys
import types
from collections.abc import Mapping
from typing import Any


class State(enum.IntEnum):
    OK = 0
    WARN = 1
    CRIT = 2
    UNKNOWN = 3

    @staticmethod
    def worst(*states: State) -> State:
        return max(states) if states else State.OK


class Result:
    def __init__(
        self,
        *,
        state: State,
        summary: str | None = None,
        notice: str | None = None,
        details: str | None = None,
    ) -> None:
        # the rule that the real API enforces and that this suite exists to catch
        if summary is not None and notice is not None:
            raise TypeError("'summary' and 'notice' are mutually exclusive arguments")
        if summary is None and notice is None and details is None:
            raise TypeError("at least 'summary', 'notice' or 'details' is required")
        for name, value in (("summary", summary), ("notice", notice)):
            if value is not None and "\n" in value:
                raise ValueError(f"'{name}' must be a one-line string")
        self.state = state
        self.summary = summary or ""
        self.notice = notice or ""
        self.details = details or summary or notice or ""

    def __repr__(self) -> str:
        return f"Result(state={self.state!r}, summary={self.summary!r}, notice={self.notice!r})"


class Metric:
    def __init__(
        self,
        name: str,
        value: float,
        *,
        levels: tuple[float, float] | None = None,
        boundaries: tuple[float | None, float | None] | None = None,
    ) -> None:
        if not name or " " in name:
            raise ValueError(f"invalid metric name: {name!r}")
        self.name = name
        self.value = value
        self.levels = levels
        self.boundaries = boundaries

    def __repr__(self) -> str:
        return f"Metric({self.name!r}, {self.value!r})"


class Service:
    def __init__(self, *, item: str | None = None, parameters: Mapping[str, Any] | None = None):
        self.item = item
        self.parameters = parameters or {}

    def __repr__(self) -> str:
        return f"Service(item={self.item!r})"


class _Render:
    @staticmethod
    def percent(value: float) -> str:
        return f"{value:.2f}%"

    @staticmethod
    def timespan(seconds: float) -> str:
        return f"{seconds:.0f}s"

    @staticmethod
    def bytes(value: float) -> str:
        return f"{value:.0f}B"


render = _Render()


def check_levels(
    value: float,
    *,
    levels_upper: Any = None,
    levels_lower: Any = None,
    metric_name: str | None = None,
    label: str | None = None,
    render_func: Any = None,
    boundaries: Any = None,
    notice_only: bool = False,
):
    """Same shape as the real helper: yields a Result and optionally a Metric."""
    text = render_func(value) if render_func else str(value)
    state = State.OK
    for levels, worse in ((levels_upper, True), (levels_lower, False)):
        if not levels or levels[0] != "fixed" or not levels[1]:
            continue
        warn, crit = levels[1]
        if (value >= crit) if worse else (value <= crit):
            state = State.CRIT
        elif (value >= warn) if worse else (value <= warn):
            state = State.worst(state, State.WARN)
    summary = f"{label}: {text}" if label else text
    yield Result(state=state, **({"notice": summary} if notice_only else {"summary": summary}))
    if metric_name:
        yield Metric(metric_name, value, boundaries=boundaries)


class _Registered:
    """Captures the plug-in declarations so tests can find them."""

    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


AgentSection = _Registered
CheckPlugin = _Registered
SimpleSNMPSection = _Registered

CheckResult = Any
DiscoveryResult = Any
StringTable = list[list[str]]


class RuleSetType(enum.Enum):
    MERGED = "merged"
    ALL = "all"


def install() -> None:
    """Put this module in place of cmk.agent_based.v2 for the test session."""
    if "cmk.agent_based.v2" in sys.modules:
        return
    cmk = sys.modules.setdefault("cmk", types.ModuleType("cmk"))
    agent_based = types.ModuleType("cmk.agent_based")
    v2 = sys.modules[__name__]
    cmk.agent_based = agent_based
    agent_based.v2 = v2
    sys.modules["cmk.agent_based"] = agent_based
    sys.modules["cmk.agent_based.v2"] = v2
