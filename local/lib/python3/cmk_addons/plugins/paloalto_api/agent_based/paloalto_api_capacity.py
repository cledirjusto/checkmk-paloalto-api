#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Service: 'Capacity <object type>'."""

import json
import time
from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    StringTable,
    check_levels,
    render,
)

# item title -> key in the agent section
CAPACITY_ITEMS: dict[str, str] = {
    "Security rules": "security_rule",
    "NAT rules": "nat_rule",
    "NAT DIPP rules": "nat_dipp_rule",
    "Address objects": "address",
    "Address groups": "address_group",
    "Service objects": "service",
    "Service groups": "service_group",
    "Zones": "zone",
    "Virtual systems": "vsys",
}

Section = Mapping[str, Any]


def parse_paloalto_api_capacity(string_table: StringTable) -> Section | None:
    if not string_table or not string_table[0]:
        return None
    return json.loads(string_table[0][0])


agent_section_paloalto_api_capacity = AgentSection(
    name="paloalto_api_capacity",
    parse_function=parse_paloalto_api_capacity,
)


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------


def discover_capacity(section: Section) -> DiscoveryResult:
    items = section.get("items", {})
    for title, key in CAPACITY_ITEMS.items():
        if key in items and items[key].get("used") is not None:
            yield Service(item=title)


def _cache_result(section: Section) -> Result | None:
    """Say how old the object counts are when they come from the cache."""
    timestamp = section.get("counts_timestamp")
    if timestamp is None or not section.get("counts_cache_age"):
        return None
    age = time.time() - timestamp
    if age < 60:
        return None
    return Result(
        state=State.OK,
        notice=f"Object counts are {render.timespan(age)} old (read from cache)",
    )


def check_capacity(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    items = section.get("items", {})
    key = CAPACITY_ITEMS.get(item)
    if key is None or key not in items:
        return
    data = items[key]
    used = data.get("used")
    if used is None:
        return

    maximum = params.get("max_override") or data.get("max")
    if maximum:
        pct = used / maximum * 100.0
        yield from check_levels(
            pct,
            levels_upper=params.get("levels_pct"),
            metric_name="paloalto_capacity_used_pct",
            label="Usage",
            render_func=render.percent,
            boundaries=(0.0, 100.0),
        )
        yield from check_levels(
            used,
            levels_upper=params.get("levels_abs"),
            metric_name="paloalto_capacity_used",
            label="Used",
            render_func=lambda v: f"{v:,.0f} of {maximum:,}",
            boundaries=(0, maximum),
        )
        source = "rule" if params.get("max_override") else "device"
        yield Result(state=State.OK, notice=f"Limit source: {source}")
    else:
        yield from check_levels(
            used,
            levels_upper=params.get("levels_abs"),
            metric_name="paloalto_capacity_used",
            label="Used",
            render_func=lambda v: f"{v:,.0f}",
        )
        yield Result(
            state=State.OK,
            summary="no limit reported by device",
            details=(
                "The firewall does not report a maximum for this object type. "
                "Set 'Maximum (override)' in the rule 'Palo Alto capacity' to get "
                "percentage based levels."
            ),
        )

    if (cache_note := _cache_result(section)) is not None:
        yield cache_note


check_plugin_paloalto_api_capacity = CheckPlugin(
    name="paloalto_api_capacity",
    service_name="Capacity %s",
    sections=["paloalto_api_capacity"],
    discovery_function=discover_capacity,
    check_function=check_capacity,
    check_ruleset_name="paloalto_api_capacity",
    check_default_parameters={
        "levels_pct": ("fixed", (80.0, 90.0)),
        "levels_abs": ("no_levels", None),
    },
)
