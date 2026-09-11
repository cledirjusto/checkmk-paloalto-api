#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Service: 'Throughput' (from 'show session info').

The session table itself is covered by Checkmk's SNMP check
'Palo Alto Sessions', so no service is created for it here. Throughput has
no SNMP equivalent, which is why this section is still collected.
"""

import json
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
)

Section = Mapping[str, Any]


def parse_paloalto_api_sessions(string_table: StringTable) -> Section | None:
    if not string_table or not string_table[0]:
        return None
    return json.loads(string_table[0][0])


agent_section_paloalto_api_sessions = AgentSection(
    name="paloalto_api_sessions",
    parse_function=parse_paloalto_api_sessions,
)


def render_bits_per_second(value: float) -> str:
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"):
        if abs(value) < 1000 or unit == "Tbit/s":
            return f"{value:.2f} {unit}" if unit != "bit/s" else f"{value:.0f} {unit}"
        value /= 1000.0
    return f"{value:.2f} Tbit/s"


def _render_pps(value: float) -> str:
    return f"{value:,.0f} pkt/s"


# ---------------------------------------------------------------------------
# Throughput
# ---------------------------------------------------------------------------


def discover_throughput(section: Section) -> DiscoveryResult:
    if "kbps" in section or "pps" in section:
        yield Service()


def _mbit_levels_to_bit(levels: Any) -> Any:
    """Levels are configured in Mbit/s, the check works in bit/s."""
    if not levels or levels[0] != "fixed" or not levels[1]:
        return levels
    warn, crit = levels[1]
    return ("fixed", (float(warn) * 1_000_000.0, float(crit) * 1_000_000.0))


def check_throughput(params: Mapping[str, Any], section: Section) -> CheckResult:
    kbps = section.get("kbps")
    if kbps is not None:
        bps = float(kbps) * 1000.0
        yield from check_levels(
            bps,
            levels_upper=_mbit_levels_to_bit(params.get("levels_mbps")),
            metric_name="paloalto_throughput",
            label="Throughput",
            render_func=render_bits_per_second,
        )
    pps = section.get("pps")
    if pps is not None:
        yield from check_levels(
            float(pps),
            levels_upper=params.get("levels_pps"),
            metric_name="paloalto_pps",
            label="Packets",
            render_func=_render_pps,
        )
    if kbps is None and pps is None:
        yield Result(state=State.UNKNOWN, summary="No throughput information")


check_plugin_paloalto_api_throughput = CheckPlugin(
    name="paloalto_api_throughput",
    service_name="Throughput",
    sections=["paloalto_api_sessions"],
    discovery_function=discover_throughput,
    check_function=check_throughput,
    check_ruleset_name="paloalto_api_throughput",
    check_default_parameters={
        "levels_mbps": ("no_levels", None),
        "levels_pps": ("no_levels", None),
    },
)
