#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Service: 'Public IP <network>' - how much of an allocated block is in use.

Answers the question "when do we have to ask ARIN for more addresses". An
address counts as used when it appears in a NAT rule, in the ARP table or on a
logical interface, counted once no matter how often it occurs.
"""

import json
from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
    check_levels,
    render,
)

Section = Mapping[str, Mapping[str, Any]]

SOURCE_LABELS = {"nat": "NAT rules", "arp": "ARP table", "interface": "Interfaces"}


def parse_paloalto_api_public_ip(string_table: StringTable) -> Section | None:
    if not string_table or not string_table[0]:
        return None
    return json.loads(string_table[0][0]).get("networks", {})


agent_section_paloalto_api_public_ip = AgentSection(
    name="paloalto_api_public_ip",
    parse_function=parse_paloalto_api_public_ip,
)


def discover_public_ip(section: Section) -> DiscoveryResult:
    for network in section:
        yield Service(item=network)


def check_public_ip(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    data = section.get(item)
    if data is None:
        return

    used = data.get("used")
    if used is None:
        return
    # the network and broadcast address of an on-link block cannot be handed
    # out; set 'count_all_addresses' if the block is routed to the firewall
    capacity = data.get("total") if params.get("count_all_addresses") else data.get("usable")
    capacity = capacity or data.get("total") or 0

    if capacity:
        yield from check_levels(
            used / capacity * 100.0,
            levels_upper=params.get("levels_pct"),
            metric_name="paloalto_public_ip_used_pct",
            label="Used",
            render_func=render.percent,
            boundaries=(0.0, 100.0),
        )
        yield Result(state=State.OK, summary=f"{used} of {capacity} addresses")
        yield Metric("paloalto_public_ip_used", used, boundaries=(0, capacity))
        yield Metric("paloalto_public_ip_free", capacity - used)
        yield from check_levels(
            capacity - used,
            levels_lower=params.get("levels_free"),
            metric_name=None,
            label="Free",
            render_func=lambda v: f"{v:.0f} addresses",
            notice_only=True,
        )
    else:
        # cannot normally happen: a valid CIDR always has at least one address
        yield Result(state=State.OK, summary=f"Used: {used} addresses")
        yield Metric("paloalto_public_ip_used", used)

    by_source = data.get("by_source") or {}
    if by_source:
        # where the addresses were seen; the totals overlap, an address can be
        # in a NAT rule and in the ARP table at the same time
        yield Result(
            state=State.OK,
            summary=", ".join(
                f"{SOURCE_LABELS.get(key, key)}: {value}"
                for key, value in sorted(by_source.items())
            ),
        )


check_plugin_paloalto_api_public_ip = CheckPlugin(
    name="paloalto_api_public_ip",
    service_name="Public IP %s",
    sections=["paloalto_api_public_ip"],
    discovery_function=discover_public_ip,
    check_function=check_public_ip,
    check_ruleset_name="paloalto_api_public_ip",
    check_default_parameters={
        "levels_pct": ("fixed", (80.0, 90.0)),
        "levels_free": ("no_levels", None),
        "count_all_addresses": False,
    },
)
