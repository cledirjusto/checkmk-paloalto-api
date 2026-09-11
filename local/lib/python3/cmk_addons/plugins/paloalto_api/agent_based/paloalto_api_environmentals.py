#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Service: 'Power Supply ...'.

Fans and temperature sensors are covered by Checkmk's SNMP checks, and the
individual voltage rails were 29 services reporting one thing, so neither
gets a service here. Power supplies have no SNMP equivalent on this hardware,
which is why the section is still collected.
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
)

Section = Mapping[str, list[dict[str, Any]]]


def _item_name(entry: Mapping[str, Any]) -> str:
    desc = (entry.get("description") or "").strip()
    slot = (entry.get("slot") or "").strip()
    return f"{slot} {desc}".strip() if slot else desc


def parse_paloalto_api_environmentals(string_table: StringTable) -> Section | None:
    if not string_table or not string_table[0]:
        return None
    raw = json.loads(string_table[0][0])
    # index by item name so the checks are cheap
    return {category: {_item_name(e): e for e in entries} for category, entries in raw.items()}


agent_section_paloalto_api_environmentals = AgentSection(
    name="paloalto_api_environmentals",
    parse_function=parse_paloalto_api_environmentals,
)


def _discover(category: str):
    def _discovery(section: Section) -> DiscoveryResult:
        for item in section.get(category, {}):
            yield Service(item=item)

    return _discovery


def _alarm_result(entry: Mapping[str, Any]) -> Result:
    alarm = entry.get("alarm")
    if alarm is True:
        return Result(state=State.CRIT, summary="Alarm")
    if alarm is False:
        return Result(state=State.OK, summary="No alarm")
    return Result(state=State.UNKNOWN, summary="Alarm state unknown")


# ---------------------------------------------------------------------------
# Power supplies
# ---------------------------------------------------------------------------


def check_power_supply(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    entry = section.get("power_supply", {}).get(item)
    if entry is None:
        return
    inserted = entry.get("inserted")
    if inserted is False:
        yield Result(state=State(params.get("state_not_inserted", 1)), summary="Not inserted")
    elif inserted is True:
        yield Result(state=State.OK, summary="Inserted")
    yield _alarm_result(entry)
    yield Metric(
        "paloalto_healthy", 1 if (entry.get("alarm") is False and inserted is not False) else 0
    )


check_plugin_paloalto_api_power_supply = CheckPlugin(
    name="paloalto_api_power_supply",
    service_name="Power Supply %s",
    sections=["paloalto_api_environmentals"],
    discovery_function=_discover("power_supply"),
    check_function=check_power_supply,
    check_ruleset_name="paloalto_api_power_supply",
    check_default_parameters={"state_not_inserted": 1},
)


# ---------------------------------------------------------------------------
# Power rails (voltages)
