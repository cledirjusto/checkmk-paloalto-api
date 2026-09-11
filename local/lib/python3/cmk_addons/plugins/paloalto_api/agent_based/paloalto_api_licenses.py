#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Services: 'License <feature>' and 'GlobalProtect <gateway>'."""

import json
import time
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

# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------


class LicenseSection:
    def __init__(self, licenses: Mapping[str, dict[str, Any]], now: int | None) -> None:
        self.licenses = licenses
        self.now = now


def parse_paloalto_api_licenses(string_table: StringTable) -> LicenseSection | None:
    if not string_table or not string_table[0]:
        return None
    raw = json.loads(string_table[0][0])
    return LicenseSection(
        licenses={lic["feature"]: lic for lic in raw.get("licenses", []) if lic.get("feature")},
        now=raw.get("now"),
    )


agent_section_paloalto_api_licenses = AgentSection(
    name="paloalto_api_licenses",
    parse_function=parse_paloalto_api_licenses,
)


def discover_licenses(section: LicenseSection) -> DiscoveryResult:
    for feature in section.licenses:
        yield Service(item=feature)


def check_license(item: str, params: Mapping[str, Any], section: LicenseSection) -> CheckResult:
    lic = section.licenses.get(item)
    if lic is None:
        return

    if lic.get("description"):
        yield Result(state=State.OK, summary=lic["description"])

    if lic.get("expired") is True:
        yield Result(
            state=State(params.get("state_expired", 2)),
            summary=f"Expired ({lic.get('expires') or 'unknown date'})",
        )
        yield Metric("paloalto_license_remaining", 0)
        return

    if lic.get("never_expires"):
        yield Result(state=State.OK, summary="Never expires")
        return

    expires_ts = lic.get("expires_ts")
    if expires_ts is None:
        yield Result(
            state=State.UNKNOWN,
            summary=f"Cannot parse expiry date '{lic.get('expires')}'",
        )
        return

    now = section.now or time.time()
    remaining = float(expires_ts - now)
    if remaining <= 0:
        yield Result(
            state=State(params.get("state_expired", 2)),
            summary=f"Expired on {lic.get('expires')}",
        )
        yield Metric("paloalto_license_remaining", 0)
        return

    yield from check_levels(
        remaining,
        levels_lower=params.get("levels_remaining"),
        metric_name="paloalto_license_remaining",
        label="Expires in",
        render_func=render.timespan,
    )
    yield Result(state=State.OK, summary=f"on {lic.get('expires')}")
    if lic.get("issued"):
        yield Result(state=State.OK, notice=f"Issued: {lic['issued']}")


check_plugin_paloalto_api_license = CheckPlugin(
    name="paloalto_api_license",
    service_name="License %s",
    sections=["paloalto_api_licenses"],
    discovery_function=discover_licenses,
    check_function=check_license,
    check_ruleset_name="paloalto_api_license",
    check_default_parameters={
        "levels_remaining": ("fixed", (180.0 * 86400, 90.0 * 86400)),
        "state_expired": 2,
    },
)


# ---------------------------------------------------------------------------
# GlobalProtect
# ---------------------------------------------------------------------------


def parse_paloalto_api_globalprotect(string_table: StringTable) -> Mapping[str, Any] | None:
    if not string_table or not string_table[0]:
        return None
    raw = json.loads(string_table[0][0])
    # No 'Total' item: Checkmk's SNMP check 'Palo Alto Users' already reports
    # the total, and it knows the licensed maximum, which this API does not.
    return {g["name"]: g for g in raw.get("gateways", []) if g.get("name")}


agent_section_paloalto_api_globalprotect = AgentSection(
    name="paloalto_api_globalprotect",
    parse_function=parse_paloalto_api_globalprotect,
)


def discover_globalprotect(section: Mapping[str, Any]) -> DiscoveryResult:
    for name in section:
        yield Service(item=name)


def check_globalprotect(
    item: str, params: Mapping[str, Any], section: Mapping[str, Any]
) -> CheckResult:
    gw = section.get(item)
    if gw is None:
        return
    yield from check_levels(
        gw.get("current_users") or 0,
        levels_upper=params.get("levels_users"),
        levels_lower=params.get("levels_users_lower"),
        metric_name="paloalto_gp_users",
        label="Connected users",
        render_func=lambda v: f"{v:.0f}",
    )
    prev = gw.get("previous_users")
    if prev is not None:
        yield Result(state=State.OK, notice=f"Previous users: {prev}")


check_plugin_paloalto_api_globalprotect = CheckPlugin(
    name="paloalto_api_globalprotect",
    service_name="GlobalProtect %s",
    sections=["paloalto_api_globalprotect"],
    discovery_function=discover_globalprotect,
    check_function=check_globalprotect,
    check_ruleset_name="paloalto_api_globalprotect",
    check_default_parameters={
        "levels_users": ("no_levels", None),
        "levels_users_lower": ("no_levels", None),
    },
)
