#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Services: 'PAN-OS System' and 'HA State'."""

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
    render,
)

Section = Mapping[str, Any]


def _parse_json(string_table: StringTable) -> Section | None:
    if not string_table or not string_table[0]:
        return None
    return json.loads(string_table[0][0])


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

agent_section_paloalto_api_system = AgentSection(
    name="paloalto_api_system",
    parse_function=_parse_json,
)


def discover_system(section: Section) -> DiscoveryResult:
    yield Service()


def check_system(section: Section) -> CheckResult:
    model = section.get("model", "unknown")
    version = section.get("sw-version", "unknown")
    serial = section.get("serial", "")
    yield Result(state=State.OK, summary=f"Model: {model}, PAN-OS: {version}")
    if serial:
        yield Result(state=State.OK, summary=f"Serial: {serial}")

    uptime = section.get("uptime_sec")
    if uptime is not None:
        yield Result(state=State.OK, summary=f"Up since {render.timespan(uptime)}")
        yield Metric("uptime", uptime)

    details = []
    for key, label in (
        ("hostname", "Hostname"),
        ("family", "Family"),
        ("operational-mode", "Operational mode"),
        ("multi-vsys", "Multi-vsys"),
        ("app-version", "Applications"),
        ("threat-version", "Threats"),
        ("av-version", "Antivirus"),
        ("wildfire-version", "WildFire"),
        ("url-filtering-version", "URL filtering"),
        ("global-protect-client-package-version", "GlobalProtect client"),
    ):
        if section.get(key):
            details.append(f"{label}: {section[key]}")
    if details:
        yield Result(state=State.OK, notice="\n".join(details))


check_plugin_paloalto_api_system = CheckPlugin(
    name="paloalto_api_system",
    service_name="PAN-OS System",
    discovery_function=discover_system,
    check_function=check_system,
)


# ---------------------------------------------------------------------------
# High availability
# ---------------------------------------------------------------------------

agent_section_paloalto_api_ha = AgentSection(
    name="paloalto_api_ha",
    parse_function=_parse_json,
)

_HA_GOOD_STATES = ("active", "passive", "active-primary", "active-secondary")
_HA_WARN_STATES = ("initial", "tentative")


def discover_ha(section: Section) -> DiscoveryResult:
    if section.get("enabled"):
        yield Service()


def check_ha(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("enabled"):
        yield Result(state=State.WARN, summary="HA is not enabled (anymore)")
        yield Metric("paloalto_healthy", 0)
        return

    local = (section.get("local_state") or "unknown").lower()
    peer = (section.get("peer_state") or "unknown").lower()
    mode = section.get("mode") or ""

    if local in _HA_GOOD_STATES:
        state = State.OK
    elif local in _HA_WARN_STATES:
        state = State.WARN
    else:
        state = State.CRIT
    yield Result(state=state, summary=f"Local: {local}")

    # The rule spec has to use valid Python identifiers, so 'active-primary'
    # arrives as 'active_primary' and is translated back here.
    expected = params.get("expected_state")
    if expected:
        expected = expected.replace("_", "-")
    if expected and expected != local:
        yield Result(
            state=State(params.get("state_unexpected", 1)),
            summary=f"expected {expected}",
        )

    if peer in _HA_GOOD_STATES:
        peer_state = State.OK
    elif peer in _HA_WARN_STATES:
        peer_state = State.WARN
    else:
        peer_state = State.CRIT
    yield Result(state=peer_state, summary=f"Peer: {peer}")

    conn = (section.get("peer_conn_status") or "").lower()
    if conn and conn != "up":
        yield Result(state=State.CRIT, summary=f"Peer connection: {conn}")

    sync = (section.get("running_sync") or "").lower()
    if sync:
        sync_ok = sync in ("synchronized", "synchronised")
        yield Result(
            state=State.OK if sync_ok else State(params.get("state_not_synced", 1)),
            summary=f"Config sync: {sync}",
        )

    if mode:
        yield Result(state=State.OK, summary=f"Mode: {mode}")

    details = []
    for key, label in (
        ("local_state_reason", "Local state reason"),
        ("peer_state_reason", "Peer state reason"),
        ("local_priority", "Local priority"),
        ("peer_priority", "Peer priority"),
        ("local_version", "Local version"),
        ("peer_version", "Peer version"),
        ("link_monitoring", "Link monitoring"),
        ("path_monitoring", "Path monitoring"),
    ):
        if section.get(key) not in (None, ""):
            details.append(f"{label}: {section[key]}")
    local_ver, peer_ver = section.get("local_version"), section.get("peer_version")
    if local_ver and peer_ver and local_ver != peer_ver:
        yield Result(state=State.WARN, summary=f"Version mismatch ({local_ver} / {peer_ver})")
    if details:
        yield Result(state=State.OK, notice="\n".join(details))

    healthy = (
        local in _HA_GOOD_STATES
        and peer in _HA_GOOD_STATES
        and conn in ("", "up")
        and (not sync or sync in ("synchronized", "synchronised"))
        and (not expected or expected == local)
    )
    yield Metric("paloalto_healthy", 1 if healthy else 0)


check_plugin_paloalto_api_ha = CheckPlugin(
    name="paloalto_api_ha",
    service_name="HA State",
    discovery_function=discover_ha,
    check_function=check_ha,
    check_ruleset_name="paloalto_api_ha",
    check_default_parameters={
        "state_not_synced": 1,
        "state_unexpected": 1,
    },
)
