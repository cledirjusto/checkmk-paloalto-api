#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Service: 'BGP Peer <name>'.

PAN-OS exposes BGP peer state only over the XML API, not over SNMP, which is
why this lives here.
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

# States a peer passes through on its way up. Anything else is a hard failure.
TRANSIENT_STATES = ("idle", "connect", "active", "opensent", "openconfirm")


def parse_paloalto_api_bgp(string_table: StringTable) -> Section | None:
    if not string_table or not string_table[0]:
        return None
    raw = json.loads(string_table[0][0])
    return {p["name"]: p for p in raw.get("peers", []) if p.get("name")}


agent_section_paloalto_api_bgp = AgentSection(
    name="paloalto_api_bgp",
    parse_function=parse_paloalto_api_bgp,
)


def discover_bgp(section: Section) -> DiscoveryResult:
    for name in section:
        yield Service(item=name)


def check_bgp(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    peer = section.get(item)
    if peer is None:
        return

    status = (peer.get("status") or "unknown").strip()
    if peer.get("established"):
        yield Result(state=State.OK, summary=f"Session: {status}")
        yield Metric("paloalto_bgp_established", 1)
    else:
        # a peer on its way up is not the same as one that will not come up
        transient = status.lower() in TRANSIENT_STATES
        state = State(
            params.get("state_transient", 1) if transient else params.get("state_down", 2)
        )
        yield Result(state=state, summary=f"Session: {status}")
        yield Metric("paloalto_bgp_established", 0)

    if peer.get("remote_as"):
        yield Result(state=State.OK, summary=f"Remote AS: {peer['remote_as']}")
    if peer.get("peer_address"):
        yield Result(state=State.OK, summary=f"Peer: {peer['peer_address']}")

    duration = peer.get("status_duration_sec")
    if duration is not None:
        # a session that just came up is worth noticing: it means it flapped
        yield from check_levels(
            float(duration),
            levels_lower=params.get("levels_uptime"),
            metric_name="paloalto_bgp_uptime",
            label="Session for",
            render_func=render.timespan,
            notice_only=True,
        )

    received = peer.get("prefixes_received")
    limit = peer.get("prefix_limit")
    if received is not None:
        yield from check_levels(
            received,
            levels_lower=params.get("levels_prefixes"),
            metric_name="paloalto_bgp_prefixes_received",
            label="Prefixes received",
            render_func=(
                (lambda v: f"{v:.0f} of {limit} (limit)") if limit else (lambda v: f"{v:.0f}")
            ),
            boundaries=(0, limit) if limit else None,
            notice_only=True,
        )
        if limit:
            # PAN-OS tears the session down when the limit is exceeded, so
            # filling it up is worth knowing about before it happens. No level
            # by default: a peer configured to accept exactly one default route
            # sits at 100% legitimately.
            yield from check_levels(
                received / limit * 100.0,
                levels_upper=params.get("levels_prefix_limit_pct"),
                metric_name="paloalto_bgp_prefix_limit_used_pct",
                label="Prefix limit used",
                render_func=render.percent,
                boundaries=(0.0, 100.0),
                notice_only=True,
            )
    if peer.get("prefixes_sent") is not None:
        yield Metric("paloalto_bgp_prefixes_sent", peer["prefixes_sent"])

    flaps = peer.get("flap_count")
    if flaps is not None:
        yield Metric("paloalto_bgp_flaps", flaps)
    if peer.get("last_error"):
        yield Result(state=State.OK, notice=f"Last error: {peer['last_error']}")

    details = []
    for key, label in (
        ("vr", "Virtual router"),
        ("peer_group", "Peer group"),
        ("local_address", "Local address"),
        ("local_as", "Local AS"),
        ("peer_router_id", "Peer router ID"),
        ("holdtime", "Hold time"),
        ("keepalive", "Keepalive"),
        ("flap_count", "Session flaps"),
    ):
        if peer.get(key):
            details.append(f"{label}: {peer[key]}")
    if peer.get("passive") is True:
        details.append("Passive: yes")
    if peer.get("password_set") is False:
        details.append("MD5 password: not set")
    if details:
        yield Result(state=State.OK, notice="\n".join(details))


check_plugin_paloalto_api_bgp = CheckPlugin(
    name="paloalto_api_bgp",
    service_name="BGP Peer %s",
    sections=["paloalto_api_bgp"],
    discovery_function=discover_bgp,
    check_function=check_bgp,
    check_ruleset_name="paloalto_api_bgp",
    check_default_parameters={
        "state_down": 2,
        "state_transient": 1,
        "levels_uptime": ("no_levels", None),
        "levels_prefixes": ("no_levels", None),
        "levels_prefix_limit_pct": ("no_levels", None),
    },
)
