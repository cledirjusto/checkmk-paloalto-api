#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Services: 'VPN IKE <gateway>' (phase 1) and 'VPN IPsec <tunnel>' (phase 2)."""

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


class VpnSection:
    def __init__(self, ha_passive: bool, entries: Mapping[str, dict[str, Any]]) -> None:
        self.ha_passive = ha_passive
        self.entries = entries


def _parse(key: str):
    def _parse_function(string_table: StringTable) -> VpnSection | None:
        if not string_table or not string_table[0]:
            return None
        raw = json.loads(string_table[0][0])
        return VpnSection(
            ha_passive=bool(raw.get("ha_passive")),
            entries={e["name"]: e for e in raw.get(key, []) if e.get("name")},
        )

    return _parse_function


agent_section_paloalto_api_vpn_ike = AgentSection(
    name="paloalto_api_vpn_ike",
    parse_function=_parse("gateways"),
)

agent_section_paloalto_api_vpn_ipsec = AgentSection(
    name="paloalto_api_vpn_ipsec",
    parse_function=_parse("tunnels"),
)


def _discover(section: VpnSection) -> DiscoveryResult:
    for name in section.entries:
        yield Service(item=name)


def _gateway_of(tunnel_name: str) -> str:
    """'to_Fortigate_Phase2:Switch-6A-Data' -> 'to_Fortigate_Phase2'."""
    return tunnel_name.split(":", 1)[0]


def _metric_name(tunnel_name: str) -> str:
    """A per-tunnel metric name for the grouped service."""
    proxy = tunnel_name.split(":", 1)[1] if ":" in tunnel_name else tunnel_name
    return f"paloalto_vpn_up_{proxy}"


def discover_vpn_ipsec(params: Mapping[str, Any], section: VpnSection) -> DiscoveryResult:
    """One service per tunnel, or one per IKE gateway.

    Grouping suits on-demand tunnels, where phase 2 only comes up when there
    is traffic and an individual tunnel being down means nothing. One service
    per tunnel suits always-on site-to-site links, where it means everything.
    """
    if params.get("grouping") == "gateway":
        for gateway in sorted({_gateway_of(name) for name in section.entries}):
            yield Service(item=gateway)
        return
    for name in section.entries:
        yield Service(item=name)


def _down_state(params: Mapping[str, Any], section: VpnSection) -> State:
    if section.ha_passive:
        return State(params.get("state_down_passive", 0))
    return State(params.get("state_down", 2))


# ---------------------------------------------------------------------------
# Phase 1 - IKE gateways
# ---------------------------------------------------------------------------


def check_vpn_ike(item: str, params: Mapping[str, Any], section: VpnSection) -> CheckResult:
    gw = section.entries.get(item)
    if gw is None:
        return

    sa = gw.get("ike_sa")
    if sa:
        yield Result(state=State.OK, summary="Phase 1 established")
        details = []
        if sa.get("version"):
            details.append(f"IKE version: {sa['version']}")
        if sa.get("role"):
            details.append(f"Role: {sa['role']}")
        if sa.get("created"):
            details.append(f"Created: {sa['created']}")
        if sa.get("expires"):
            details.append(f"Expires: {sa['expires']}")
        algo = sa.get("algo") or {}
        algo_str = "/".join(v for v in (algo.get("enc"), algo.get("hash"), algo.get("dh")) if v)
        if algo_str:
            details.append(f"Algorithms: {algo_str}")
        if details:
            yield Result(state=State.OK, notice="\n".join(details))
        yield Metric("paloalto_vpn_up", 1)
    else:
        state = _down_state(params, section)
        summary = "Phase 1 not established (no IKE SA)"
        if section.ha_passive:
            summary += " - HA passive member"
        yield Result(state=state, summary=summary)
        yield Metric("paloalto_vpn_up", 0)

    peer = gw.get("peer_address")
    local = gw.get("local_address")
    if peer or local:
        yield Result(
            state=State.OK,
            summary=f"Peer: {peer or '?'}",
            details=f"Peer: {peer or '?'}\nLocal: {local or '?'}",
        )
    if gw.get("protocol"):
        yield Result(state=State.OK, notice=f"Protocol: {gw['protocol']}")


check_plugin_paloalto_api_vpn_ike = CheckPlugin(
    name="paloalto_api_vpn_ike",
    service_name="VPN IKE %s",
    sections=["paloalto_api_vpn_ike"],
    discovery_function=_discover,
    check_function=check_vpn_ike,
    check_ruleset_name="paloalto_api_vpn_ike",
    check_default_parameters={
        "state_down": 2,
        "state_down_passive": 0,
    },
)


# ---------------------------------------------------------------------------
# Phase 2 - IPsec tunnels
# ---------------------------------------------------------------------------


def _check_gateway(item: str, params: Mapping[str, Any], section: VpnSection) -> CheckResult:
    """One service covering every phase 2 tunnel of one IKE gateway."""
    members = {name: entry for name, entry in section.entries.items() if _gateway_of(name) == item}
    if not members:
        return

    active = [n for n, e in members.items() if (e.get("state") or "").lower() == "active"]
    yield from check_levels(
        len(active),
        levels_lower=params.get("levels_active"),
        metric_name="paloalto_vpn_tunnels_active",
        label="Active",
        render_func=lambda v: f"{v:.0f} of {len(members)} tunnels",
        boundaries=(0, len(members)),
    )
    yield Metric("paloalto_vpn_tunnels_total", len(members))

    # one metric per tunnel, so each still has its own graph
    for name, entry in sorted(members.items()):
        up = 1 if (entry.get("state") or "").lower() == "active" else 0
        yield Metric(_metric_name(name), up)

    down = sorted(n for n in members if n not in active)
    if down:
        yield Result(
            state=State(params.get("state_down_grouped", 0)),
            summary=f"{len(down)} not active",
        )

    details = []
    for name, entry in sorted(members.items()):
        proxy = name.split(":", 1)[1] if ":" in name else name
        nets = f"{entry.get('local_networks') or '?'} -> {entry.get('remote_networks') or '?'}"
        sas = len(entry.get("sas") or [])
        details.append(f"{proxy}: {entry.get('state') or '?'}, {sas} SA(s), {nets}")
    peer = next((e.get("peer_ip") for e in members.values() if e.get("peer_ip")), "")
    if peer:
        yield Result(state=State.OK, summary=f"Peer: {peer}")
    yield Result(state=State.OK, notice="\n".join(details))


def check_vpn_ipsec(item: str, params: Mapping[str, Any], section: VpnSection) -> CheckResult:
    tunnel = section.entries.get(item)
    if tunnel is None:
        # not a single tunnel: this is the grouped, per-gateway service
        yield from _check_gateway(item, params, section)
        return

    flow_state = (tunnel.get("state") or "unknown").lower()
    sas = tunnel.get("sas") or []

    if flow_state == "active":
        if sas:
            yield Result(state=State.OK, summary=f"Phase 2 active, {len(sas)} SA(s)")
        else:
            yield Result(
                state=State(params.get("state_no_sa", 1)),
                summary="Phase 2 active but no IPsec SA installed",
            )
        yield Metric("paloalto_vpn_up", 1)
    else:
        state = _down_state(params, section)
        summary = f"Phase 2 down (state: {flow_state})"
        if section.ha_passive:
            summary += " - HA passive member"
        yield Result(state=state, summary=summary)
        yield Metric("paloalto_vpn_up", 0)

    # Tunnel monitor
    mon = (tunnel.get("monitor") or "").lower()
    mon_status = (tunnel.get("monitor_status") or "").lower()
    if mon in ("on", "yes", "true", "enabled") and mon_status:
        if mon_status in ("up", "ok"):
            yield Result(state=State.OK, summary="Monitor: up")
        elif flow_state == "active":
            yield Result(
                state=State(params.get("state_monitor_down", 1)),
                summary=f"Monitor: {mon_status}",
            )

    # Remaining lifetime of the shortest-living SA
    remaining = [sa["remain_sec"] for sa in sas if sa.get("remain_sec") is not None]
    if remaining:
        yield from check_levels(
            float(min(remaining)),
            levels_lower=params.get("levels_remaining"),
            metric_name="paloalto_vpn_sa_remaining",
            label="SA lifetime remaining",
            render_func=render.timespan,
            notice_only=True,
        )

    # the phase 2 traffic selectors: which networks this tunnel carries
    local_nets = tunnel.get("local_networks")
    remote_nets = tunnel.get("remote_networks")
    if local_nets or remote_nets:
        yield Result(
            state=State.OK,
            summary=f"{local_nets or '?'} -> {remote_nets or '?'}",
        )

    peer = tunnel.get("peer_ip")
    local = tunnel.get("local_ip")
    if peer:
        yield Result(state=State.OK, summary=f"Peer: {peer}")
    details = []
    if local:
        details.append(f"Local: {local}")
    if tunnel.get("inner_if"):
        details.append(f"Tunnel interface: {tunnel['inner_if']}")
    if tunnel.get("outer_if"):
        details.append(f"Outer interface: {tunnel['outer_if']}")
    if tunnel.get("gateway"):
        details.append(f"IKE gateway: {tunnel['gateway']}")
    if tunnel.get("crypto_profile"):
        details.append(f"IPsec crypto profile: {tunnel['crypto_profile']}")
    for sa in sas:
        proxy = f" proxy-id {sa['proxy_id']}" if sa.get("proxy_id") else ""
        algo = "/".join(v for v in (sa.get("proto"), sa.get("enc"), sa.get("hash")) if v)
        details.append(
            f"SA{proxy}: {algo or 'n/a'}, SPI in {sa.get('spi_in')} / out {sa.get('spi_out')}"
        )
    if details:
        yield Result(state=State.OK, notice="\n".join(details))


check_plugin_paloalto_api_vpn_ipsec = CheckPlugin(
    name="paloalto_api_vpn_ipsec",
    service_name="VPN IPsec %s",
    sections=["paloalto_api_vpn_ipsec"],
    discovery_function=discover_vpn_ipsec,
    discovery_ruleset_name="paloalto_api_vpn_ipsec_discovery",
    discovery_default_parameters={"grouping": "tunnel"},
    check_function=check_vpn_ipsec,
    check_ruleset_name="paloalto_api_vpn_ipsec",
    check_default_parameters={
        "levels_active": ("no_levels", None),
        "state_down_grouped": 0,
        "state_down": 2,
        "state_down_passive": 0,
        "state_no_sa": 1,
        "state_monitor_down": 1,
        "levels_remaining": ("no_levels", None),
    },
)
