#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Run the check functions themselves, against the cmk API stand-in.

Everything else in this suite stops at the agent. These tests go one step
further and consume what the check plug-ins yield, so a Result the real API
would refuse to build fails here rather than on a firewall.
"""

from __future__ import annotations

import pytest
from conftest import load_check_plugin

PLUGINS = [
    "paloalto_api_bgp",
    "paloalto_api_capacity",
    "paloalto_api_environmentals",
    "paloalto_api_licenses",
    "paloalto_api_public_ip",
    "paloalto_api_sessions",
    "paloalto_api_system",
    "paloalto_api_vpn",
]


@pytest.mark.parametrize("name", PLUGINS)
def test_plugin_imports_against_the_real_api_shape(name):
    assert load_check_plugin(name) is not None


def _consume(results):
    """Force the generator so every Result and Metric is actually built."""
    return list(results)


# ---------------------------------------------------------------------------
# Public IP - the check that crashed on a real firewall
# ---------------------------------------------------------------------------

PUBLIC_IP_SECTION = {
    "203.0.113.0/24": {
        "used": 187,
        "usable": 254,
        "total": 256,
        "by_source": {"arp": 40, "interface": 5, "nat": 160},
    },
    "198.51.100.224/27": {
        "used": 29,
        "usable": 30,
        "total": 32,
        "by_source": {"arp": 3, "interface": 2, "nat": 27},
    },
}


def test_public_ip_yields_buildable_results():
    """Regression: Result(summary=..., notice=...) is refused by the API."""
    mod = load_check_plugin("paloalto_api_public_ip")
    params = mod.check_plugin_paloalto_api_public_ip.check_default_parameters
    for item in PUBLIC_IP_SECTION:
        results = _consume(mod.check_public_ip(item, params, PUBLIC_IP_SECTION))
        assert results, item


def test_public_ip_reports_usage_and_state():
    mod = load_check_plugin("paloalto_api_public_ip")
    params = mod.check_plugin_paloalto_api_public_ip.check_default_parameters

    ok = _consume(mod.check_public_ip("203.0.113.0/24", params, PUBLIC_IP_SECTION))
    summaries = " ".join(r.summary for r in ok if hasattr(r, "summary"))
    assert "187 of 254" in summaries
    assert max(r.state for r in ok if hasattr(r, "state")) == 0  # 73.6% is below 80

    # 29 of 30 is 96.7% - above the 90 crit level
    crit = _consume(mod.check_public_ip("198.51.100.224/27", params, PUBLIC_IP_SECTION))
    assert max(r.state for r in crit if hasattr(r, "state")) == 2


def test_public_ip_counts_all_addresses_when_the_block_is_routed():
    mod = load_check_plugin("paloalto_api_public_ip")
    params = dict(mod.check_plugin_paloalto_api_public_ip.check_default_parameters)
    params["count_all_addresses"] = True
    results = _consume(mod.check_public_ip("198.51.100.224/27", params, PUBLIC_IP_SECTION))
    summaries = " ".join(r.summary for r in results if hasattr(r, "summary"))
    assert "29 of 32" in summaries


def test_public_ip_discovers_one_service_per_network():
    mod = load_check_plugin("paloalto_api_public_ip")
    items = {s.item for s in mod.discover_public_ip(PUBLIC_IP_SECTION)}
    assert items == set(PUBLIC_IP_SECTION)


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------

BGP_SECTION = {
    "up": {
        "name": "up",
        "status": "Established",
        "established": True,
        "remote_as": "65000",
        "peer_address": "203.0.113.1",
        "status_duration_sec": 2020586,
        "prefix_limit": 5000,
        "prefixes_received": 54,
        "prefixes_sent": 54,
        "flap_count": 1,
        "last_error": "",
    },
    "down": {
        "name": "down",
        "status": "Active",
        "established": False,
        "remote_as": "65010",
        "peer_address": "203.0.113.2",
        "flap_count": 7,
        "last_error": "Hold Timer Expired",
    },
}


def _bgp(peers, ha_passive=False):
    """Build the parsed section the way the agent feeds it."""
    mod = load_check_plugin("paloalto_api_bgp")
    return mod.BgpSection(ha_passive=ha_passive, peers=peers)


def test_bgp_states():
    mod = load_check_plugin("paloalto_api_bgp")
    params = mod.check_plugin_paloalto_api_bgp.check_default_parameters
    up = _consume(mod.check_bgp("up", params, _bgp(BGP_SECTION)))
    assert max(r.state for r in up if hasattr(r, "state")) == 0
    # 'Active' is a transient state on the way up: WARN, not CRIT
    down = _consume(mod.check_bgp("down", params, _bgp(BGP_SECTION)))
    assert max(r.state for r in down if hasattr(r, "state")) == 1


def test_bgp_hard_down_is_critical():
    mod = load_check_plugin("paloalto_api_bgp")
    params = mod.check_plugin_paloalto_api_bgp.check_default_parameters
    peers = {"x": {**BGP_SECTION["down"], "status": "NoNeighbor"}}
    results = _consume(mod.check_bgp("x", params, _bgp(peers)))
    assert max(r.state for r in results if hasattr(r, "state")) == 2


def test_bgp_parse_reads_the_ha_flag():
    """The agent sets ha_passive on the section, as it does for the VPN ones."""
    mod = load_check_plugin("paloalto_api_bgp")
    raw = '{"ha_passive": true, "peers": [{"name": "p", "status": "Idle"}]}'
    section = mod.parse_paloalto_api_bgp([[raw]])
    assert section.ha_passive is True
    assert list(section.peers) == ["p"]
    # an older agent, or a device that is not in a pair, omits the flag
    assert mod.parse_paloalto_api_bgp([['{"peers": []}']]).ha_passive is False


def test_bgp_idle_on_the_standby_is_ok():
    """A firewall that is not active runs no BGP, so Idle is expected."""
    mod = load_check_plugin("paloalto_api_bgp")
    params = mod.check_plugin_paloalto_api_bgp.check_default_parameters
    peers = {"x": {**BGP_SECTION["down"], "status": "Idle"}}

    on_standby = _consume(mod.check_bgp("x", params, _bgp(peers, ha_passive=True)))
    assert max(r.state for r in on_standby if hasattr(r, "state")) == 0
    assert any("HA passive member" in r.summary for r in on_standby if hasattr(r, "summary"))

    # the same peer on the active member is still a transient failure
    on_active = _consume(mod.check_bgp("x", params, _bgp(peers)))
    assert max(r.state for r in on_active if hasattr(r, "state")) == 1


def test_bgp_hard_down_on_the_standby_is_also_excused():
    """Nothing comes up on the standby, whatever the peer state says."""
    mod = load_check_plugin("paloalto_api_bgp")
    params = mod.check_plugin_paloalto_api_bgp.check_default_parameters
    peers = {"x": {**BGP_SECTION["down"], "status": "NoNeighbor"}}
    results = _consume(mod.check_bgp("x", params, _bgp(peers, ha_passive=True)))
    assert max(r.state for r in results if hasattr(r, "state")) == 0


def test_bgp_standby_state_is_configurable():
    mod = load_check_plugin("paloalto_api_bgp")
    params = {
        **mod.check_plugin_paloalto_api_bgp.check_default_parameters,
        "state_down_passive": 1,
    }
    peers = {"x": {**BGP_SECTION["down"], "status": "Idle"}}
    results = _consume(mod.check_bgp("x", params, _bgp(peers, ha_passive=True)))
    assert max(r.state for r in results if hasattr(r, "state")) == 1


def test_bgp_standby_ignores_the_configured_lower_levels():
    """Levels the user set for the active member must not fire on the standby."""
    mod = load_check_plugin("paloalto_api_bgp")
    params = {
        **mod.check_plugin_paloalto_api_bgp.check_default_parameters,
        "levels_uptime": ("fixed", (3600.0, 900.0)),
        "levels_prefixes": ("fixed", (10, 1)),
    }
    peers = {
        "x": {
            **BGP_SECTION["down"],
            "status": "Idle",
            "status_duration_sec": 12.0,
            "prefixes_received": 0,
        }
    }
    on_standby = _consume(mod.check_bgp("x", params, _bgp(peers, ha_passive=True)))
    assert max(r.state for r in on_standby if hasattr(r, "state")) == 0
    # the metrics are still there, only the comparison is gone
    names = {m.name for m in on_standby if hasattr(m, "name")}
    assert "paloalto_bgp_uptime" in names
    assert "paloalto_bgp_prefixes_received" in names

    on_active = _consume(mod.check_bgp("x", params, _bgp(peers)))
    assert max(r.state for r in on_active if hasattr(r, "state")) == 2


def test_bgp_discovery_finds_peers_on_the_standby_too():
    mod = load_check_plugin("paloalto_api_bgp")
    items = {s.item for s in mod.discover_bgp(_bgp(BGP_SECTION, ha_passive=True))}
    assert items == {"up", "down"}


# ---------------------------------------------------------------------------
# Capacity, licences, VPN, HA
# ---------------------------------------------------------------------------


def test_capacity_reports_usage_against_the_device_limit():
    mod = load_check_plugin("paloalto_api_capacity")
    params = mod.check_plugin_paloalto_api_capacity.check_default_parameters
    section = {"items": {"security_rule": {"used": 569, "max": 30000}}}
    results = _consume(mod.check_capacity("Security rules", params, section))
    assert any("569" in r.summary for r in results if hasattr(r, "summary"))


def test_licence_expired_is_critical():
    mod = load_check_plugin("paloalto_api_licenses")
    params = mod.check_plugin_paloalto_api_license.check_default_parameters
    section = mod.LicenseSection(
        {"X": {"feature": "X", "expired": True, "expires": "February 17, 2026"}}, now=1800000000
    )
    results = _consume(mod.check_license("X", params, section))
    assert max(r.state for r in results if hasattr(r, "state")) == 2


def test_vpn_ipsec_down_is_critical_but_ok_on_the_passive_member():
    mod = load_check_plugin("paloalto_api_vpn")
    params = mod.check_plugin_paloalto_api_vpn_ipsec.check_default_parameters
    tunnel = {"name": "t", "state": "init", "sas": []}

    active = mod.VpnSection(ha_passive=False, entries={"t": tunnel})
    assert (
        max(
            r.state
            for r in _consume(mod.check_vpn_ipsec("t", params, active))
            if hasattr(r, "state")
        )
        == 2
    )

    passive = mod.VpnSection(ha_passive=True, entries={"t": tunnel})
    assert (
        max(
            r.state
            for r in _consume(mod.check_vpn_ipsec("t", params, passive))
            if hasattr(r, "state")
        )
        == 0
    )


def test_ha_translates_the_expected_state_back_to_the_panos_spelling():
    mod = load_check_plugin("paloalto_api_system")
    params = {"expected_state": "active_primary", "state_unexpected": 1, "state_not_synced": 1}
    section = {
        "enabled": True,
        "local_state": "active-primary",
        "peer_state": "active-secondary",
        "peer_conn_status": "up",
        "running_sync": "synchronized",
    }
    results = _consume(mod.check_ha(params, section))
    assert max(r.state for r in results if hasattr(r, "state")) == 0
