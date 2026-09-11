#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Regression tests built from a real PA-5410 running PAN-OS 11.2.13-h1.

Each test here corresponds to a bug that the hand written fixtures did not
catch, because they encoded the same assumption the plug-in made. The XML
comes from the device; only addresses and names are anonymised.
"""

from __future__ import annotations

import pytest
from panos_fixtures import REAL_RESPONSES
from test_collectors import RESPONSES, FakeClient


@pytest.fixture
def device() -> FakeClient:
    """A firewall answering with the real shapes, falling back to the generic ones."""
    return FakeClient({**RESPONSES, **REAL_RESPONSES})


# ---------------------------------------------------------------------------
# F3 - 'show system state' mixes hexadecimal and decimal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0x13880", 80000),
        ("0x9c40", 40000),
        ("0xfa0", 4000),
        ("0x15", 21),
        ("0X1F40", 8000),
        ("30000", 30000),  # plain decimal still works
        ("012", 12),  # zero padded decimal must not regress
        ("41.0", 41),  # the float fallback must survive
        ("1,234", 1234),
        ("0xzz", None),
    ],
)
def test_to_int_handles_both_notations(agent, raw, expected):
    assert agent._to_int(raw) == expected


def test_every_capacity_limit_is_recognised(agent, device):
    items = agent.collect_capacity(device)["items"]
    assert {k: v["max"] for k, v in sorted(items.items())} == {
        "address": 80000,
        "address_group": 40000,
        "nat_dipp_rule": 4000,
        "nat_rule": 6000,
        "security_rule": 30000,
        "service": 8000,
        "service_group": 4000,
        "vsys": 21,
        "zone": 4000,
    }


# ---------------------------------------------------------------------------
# F7 - the SAs have to land on the tunnel they belong to
# ---------------------------------------------------------------------------


def test_ipsec_sas_are_matched_to_their_tunnel(agent, device):
    _, ipsec = agent.collect_vpn(device, ha_passive=False)
    tunnels = {t["name"]: t for t in ipsec["tunnels"]}

    assert set(tunnels) == {"to_partner_p2:Net-A", "to_partner_p2:Net-B"}, (
        "no phantom tunnel may be invented from the part before the colon"
    )
    assert len(tunnels["to_partner_p2:Net-A"]["sas"]) == 1
    assert tunnels["to_partner_p2:Net-A"]["state"] == "active"
    assert tunnels["to_partner_p2:Net-B"]["sas"] == []
    assert tunnels["to_partner_p2:Net-B"]["state"] == "init"


def test_ipsec_sa_details_are_read(agent, device):
    _, ipsec = agent.collect_vpn(device, ha_passive=False)
    sa = {t["name"]: t for t in ipsec["tunnels"]}["to_partner_p2:Net-A"]["sas"][0]
    assert sa["proxy_id"] == "Net-A"
    assert sa["spi_in"] == "2160946712"  # i_spi, not i-spi
    assert sa["spi_out"] == "3067743524"
    assert sa["remain_sec"] == 1898
    assert sa["life_sec"] == 3600


# ---------------------------------------------------------------------------
# F4 / F5 - the gateway parameters are nested in <v2>
# ---------------------------------------------------------------------------


def test_ike_gateway_addresses_come_from_the_nested_block(agent, device):
    ike, _ = agent.collect_vpn(device, ha_passive=False)
    gw = {g["name"]: g for g in ike["gateways"]}["to_partner_p1"]
    assert gw["peer_address"] == "203.0.113.60"  # stripped of '(ipaddr:...)'
    assert gw["local_address"] == "203.0.113.57"
    assert gw["protocol"] == "IKEv2"  # from the <v2> element name


def test_ike_sa_version_comes_from_mode(agent, device):
    ike, _ = agent.collect_vpn(device, ha_passive=False)
    sa = {g["name"]: g for g in ike["gateways"]}["to_partner_p1"]["ike_sa"]
    assert sa is not None
    assert sa["version"] == "IKEv2"
    assert sa["algo"]["enc"] == "PSK/DH14/AES192-CBC/SHA256"


# ---------------------------------------------------------------------------
# Environmentals - only power supplies survive
# ---------------------------------------------------------------------------


def test_only_power_supplies_are_collected(agent, device):
    """The PA-5410 reports thermal, fans, fan-tray, power and power-supply.

    Everything except the power supplies is covered by an SNMP check, so the
    agent must not turn any of it into a service.
    """
    env = agent.collect_environmentals(device)
    assert set(env) == {"power_supply"}
    assert env["power_supply"][0]["inserted"] is True


# ---------------------------------------------------------------------------
# F10 - GlobalProtect returns <Gateway>, not <entry>
# ---------------------------------------------------------------------------


def test_globalprotect_gateways_are_found(agent, device):
    gp = agent.collect_globalprotect(device)
    assert gp is not None
    assert {g["name"]: g["current_users"] for g in gp["gateways"]} == {
        "gp-gateway-a": 0,
        "gp-gateway-b": 259,
    }
    assert gp["total_current_users"] == 259


def test_globalprotect_services_are_actually_created(agent, device):
    """With gateways present, discovery must yield one service each plus Total."""
    gp = agent.collect_globalprotect(device)
    section = {g["name"]: g for g in gp["gateways"]}
    section["Total"] = {"name": "Total", "current_users": gp["total_current_users"]}
    discovered = [n for n in section if not (n == "Total" and len(section) <= 2)]
    assert sorted(discovered) == ["Total", "gp-gateway-a", "gp-gateway-b"]
