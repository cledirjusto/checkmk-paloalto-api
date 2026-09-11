#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Tests for the collectors, driven by a stand-in for the PAN-OS API.

``FakeClient`` returns the ``<result>`` element of a canned API response for
each operational command, so the collectors run exactly as they do against a
real firewall.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest
from panos_fixtures import RESPONSES


def ag_error(msg):
    raise RuntimeError(msg)


class FakeClient:
    """Stand-in for PanOSClient that serves canned XML."""

    def __init__(self, responses: dict[str, str] | None = None, fail: tuple[str, ...] = ()) -> None:
        self.responses = RESPONSES if responses is None else responses
        self.fail = fail
        self.commands: list[str] = []

    def op(self, cmd: str) -> ET.Element:
        self.commands.append(cmd)
        for fragment in self.fail:
            if fragment in cmd:
                raise RuntimeError(f"simulated failure for {fragment}")
        for fragment, xml in self.responses.items():
            if cmd.startswith(fragment):
                return ET.fromstring(f"<result>{xml}</result>")
        raise AssertionError(f"no canned response for {cmd}")

    def config_get(self, xpath: str) -> ET.Element:
        self.commands.append(f"<config-get:{xpath}")
        for fragment, xml in self.responses.items():
            if fragment.startswith("<config-get:") and f"<config-get:{xpath}".startswith(fragment):
                return ET.fromstring(f"<result>{xml}</result>")
        raise ag_error(f"no canned config for {xpath}")

    def running_config(self) -> ET.Element:
        result = self.op("<show><config><running/></config></show>")
        cfg = result.find("config")
        return cfg if cfg is not None else result


@pytest.fixture
def client() -> FakeClient:
    return FakeClient()


# ---------------------------------------------------------------------------


def test_collect_system(agent, client):
    data = agent.collect_system(client)
    assert data["model"] == "PA-5220"
    assert data["serial"] == "001801000123"
    assert data["sw-version"] == "10.2.9-h1"
    assert data["uptime_sec"] == 45 * 86400 + 3 * 3600 + 12 * 60 + 55


def test_collect_ha(agent, client):
    data = agent.collect_ha(client)
    assert data["enabled"] is True
    assert data["local_state"] == "active"
    assert data["peer_state"] == "passive"
    assert data["peer_conn_status"] == "up"
    assert data["running_sync"] == "synchronized"
    assert data["link_monitoring"] == "yes"


def test_collect_ha_disabled(agent):
    client = FakeClient({"<show><high-availability>": "<enabled>no</enabled>"})
    assert agent.collect_ha(client) == {"enabled": False}


def test_collect_sessions_normalises_keys_and_separators(agent, client):
    data = agent.collect_sessions(client)
    assert data["num_active"] == 128540  # thousand separator removed
    assert data["num_max"] == 3200000
    assert data["kbps"] == 3500000
    assert "num-active" not in data


def test_collect_capacity_joins_counts_and_limits(agent, client):
    items = agent.collect_capacity(client)["items"]

    assert items["security_rule"] == {"used": 3, "max": 20000}
    assert "arp" not in items  # the ARP table is not queried any more
    assert items["address"] == {"used": 2, "max": 80000}
    # no limit is reported for NAT DIPP rules
    assert items["nat_dipp_rule"] == {"used": 0, "max": None}


def test_collect_capacity_survives_a_failing_command(agent):
    client = FakeClient(fail=("<show><system><state>",))
    items = agent.collect_capacity(client)["items"]
    # the limits could not be read, the counts from the running config still are
    assert items["security_rule"] == {"used": 3, "max": None}


def test_collect_environmentals_keeps_only_the_power_supplies(agent, client):
    """Fans, sensors and voltage rails are left to the SNMP checks."""
    data = agent.collect_environmentals(client)

    assert set(data) == {"power_supply"}
    assert [p["inserted"] for p in data["power_supply"]] == [True, False]
    assert [p["alarm"] for p in data["power_supply"]] == [False, True]
    assert data["power_supply"][0]["slot"] == "Slot1"


def test_collect_vpn_phase1_and_phase2(agent, client):
    ike, ipsec = agent.collect_vpn(client, ha_passive=False)

    gateways = {g["name"]: g for g in ike["gateways"]}
    assert gateways["gw-branch-a"]["ike_sa"]["version"] == "IKEv2"
    assert gateways["gw-branch-b"]["ike_sa"] is None
    assert ike["ha_passive"] is False

    tunnels = {t["name"]: t for t in ipsec["tunnels"]}
    assert tunnels["tun-branch-a"]["state"] == "active"
    assert tunnels["tun-branch-a"]["monitor_status"] == "up"
    assert len(tunnels["tun-branch-a"]["sas"]) == 1
    assert tunnels["tun-branch-a"]["sas"][0]["proxy_id"] == "proxy-1"
    assert tunnels["tun-branch-a"]["sas"][0]["remain_sec"] == 2400
    assert tunnels["tun-branch-b"]["state"] == "inactive"
    assert tunnels["tun-branch-b"]["sas"] == []


def test_collect_vpn_marks_the_passive_member(agent, client):
    ike, ipsec = agent.collect_vpn(client, ha_passive=True)
    assert ike["ha_passive"] is True
    assert ipsec["ha_passive"] is True


def test_collect_licenses(agent, client):
    data = agent.collect_licenses(client)
    licenses = {lic["feature"]: lic for lic in data["licenses"]}

    assert licenses["Threat Prevention"]["expires_ts"] == agent.parse_license_date("2027-03-15")
    assert licenses["Threat Prevention"]["never_expires"] is False
    assert licenses["Threat Prevention"]["expired"] is False
    assert licenses["PAN-DB URL Filtering"]["never_expires"] is True
    assert licenses["PAN-DB URL Filtering"]["expires_ts"] is None
    assert data["now"] > 0


def test_collect_globalprotect(agent, client):
    data = agent.collect_globalprotect(client)
    assert data["total_current_users"] == 142
    assert {g["name"]: g["current_users"] for g in data["gateways"]} == {
        "gp-gw-hq": 100,
        "gp-gw-dr": 42,
    }


def test_collect_globalprotect_absent_is_not_an_error(agent):
    class NoGpClient(FakeClient):
        def op(self, cmd):
            raise agent.PanOSError("Invalid command")

    assert agent.collect_globalprotect(NoGpClient()) is None


# ---------------------------------------------------------------------------
# Caching of the expensive 'show config running'
# ---------------------------------------------------------------------------


def _ran_config_command(client: FakeClient) -> bool:
    return any(c.startswith("<show><config><running/>") for c in client.commands)


def test_capacity_without_cache_reads_the_config_every_time(agent, tmp_path):
    for _ in range(2):
        client = FakeClient()
        agent.collect_capacity(client, cache_path=tmp_path / "c.json", cache_age=0)
        assert _ran_config_command(client)


def test_capacity_serves_the_second_run_from_the_cache(agent, tmp_path):
    cache = tmp_path / "c.json"

    first = FakeClient()
    a = agent.collect_capacity(first, cache_path=cache, cache_age=86400)
    assert _ran_config_command(first), "the first run has to read the configuration"
    assert cache.is_file()

    second = FakeClient()
    b = agent.collect_capacity(second, cache_path=cache, cache_age=86400)
    assert not _ran_config_command(second), "the second run must not touch the configuration"
    assert b["items"]["security_rule"]["used"] == a["items"]["security_rule"]["used"]
    assert b["counts_timestamp"] == a["counts_timestamp"]


def test_limits_are_never_cached(agent, tmp_path):
    """Only the object counts come from the cache; the limits stay live."""
    cache = tmp_path / "c.json"
    agent.collect_capacity(FakeClient(), cache_path=cache, cache_age=86400)

    client = FakeClient()
    data = agent.collect_capacity(client, cache_path=cache, cache_age=86400)

    assert not _ran_config_command(client), "the configuration came from the cache"
    assert any("<show><system><state>" in c for c in client.commands), (
        "the device limits must be queried on every run"
    )
    assert data["items"]["security_rule"]["max"] == 20000


def test_expired_cache_is_read_again(agent, tmp_path):
    import json as _json

    cache = tmp_path / "c.json"
    agent.collect_capacity(FakeClient(), cache_path=cache, cache_age=86400)

    payload = _json.loads(cache.read_text())
    payload["timestamp"] -= 90000  # older than a day
    cache.write_text(_json.dumps(payload))

    client = FakeClient()
    agent.collect_capacity(client, cache_path=cache, cache_age=86400)
    assert _ran_config_command(client)


def test_a_failing_config_read_falls_back_to_a_stale_cache(agent, tmp_path):
    import json as _json

    cache = tmp_path / "c.json"
    agent.collect_capacity(FakeClient(), cache_path=cache, cache_age=86400)
    payload = _json.loads(cache.read_text())
    payload["timestamp"] -= 90000
    cache.write_text(_json.dumps(payload))

    broken = FakeClient(fail=("<show><config><running/>",))
    data = agent.collect_capacity(broken, cache_path=cache, cache_age=86400)
    # stale counts beat losing the services entirely
    assert data["items"]["security_rule"]["used"] == 3


def test_cache_file_is_per_host_and_port(agent):
    a = agent._cache_file("/tmp/x", "10.1.1.1", 443)
    b = agent._cache_file("/tmp/x", "10.1.1.2", 443)
    c = agent._cache_file("/tmp/x", "10.1.1.1", 8443)
    assert len({a, b, c}) == 3, "HA members must not share a cache file"


def test_cache_contains_only_counts_never_configuration(agent, tmp_path):
    """The running config must not reach the disk of the monitoring server."""
    import json as _json

    cache = tmp_path / "c.json"
    agent.collect_capacity(FakeClient(), cache_path=cache, cache_age=86400)

    raw = cache.read_text()
    payload = _json.loads(raw)
    assert set(payload) == {"timestamp", "counts"}
    assert all(isinstance(v, int) for v in payload["counts"].values())
    # no trace of the configuration document itself
    for leaked in ("<", "rulebase", "entry", "devices", "shared"):
        assert leaked not in raw, f"{leaked!r} leaked into the cache file"


def test_cache_file_is_not_world_readable(agent, tmp_path):
    cache = tmp_path / "sub" / "c.json"
    agent.collect_capacity(FakeClient(), cache_path=cache, cache_age=86400)
    assert cache.stat().st_mode & 0o077 == 0, "cache must be readable by its owner only"
    assert cache.parent.stat().st_mode & 0o077 == 0


# ---------------------------------------------------------------------------
# BGP - shapes confirmed against a PA-5410 on PAN-OS 11.2.13-h1
# ---------------------------------------------------------------------------


def test_collect_bgp_reads_the_peer_name_from_the_entry_attributes(agent, client):
    """'peer' and 'vr' are attributes of <entry>, not child elements."""
    peers = {p["name"]: p for p in agent.collect_bgp(client)["peers"]}
    assert set(peers) == {"core-01", "border-01", "edge-01"}
    assert peers["core-01"]["vr"] == "default"
    assert peers["core-01"]["peer_group"] == "cores"


def test_collect_bgp_does_not_mistake_prefix_counters_for_peers(agent, client):
    """<prefix-counter> holds <entry> elements that must not become services."""
    peers = agent.collect_bgp(client)["peers"]
    assert len(peers) == 3, "the nested prefix-counter entries are not peers"


def test_collect_bgp_reads_the_nested_prefix_counters(agent, client):
    peers = {p["name"]: p for p in agent.collect_bgp(client)["peers"]}
    core = peers["core-01"]
    assert core["prefixes_received"] == 0
    assert core["prefixes_accepted"] == 0
    assert core["prefixes_sent"] == 54
    assert core["prefix_limit"] == 5000

    ibr = peers["border-01"]
    assert ibr["prefixes_received"] == 1
    assert ibr["prefixes_sent"] == 4
    assert ibr["prefix_limit"] == 1  # sits at 100% of its limit by design


def test_collect_bgp_strips_the_port_from_the_addresses(agent, client):
    peers = {p["name"]: p for p in agent.collect_bgp(client)["peers"]}
    assert peers["core-01"]["peer_address"] == "203.0.113.63"
    assert peers["core-01"]["local_address"] == "203.0.113.54"


def test_collect_bgp_state_and_flaps(agent, client):
    peers = {p["name"]: p for p in agent.collect_bgp(client)["peers"]}
    assert peers["core-01"]["established"] is True
    assert peers["core-01"]["status_duration_sec"] == 2020586
    assert peers["edge-01"]["established"] is False
    assert peers["edge-01"]["status"] == "Active"
    assert peers["edge-01"]["flap_count"] == 7
    assert peers["edge-01"]["last_error"] == "Hold Timer Expired"


def test_collect_bgp_falls_back_when_advanced_routing_is_off(agent):
    """The device answers 'advanced routing mode is not enabled' - not an error."""
    calls = []

    class Legacy(FakeClient):
        def op(self, cmd):
            calls.append(cmd)
            if "advanced-routing" in cmd:
                raise agent.PanOSError("advanced routing mode is not enabled")
            return super().op(cmd)

    assert agent.collect_bgp(Legacy()) is not None
    assert any("<routing><protocol><bgp>" in c for c in calls)


def test_collect_bgp_returns_none_when_not_configured(agent):
    class NoBgp(FakeClient):
        def op(self, cmd):
            if "bgp" in cmd:
                raise agent.PanOSError("Invalid command")
            return super().op(cmd)

    assert agent.collect_bgp(NoBgp()) is None


def test_bgp_peer_address_keeps_ipv6_intact(agent):
    assert agent._bgp_peer_address("203.0.113.1:179") == "203.0.113.1"
    assert agent._bgp_peer_address("2001:db8::1") == "2001:db8::1"
    assert agent._bgp_peer_address("") == ""
