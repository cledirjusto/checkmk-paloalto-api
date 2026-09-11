#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Unit tests for the parsing helpers of the special agent.

These run without a Checkmk site and without a firewall: every test feeds the
agent the XML that PAN-OS returns for the corresponding command.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

# ---------------------------------------------------------------------------
# scalar helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("45 days, 3:12:55", 45 * 86400 + 3 * 3600 + 12 * 60 + 55),
        ("1 day, 0:00:01", 86401),
        ("0:00:30", 30),
        ("", None),
        ("garbage", None),
    ],
)
def test_parse_uptime(agent, value, expected):
    assert agent.parse_uptime(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("yes", True), ("True", True), ("active", True), ("no", False), ("0", False), ("?", None)],
)
def test_to_bool(agent, value, expected):
    assert agent._to_bool(value) is expected


def test_to_int_strips_thousand_separators(agent):
    assert agent._to_int("1,234") == 1234
    assert agent._to_int("12.9") == 12
    assert agent._to_int("nope", default=-1) == -1


def test_parse_license_date(agent):
    assert agent.parse_license_date("Never") is None
    assert agent.parse_license_date("") is None
    for spelling in ("March 15, 2027", "Mar 15, 2027", "2027/03/15", "2027-03-15"):
        parsed = agent.parse_license_date(spelling)
        assert parsed is not None, spelling
        # end of that day in UTC
        assert parsed == agent.parse_license_date("2027-03-15")
    assert agent.parse_license_date("15.03.2027") is None


def test_parse_system_state(agent):
    raw = """
cfg.general.max-address: 80000
cfg.general.max-policy-rule: 20000
not a key value line
cfg.general.max-zone: 900
"""
    assert agent.parse_system_state(raw) == {
        "cfg.general.max-address": "80000",
        "cfg.general.max-policy-rule": "20000",
        "cfg.general.max-zone": "900",
    }


# ---------------------------------------------------------------------------
# section builders
# ---------------------------------------------------------------------------

RUNNING_CONFIG = """
<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <zone><entry name="trust"/><entry name="untrust"/></zone>
          <address><entry name="a1"/><entry name="a2"/><entry name="a3"/></address>
          <address-group><entry name="g1"/></address-group>
          <service><entry name="s1"/><entry name="s2"/></service>
          <service-group><entry name="sg1"/></service-group>
          <rulebase>
            <security><rules><entry name="r1"/><entry name="r2"/></rules></security>
            <nat>
              <rules>
                <entry name="n1">
                  <source-translation><dynamic-ip-and-port/></source-translation>
                </entry>
                <entry name="n2"><destination-translation/></entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
  <shared>
    <address><entry name="shared1"/></address>
    <pre-rulebase>
      <security><rules><entry name="pre1"/></rules></security>
    </pre-rulebase>
  </shared>
</config>
"""


def test_count_config_objects(agent):
    counts = agent._count_config_objects(ET.fromstring(RUNNING_CONFIG))
    assert counts == {
        "address": 4,  # 3 in vsys1 + 1 shared
        "address_group": 1,
        "service": 2,
        "service_group": 1,
        "zone": 2,
        "security_rule": 3,  # 2 in the vsys rulebase + 1 shared pre-rule
        "nat_rule": 2,
        "nat_dipp_rule": 1,
        "vsys": 1,
    }


def test_count_config_objects_empty(agent):
    counts = agent._count_config_objects(ET.fromstring("<config/>"))
    assert set(counts.values()) == {0}


def test_entry_to_dict_keeps_one_nesting_level(agent):
    entry = ET.fromstring(
        '<entry name="fan1"><alarm>False</alarm><RPMs>3600</RPMs>'
        "<nested><a>1</a><b>2</b></nested></entry>"
    )
    assert agent._entry_to_dict(entry) == {
        "name": "fan1",
        "alarm": "False",
        "RPMs": "3600",
        "nested": {"a": "1", "b": "2"},
    }


# ---------------------------------------------------------------------------
# output format
# ---------------------------------------------------------------------------


def test_emit_section_is_one_json_line_with_sep0(agent, capsys):
    agent.emit_section("system", {"model": "PA-5220", "b": 1})
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "<<<paloalto_api_system:sep(0)>>>"
    assert json.loads(out[1]) == {"model": "PA-5220", "b": 1}
    assert len(out) == 2


def test_all_sections_are_accepted_by_the_argument_parser(agent):
    args = agent.parse_arguments(
        ["--host", "10.0.0.1", "--api-key", "x", "--sections", ",".join(agent.ALL_SECTIONS)]
    )
    assert args.host == "10.0.0.1"
    assert set(args.sections.split(",")) == set(agent.ALL_SECTIONS)


def test_api_key_is_mandatory(agent):
    with pytest.raises(SystemExit):
        agent.parse_arguments(["--host", "10.0.0.1"])


def test_resolve_api_key_prefers_the_plain_key(agent):
    assert agent._resolve_api_key("PLAIN", None) == "PLAIN"


def test_resolve_api_key_rejects_a_malformed_reference(agent):
    with pytest.raises(SystemExit):
        agent._resolve_api_key(None, "just-an-id")
    with pytest.raises(SystemExit):
        agent._resolve_api_key(None, None)
