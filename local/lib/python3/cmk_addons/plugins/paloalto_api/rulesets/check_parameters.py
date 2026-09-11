#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Check parameter rules (Setup > Services > Service monitoring rules)."""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    InputHint,
    Integer,
    LevelDirection,
    ServiceState,
    SimpleLevels,
    SingleChoice,
    SingleChoiceElement,
    TimeMagnitude,
    TimeSpan,
    validators,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    DiscoveryParameters,
    HostAndItemCondition,
    HostCondition,
    Topic,
)


def _pct_levels(title: str, default: tuple[float, float] = (80.0, 90.0)) -> SimpleLevels:
    return SimpleLevels(
        title=Title(title),
        form_spec_template=Float(unit_symbol="%"),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue(default),
    )


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------


def _capacity_form() -> Dictionary:
    return Dictionary(
        elements={
            "levels_pct": DictElement(
                parameter_form=_pct_levels("Upper levels on usage in % of the limit"),
            ),
            "levels_abs": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on the absolute number of objects"),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=InputHint((250, 280)),
                ),
            ),
            "max_override": DictElement(
                parameter_form=Integer(
                    title=Title("Maximum (override)"),
                    help_text=Help(
                        "Use this limit instead of the one reported by the firewall "
                        "('show system state filter cfg.general.max-*'). Needed for "
                        "object types the device does not report a limit for, or if "
                        "you want to alert against a lower planning limit. The "
                        "datasheet limits differ per model (PA-5220, PA-5410, ...)."
                    ),
                    custom_validate=(validators.NumberInRange(min_value=1),),
                    prefill=InputHint(300),
                ),
            ),
        },
    )


rule_spec_paloalto_api_capacity = CheckParameters(
    name="paloalto_api_capacity",
    title=Title("Palo Alto capacity (rules, objects, zones)"),
    topic=Topic.NETWORKING,
    parameter_form=_capacity_form,
    condition=HostAndItemCondition(item_title=Title("Object type")),
)


# ---------------------------------------------------------------------------
# Ports by speed
# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
# Throughput
# ---------------------------------------------------------------------------


def _throughput_form() -> Dictionary:
    return Dictionary(
        elements={
            "levels_mbps": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on total throughput"),
                    help_text=Help(
                        "Sum of all traffic through the dataplane as reported by "
                        "'show session info' (kbps)."
                    ),
                    form_spec_template=Float(unit_symbol="Mbit/s"),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=InputHint((10000.0, 13000.0)),
                ),
            ),
            "levels_pps": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on packets per second"),
                    form_spec_template=Integer(unit_symbol="pkt/s"),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=InputHint((2000000, 3000000)),
                ),
            ),
        },
    )


rule_spec_paloalto_api_throughput = CheckParameters(
    name="paloalto_api_throughput",
    title=Title("Palo Alto throughput"),
    topic=Topic.NETWORKING,
    parameter_form=_throughput_form,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# High availability
# ---------------------------------------------------------------------------


def _ha_form() -> Dictionary:
    return Dictionary(
        elements={
            "expected_state": DictElement(
                parameter_form=SingleChoice(
                    title=Title("Expected local HA state"),
                    help_text=Help(
                        "Alert if this member is not in the expected role, e.g. after "
                        "an unplanned failover."
                    ),
                    # The names have to be valid Python identifiers, so the
                    # active/passive states of an active/active pair are spelled
                    # with an underscore here and translated back to the PAN-OS
                    # spelling ('active-primary') by the check plug-in.
                    elements=[
                        SingleChoiceElement(name="active", title=Title("active")),
                        SingleChoiceElement(name="passive", title=Title("passive")),
                        SingleChoiceElement(
                            name="active_primary", title=Title("active-primary (A/A)")
                        ),
                        SingleChoiceElement(
                            name="active_secondary", title=Title("active-secondary (A/A)")
                        ),
                    ],
                    prefill=DefaultValue("active"),
                ),
            ),
            "state_unexpected": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the local HA state is not the expected one"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_not_synced": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the running configuration is not synchronized"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_paloalto_api_ha = CheckParameters(
    name="paloalto_api_ha",
    title=Title("Palo Alto high availability"),
    topic=Topic.NETWORKING,
    parameter_form=_ha_form,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# VPN
# ---------------------------------------------------------------------------


def _vpn_common_elements() -> dict[str, DictElement]:
    return {
        "state_down": DictElement(
            parameter_form=ServiceState(
                title=Title("State if the tunnel/gateway is down"),
                prefill=DefaultValue(ServiceState.CRIT),
            ),
        ),
        "state_down_passive": DictElement(
            parameter_form=ServiceState(
                title=Title("State if down on the passive HA member"),
                help_text=Help(
                    "On the passive member of an active/passive HA pair the tunnels "
                    "are expected to be down. Default: OK."
                ),
                prefill=DefaultValue(ServiceState.OK),
            ),
        ),
    }


def _vpn_ike_form() -> Dictionary:
    return Dictionary(elements=_vpn_common_elements())


rule_spec_paloalto_api_vpn_ike = CheckParameters(
    name="paloalto_api_vpn_ike",
    title=Title("Palo Alto VPN IKE gateways (phase 1)"),
    topic=Topic.NETWORKING,
    parameter_form=_vpn_ike_form,
    condition=HostAndItemCondition(item_title=Title("IKE gateway name")),
)


def _vpn_ipsec_discovery_form() -> Dictionary:
    return Dictionary(
        elements={
            "grouping": DictElement(
                required=True,
                parameter_form=SingleChoice(
                    title=Title("How to create the services"),
                    help_text=Help(
                        "One service per tunnel suits always-on site-to-site links, "
                        "where a single tunnel being down is a fault worth its own "
                        "alert, acknowledgement and availability report. One service "
                        "per IKE gateway suits on-demand tunnels, where phase 2 only "
                        "comes up when there is traffic and an individual tunnel "
                        "being down means nothing: the service then reports how many "
                        "of the gateway's tunnels are active, and still records one "
                        "graph per tunnel."
                    ),
                    elements=[
                        SingleChoiceElement(name="tunnel", title=Title("One service per tunnel")),
                        SingleChoiceElement(
                            name="gateway", title=Title("One service per IKE gateway")
                        ),
                    ],
                    prefill=DefaultValue("tunnel"),
                ),
            ),
        },
    )


def _vpn_ipsec_form() -> Dictionary:
    elements = _vpn_common_elements()
    elements.update(
        {
            "levels_active": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on active tunnels per gateway"),
                    help_text=Help(
                        "Only used when the services are grouped per IKE gateway. "
                        "Leave unset for on-demand tunnels, where the number of "
                        "active tunnels legitimately varies with the traffic."
                    ),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=InputHint((1, 0)),
                ),
            ),
            "state_down_grouped": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when some tunnels of a gateway are not active"),
                    help_text=Help(
                        "Only used when the services are grouped per IKE gateway. OK "
                        "by default: an on-demand tunnel is down until there is "
                        "traffic, which is not a fault."
                    ),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
            "state_no_sa": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the tunnel is active but has no IPsec SA"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_monitor_down": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the tunnel monitor reports down"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "levels_remaining": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on remaining SA lifetime"),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.HOUR, TimeMagnitude.MINUTE]
                    ),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=InputHint((300.0, 60.0)),
                ),
            ),
        }
    )
    return Dictionary(elements=elements)


rule_spec_paloalto_api_vpn_ipsec_discovery = DiscoveryParameters(
    name="paloalto_api_vpn_ipsec_discovery",
    title=Title("Palo Alto IPsec tunnel discovery"),
    topic=Topic.NETWORKING,
    parameter_form=_vpn_ipsec_discovery_form,
)


rule_spec_paloalto_api_vpn_ipsec = CheckParameters(
    name="paloalto_api_vpn_ipsec",
    title=Title("Palo Alto VPN IPsec tunnels (phase 2)"),
    topic=Topic.NETWORKING,
    parameter_form=_vpn_ipsec_form,
    condition=HostAndItemCondition(item_title=Title("IPsec tunnel name")),
)


# ---------------------------------------------------------------------------
# Public IP
# ---------------------------------------------------------------------------
# Public IP addresses
# ---------------------------------------------------------------------------


def _public_ip_form() -> Dictionary:
    return Dictionary(
        elements={
            "levels_pct": DictElement(
                parameter_form=_pct_levels("Upper levels on the block used"),
            ),
            "levels_free": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on the number of free addresses"),
                    help_text=Help(
                        "Usually the more natural way to think about a small block: "
                        "warn when fewer than N addresses are left, regardless of the "
                        "percentage."
                    ),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=InputHint((20, 10)),
                ),
            ),
            "count_all_addresses": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Count the network and broadcast address as usable"),
                    label=Label("The block is routed to the firewall, not on-link"),
                    help_text=Help(
                        "By default the first and last address of a block are not "
                        "counted as usable. If the block is routed to the firewall "
                        "rather than configured on-link, every address can be handed "
                        "out. On a /29 this is the difference between 6 and 8."
                    ),
                    prefill=DefaultValue(False),
                ),
            ),
        },
    )


rule_spec_paloalto_api_public_ip = CheckParameters(
    name="paloalto_api_public_ip",
    title=Title("Palo Alto public IP addresses"),
    topic=Topic.NETWORKING,
    parameter_form=_public_ip_form,
    condition=HostAndItemCondition(item_title=Title("Network")),
)


# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------


def _license_form() -> Dictionary:
    return Dictionary(
        elements={
            "levels_remaining": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on remaining license lifetime"),
                    form_spec_template=TimeSpan(displayed_magnitudes=[TimeMagnitude.DAY]),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue((180.0 * 86400, 90.0 * 86400)),
                ),
            ),
            "state_expired": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the license has expired"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
        },
    )


rule_spec_paloalto_api_license = CheckParameters(
    name="paloalto_api_license",
    title=Title("Palo Alto licenses / subscriptions"),
    topic=Topic.NETWORKING,
    parameter_form=_license_form,
    condition=HostAndItemCondition(item_title=Title("License feature")),
)


# ---------------------------------------------------------------------------
# GlobalProtect
# ---------------------------------------------------------------------------


def _globalprotect_form() -> Dictionary:
    return Dictionary(
        elements={
            "levels_users": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on connected users"),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=InputHint((800, 950)),
                ),
            ),
            "levels_users_lower": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on connected users"),
                    help_text=Help(
                        "Useful during business hours to detect a gateway nobody can reach anymore."
                    ),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=InputHint((1, 0)),
                ),
            ),
        },
    )


rule_spec_paloalto_api_globalprotect = CheckParameters(
    name="paloalto_api_globalprotect",
    title=Title("Palo Alto GlobalProtect gateways"),
    topic=Topic.NETWORKING,
    parameter_form=_globalprotect_form,
    condition=HostAndItemCondition(item_title=Title("Gateway name (or 'Total')")),
)


# ---------------------------------------------------------------------------
# Power supplies
# ---------------------------------------------------------------------------


def _power_supply_form() -> Dictionary:
    return Dictionary(
        elements={
            "state_not_inserted": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the power supply is not inserted"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_paloalto_api_power_supply = CheckParameters(
    name="paloalto_api_power_supply",
    title=Title("Palo Alto power supplies"),
    topic=Topic.NETWORKING,
    parameter_form=_power_supply_form,
    condition=HostAndItemCondition(item_title=Title("Power supply")),
)


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------


def _bgp_form() -> Dictionary:
    return Dictionary(
        elements={
            "state_down": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the session is not established"),
                    help_text=Help(
                        "Applies to a peer that is not established and not on its "
                        "way up, e.g. one the firewall has given up on."
                    ),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_transient": DictElement(
                parameter_form=ServiceState(
                    title=Title("State while the session is coming up"),
                    help_text=Help(
                        "Applies to the states a peer passes through on its way to "
                        "Established: Idle, Connect, Active, OpenSent, OpenConfirm."
                    ),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "levels_uptime": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on how long the session has been up"),
                    help_text=Help(
                        "Alerts on a peer that keeps re-establishing. A session that "
                        "has only been up for a few minutes has just flapped."
                    ),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.HOUR, TimeMagnitude.MINUTE],
                    ),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=InputHint((3600.0, 900.0)),
                ),
            ),
            "levels_prefix_limit_pct": DictElement(
                parameter_form=_pct_levels(
                    "Upper levels on the configured prefix limit used", (80.0, 90.0)
                ),
            ),
            "levels_prefixes": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on the number of prefixes received"),
                    help_text=Help(
                        "Catches a peer that is established but has stopped "
                        "advertising the routes you expect from it."
                    ),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=InputHint((10, 1)),
                ),
            ),
        },
    )


rule_spec_paloalto_api_bgp = CheckParameters(
    name="paloalto_api_bgp",
    title=Title("Palo Alto BGP peers"),
    topic=Topic.NETWORKING,
    parameter_form=_bgp_form,
    condition=HostAndItemCondition(item_title=Title("Peer name")),
)


__all__ = [
    "rule_spec_paloalto_api_vpn_ipsec_discovery",
    "rule_spec_paloalto_api_bgp",
    "rule_spec_paloalto_api_license",
    "rule_spec_paloalto_api_globalprotect",
    "rule_spec_paloalto_api_capacity",
    "rule_spec_paloalto_api_throughput",
    "rule_spec_paloalto_api_ha",
    "rule_spec_paloalto_api_vpn_ike",
    "rule_spec_paloalto_api_vpn_ipsec",
    "rule_spec_paloalto_api_public_ip",
    "rule_spec_paloalto_api_power_supply",
]
