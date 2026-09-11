#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Rule: 'Palo Alto Networks firewall (PAN-OS XML API)'"""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    List,
    MultipleChoice,
    MultipleChoiceElement,
    Password,
    String,
    TimeMagnitude,
    TimeSpan,
    migrate_to_password,
    validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _form() -> Dictionary:
    return Dictionary(
        title=Title("Palo Alto Networks firewall (PAN-OS XML API)"),
        help_text=Help(
            "Monitor Palo Alto Networks firewalls through the PAN-OS XML API "
            "instead of SNMP. Collects system information, HA state, session "
            "table and throughput, configuration capacity (rules, NAT, objects, "
            "zones), environmentals (power supplies, fans, temperature), "
            "licenses, GlobalProtect users, interface traffic and the state of "
            "IKE gateways (phase 1) and IPsec tunnels (phase 2). "
            "Create a read-only superuser or a custom admin role with XML API "
            "'Operational Requests' and 'Configuration' (read) permissions and "
            "generate an API key for it."
        ),
        elements={
            "api_key": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("PAN-OS API key"),
                    help_text=Help(
                        "API key of a (read-only) administrator. Generate it with "
                        "https://firewall/api/?type=keygen&user=...&password=... "
                        "Store it in the password store (Setup > General > Passwords) "
                        "so that the same key can be reused for the HA peer."
                    ),
                    migrate=migrate_to_password,
                ),
            ),
            "address": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Management address"),
                    help_text=Help(
                        "Hostname or IP address of the firewall's management "
                        "interface. If not set, the host's primary IP address (or "
                        "the host name if no IP is configured) is used."
                    ),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("TCP port"),
                    prefill=DefaultValue(443),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "verify_cert": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("TLS certificate verification"),
                    label=Label("Verify the certificate of the firewall"),
                    prefill=DefaultValue(True),
                    help_text=Help(
                        "Disable this if the management interface still uses the "
                        "factory self-signed certificate."
                    ),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=TimeSpan(
                    title=Title("HTTP timeout per request"),
                    displayed_magnitudes=[TimeMagnitude.SECOND],
                    prefill=DefaultValue(30.0),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=600),),
                ),
            ),
            "config_cache_age": DictElement(
                required=False,
                parameter_form=TimeSpan(
                    title=Title("Re-read the running configuration at most every"),
                    help_text=Help(
                        "'show config running' is the most expensive command the "
                        "agent issues and the configuration it counts changes "
                        "rarely. With this set, the object counts behind the "
                        "'Capacity ...' services are read at most that often and "
                        "served from a cache in between. The limits the device "
                        "reports and the port link states are never cached, so "
                        "'Ports ...' stays up to date. Leave unset to read the "
                        "configuration on every check."
                    ),
                    displayed_magnitudes=[
                        TimeMagnitude.DAY,
                        TimeMagnitude.HOUR,
                        TimeMagnitude.MINUTE,
                    ],
                    prefill=DefaultValue(86400.0),
                    custom_validate=(validators.NumberInRange(min_value=60, max_value=604800),),
                ),
            ),
            "sections": DictElement(
                required=False,
                parameter_form=MultipleChoice(
                    title=Title("Sections to collect"),
                    help_text=Help(
                        "Restrict the data that is fetched. All sections are collected "
                        "if this option is not set. 'System' is always collected as it "
                        "doubles as the connectivity check."
                    ),
                    elements=[
                        MultipleChoiceElement(name="ha", title=Title("High availability state")),
                        MultipleChoiceElement(name="sessions", title=Title("Throughput")),
                        MultipleChoiceElement(
                            name="capacity", title=Title("Capacity (rules, objects, zones, ...)")
                        ),
                        MultipleChoiceElement(
                            name="environmentals",
                            title=Title("Environmentals (power supplies, power rails)"),
                        ),
                        MultipleChoiceElement(
                            name="vpn", title=Title("VPN (IKE gateways and IPsec tunnels)")
                        ),
                        MultipleChoiceElement(name="bgp", title=Title("BGP peers")),
                        MultipleChoiceElement(
                            name="licenses", title=Title("Licenses / subscriptions")
                        ),
                        MultipleChoiceElement(
                            name="globalprotect", title=Title("GlobalProtect gateway users")
                        ),
                    ],
                    prefill=DefaultValue(
                        [
                            "ha",
                            "sessions",
                            "capacity",
                            "environmentals",
                            "vpn",
                            "bgp",
                            "licenses",
                            "globalprotect",
                        ]
                    ),
                ),
            ),
            "public_ip_networks": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("Public IP networks allocated to you"),
                    help_text=Help(
                        "Your public allocations in CIDR notation, e.g. "
                        "'203.0.113.0/24' or '198.51.100.224/27'. One service per "
                        "network counts how many of its addresses are in use across "
                        "the NAT rules, the ARP table and the interfaces, so that a "
                        "block filling up is noticed before it runs out. Only blocks "
                        "the firewall itself can see are counted: addresses that live "
                        "on a border router do not appear in any of those sources."
                    ),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=9),),
                    ),
                    add_element_label=Label("Add network"),
                ),
            ),
        },
    )


rule_spec_paloalto_api = SpecialAgent(
    name="paloalto_api",
    title=Title("Palo Alto Networks firewall (PAN-OS XML API)"),
    topic=Topic.NETWORKING,
    parameter_form=_form,
)
