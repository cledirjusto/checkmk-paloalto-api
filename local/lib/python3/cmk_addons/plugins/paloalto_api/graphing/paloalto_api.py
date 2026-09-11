#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Metrics, perf-o-meters and graphs."""

from cmk.graphing.v1 import Title, graphs, metrics, perfometers

UNIT_PERCENT = metrics.Unit(metrics.DecimalNotation("%"), metrics.AutoPrecision(1))
UNIT_COUNT = metrics.Unit(metrics.DecimalNotation(""), metrics.StrictPrecision(0))
UNIT_BITS_PER_SEC = metrics.Unit(metrics.SINotation("bit/s"), metrics.AutoPrecision(2))
UNIT_PER_SEC = metrics.Unit(metrics.SINotation("/s"), metrics.AutoPrecision(1))
UNIT_SECONDS = metrics.Unit(metrics.TimeNotation())

# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------

metric_paloalto_capacity_used_pct = metrics.Metric(
    name="paloalto_capacity_used_pct",
    title=Title("Capacity usage"),
    unit=UNIT_PERCENT,
    color=metrics.Color.BLUE,
)
metric_paloalto_capacity_used = metrics.Metric(
    name="paloalto_capacity_used",
    title=Title("Objects in use"),
    unit=UNIT_COUNT,
    color=metrics.Color.DARK_BLUE,
)

perfometer_paloalto_capacity = perfometers.Perfometer(
    name="paloalto_capacity_used_pct",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Closed(100)),
    segments=["paloalto_capacity_used_pct"],
)

graph_paloalto_capacity = graphs.Graph(
    name="paloalto_capacity",
    title=Title("Capacity usage"),
    compound_lines=["paloalto_capacity_used"],
)

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Throughput
# ---------------------------------------------------------------------------

metric_paloalto_throughput = metrics.Metric(
    name="paloalto_throughput",
    title=Title("Throughput"),
    unit=UNIT_BITS_PER_SEC,
    color=metrics.Color.CYAN,
)
metric_paloalto_pps = metrics.Metric(
    name="paloalto_pps",
    title=Title("Packets"),
    unit=UNIT_PER_SEC,
    color=metrics.Color.DARK_CYAN,
)

perfometer_paloalto_throughput = perfometers.Perfometer(
    name="paloalto_throughput",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(10_000_000_000)),
    segments=["paloalto_throughput"],
)

graph_paloalto_throughput = graphs.Graph(
    name="paloalto_throughput",
    title=Title("Throughput"),
    compound_lines=["paloalto_throughput"],
)
graph_paloalto_pps = graphs.Graph(
    name="paloalto_pps",
    title=Title("Packets per second"),
    compound_lines=["paloalto_pps"],
)

# ---------------------------------------------------------------------------
# VPN
# ---------------------------------------------------------------------------

metric_paloalto_vpn_up = metrics.Metric(
    name="paloalto_vpn_up",
    title=Title("Tunnel up (1) / down (0)"),
    unit=UNIT_COUNT,
    color=metrics.Color.GREEN,
)
metric_paloalto_vpn_sa_remaining = metrics.Metric(
    name="paloalto_vpn_sa_remaining",
    title=Title("Remaining SA lifetime"),
    unit=UNIT_SECONDS,
    color=metrics.Color.BLUE,
)

graph_paloalto_vpn_up = graphs.Graph(
    name="paloalto_vpn_up",
    title=Title("Tunnel state"),
    compound_lines=["paloalto_vpn_up"],
)

# ---------------------------------------------------------------------------
# Generic health flag (HA, power supplies, public IP)
# ---------------------------------------------------------------------------

metric_paloalto_healthy = metrics.Metric(
    name="paloalto_healthy",
    title=Title("Healthy (1) / problem (0)"),
    unit=UNIT_COUNT,
    color=metrics.Color.GREEN,
)

graph_paloalto_healthy = graphs.Graph(
    name="paloalto_healthy",
    title=Title("Health"),
    compound_lines=["paloalto_healthy"],
)

# ---------------------------------------------------------------------------
# Licenses / GlobalProtect
# ---------------------------------------------------------------------------

metric_paloalto_license_remaining = metrics.Metric(
    name="paloalto_license_remaining",
    title=Title("Remaining license lifetime"),
    unit=UNIT_SECONDS,
    color=metrics.Color.BLUE,
)
metric_paloalto_gp_users = metrics.Metric(
    name="paloalto_gp_users",
    title=Title("Connected GlobalProtect users"),
    unit=UNIT_COUNT,
    color=metrics.Color.PURPLE,
)

perfometer_paloalto_gp_users = perfometers.Perfometer(
    name="paloalto_gp_users",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(500)),
    segments=["paloalto_gp_users"],
)

graph_paloalto_gp_users = graphs.Graph(
    name="paloalto_gp_users",
    title=Title("GlobalProtect users"),
    compound_lines=["paloalto_gp_users"],
)


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------

metric_paloalto_bgp_established = metrics.Metric(
    name="paloalto_bgp_established",
    title=Title("BGP session established"),
    unit=metrics.Unit(metrics.DecimalNotation("")),
    color=metrics.Color.GREEN,
)

metric_paloalto_bgp_uptime = metrics.Metric(
    name="paloalto_bgp_uptime",
    title=Title("BGP session uptime"),
    unit=metrics.Unit(metrics.TimeNotation()),
    color=metrics.Color.BLUE,
)

metric_paloalto_bgp_prefixes_received = metrics.Metric(
    name="paloalto_bgp_prefixes_received",
    title=Title("Prefixes received"),
    unit=metrics.Unit(metrics.DecimalNotation("")),
    color=metrics.Color.CYAN,
)

metric_paloalto_bgp_prefixes_sent = metrics.Metric(
    name="paloalto_bgp_prefixes_sent",
    title=Title("Prefixes sent"),
    unit=metrics.Unit(metrics.DecimalNotation("")),
    color=metrics.Color.ORANGE,
)

perfometer_paloalto_bgp_prefixes = perfometers.Perfometer(
    name="paloalto_bgp_prefixes_received",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(1000)),
    segments=["paloalto_bgp_prefixes_received"],
)

graph_paloalto_bgp_prefixes = graphs.Graph(
    name="paloalto_bgp_prefixes",
    title=Title("BGP prefixes"),
    simple_lines=["paloalto_bgp_prefixes_received", "paloalto_bgp_prefixes_sent"],
)

metric_paloalto_bgp_flaps = metrics.Metric(
    name="paloalto_bgp_flaps",
    title=Title("BGP session flaps"),
    unit=metrics.Unit(metrics.DecimalNotation("")),
    color=metrics.Color.RED,
)

metric_paloalto_bgp_prefix_limit_used_pct = metrics.Metric(
    name="paloalto_bgp_prefix_limit_used_pct",
    title=Title("BGP prefix limit used"),
    unit=metrics.Unit(metrics.DecimalNotation("%")),
    color=metrics.Color.PURPLE,
)

metric_paloalto_public_ip_used = metrics.Metric(
    name="paloalto_public_ip_used",
    title=Title("Public addresses in use"),
    unit=metrics.Unit(metrics.DecimalNotation("")),
    color=metrics.Color.BLUE,
)

metric_paloalto_public_ip_free = metrics.Metric(
    name="paloalto_public_ip_free",
    title=Title("Public addresses free"),
    unit=metrics.Unit(metrics.DecimalNotation("")),
    color=metrics.Color.GREEN,
)

metric_paloalto_public_ip_used_pct = metrics.Metric(
    name="paloalto_public_ip_used_pct",
    title=Title("Public block used"),
    unit=metrics.Unit(metrics.DecimalNotation("%")),
    color=metrics.Color.ORANGE,
)

perfometer_paloalto_public_ip = perfometers.Perfometer(
    name="paloalto_public_ip_used_pct",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Closed(100)),
    segments=["paloalto_public_ip_used_pct"],
)

graph_paloalto_public_ip = graphs.Graph(
    name="paloalto_public_ip",
    title=Title("Public IP address usage"),
    compound_lines=["paloalto_public_ip_used"],
    simple_lines=["paloalto_public_ip_free"],
)
