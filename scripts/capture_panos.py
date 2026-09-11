#!/usr/bin/env python3
#
# Capture sanitised PAN-OS API responses from a real firewall.
#
# Copyright (C) 2026 The checkmk-paloalto-api authors
# License: GNU General Public License v2 - see LICENSE
"""Record what a real firewall answers, so the test fixtures can be based on
it instead of on guesses.

    python3 scripts/capture_panos.py --host 10.1.1.1 --api-key 'LUFRPT...' \
        --no-cert-check --out capture/

For every command the special agent issues, the raw XML is written to
``<out>/<name>.xml`` after sanitising it, with two exceptions:

    show config running       -> only the element skeleton and the counts,
                                 never rule or object names
    show arp entry name all   -> not queried at all

Sanitising replaces every IP address, serial number and hostname with a stable
placeholder, and blanks out MAC addresses entirely. The mapping is written to
``<out>/MAPPING.txt``, which stays on your machine - it is the only file that
can undo the replacement, so do not share it.

``<out>/REPORT.txt`` lists, for each field the agent is unsure about, which
spelling this firewall actually uses. That is the interesting part.
"""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import ipaddress
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("error: this script needs 'requests' (pip install requests)")

AGENT_PATH = (
    Path(__file__).resolve().parent.parent
    / "local/lib/python3/cmk_addons/plugins/paloalto_api/libexec/agent_paloalto_api"
)


def _load_agent():
    """Import the special agent so the object counts use its own logic.

    The summary of the running config has to report the same numbers the
    'Capacity ...' services will show, otherwise comparing them is misleading:
    the agent also counts shared objects and the pre/post rulebases Panorama
    pushes, not just the local vsys.
    """
    spec = importlib.util.spec_from_loader(
        "agent_paloalto_api",
        importlib.machinery.SourceFileLoader("agent_paloalto_api", str(AGENT_PATH)),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AGENT = _load_agent()

# name -> operational command, exactly as the special agent sends it
COMMANDS: dict[str, str] = {
    "system_info": "<show><system><info/></system></show>",
    "ha_state": "<show><high-availability><state/></high-availability></show>",
    "session_info": "<show><session><info/></session></show>",
    "system_state_limits": (
        "<show><system><state><filter>cfg.general.max-*</filter></state></system></show>"
    ),
    "environmentals": "<show><system><environmentals/></system></show>",
    "interface_all": "<show><interface>all</interface></show>",
    "vpn_gateway": "<show><vpn><gateway/></vpn></show>",
    "vpn_ike_sa": "<show><vpn><ike-sa/></vpn></show>",
    "vpn_flow": "<show><vpn><flow/></vpn></show>",
    "vpn_ipsec_sa": "<show><vpn><ipsec-sa/></vpn></show>",
    "bgp_peer": "<show><routing><protocol><bgp><peer/></bgp></protocol></routing></show>",
    "bgp_peer_advanced": (
        "<show><advanced-routing><bgp><peer-status/></bgp></advanced-routing></show>"
    ),
    "license_info": "<request><license><info/></license></request>",
    "globalprotect": (
        "<show><global-protect-gateway><statistics/></global-protect-gateway></show>"
    ),
    "counter_interface_all": "<show><counter><interface>all</interface></counter></show>",
}

# Captured as structure only - the full answer is confidential.
# 'show arp entry name all' is not queried at all: it would return the whole
# ARP table of the internal network for the sake of two numbers.
REDUCED: dict[str, str] = {
    "config_running": "<show><config><running/></config></show>",
}

# Fields where the agent accepts more than one spelling, i.e. where its author
# was not sure what PAN-OS actually returns. file -> (label, alternatives)
HEDGED_FIELDS: list[tuple[str, str, tuple[str, ...]]] = [
    ("vpn_gateway", "IKE gateway name", ("name", "gateway")),
    ("vpn_gateway", "IKE gateway id", ("id", "gwid")),
    ("vpn_gateway", "peer address", ("peer-address", "peer-ip")),
    ("vpn_gateway", "local address", ("local-address", "local-ip")),
    ("vpn_gateway", "protocol", ("protocol", "ike-version")),
    ("vpn_ike_sa", "SA encryption", ("algo-enc", "algo")),
    ("vpn_ike_sa", "SA hash", ("algo-hash", "hash")),
    ("vpn_ike_sa", "SA DH group", ("algo-dh", "dh")),
    ("vpn_ike_sa", "IKE version", ("ike-version", "version")),
    ("vpn_flow", "tunnel id", ("id", "tid")),
    ("vpn_flow", "tunnel monitor", ("mon", "monitor")),
    ("vpn_flow", "tunnel monitor status", ("mon-status", "monitor-status")),
    ("vpn_ipsec_sa", "SA remaining KB", ("remain-kb", "remaining-kb")),
    ("vpn_ipsec_sa", "SA lifetime KB", ("life-kb", "lifesize-kb")),
    ("license_info", "license feature", ("feature", "name")),
    ("globalprotect", "current users", ("CurrentUsers", "current-users")),
    ("globalprotect", "previous users", ("PreviousUsers", "previous-users")),
    # BGP: the whole shape is inferred, so every field here is unconfirmed
    ("bgp_peer", "BGP peer name", ("peer-name", "name", "peer")),
    ("bgp_peer", "BGP status", ("status", "state")),
    ("bgp_peer", "BGP remote AS", ("remote-as", "peer-as")),
    ("bgp_peer", "BGP peer address", ("peer-address", "peer-ip")),
    ("bgp_peer", "BGP session duration", ("status-duration", "status-dur")),
    ("bgp_peer", "BGP virtual router", ("vr", "virtual-router")),
]

# MAC addresses are replaced by this, not mapped - see Sanitiser.scrub.
BLANK_MAC = "00:00:00:00:00:00"
_MAC_SENTINEL = "\x00MAC\x00"

# 'show system state filter cfg.general.max-*' keys the agent looks for
LIMIT_KEYS: dict[str, tuple[str, ...]] = {
    "address": ("cfg.general.max-address",),
    "address_group": ("cfg.general.max-address-group",),
    "service": ("cfg.general.max-service",),
    "service_group": ("cfg.general.max-service-group",),
    "zone": ("cfg.general.max-zone",),
    "security_rule": ("cfg.general.max-policy-rule", "cfg.general.max-security-rule"),
    "nat_rule": ("cfg.general.max-nat-policy-rule", "cfg.general.max-nat-rule"),
    "nat_dipp_rule": ("cfg.general.max-nat-dipp-rule", "cfg.general.max-dipp-rule"),
    "vsys": ("cfg.general.max-vsys",),
}


class Sanitiser:
    """Replace identifying values with stable placeholders."""

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self._counters: Counter[str] = Counter()

    def _placeholder(self, kind: str, original: str) -> str:
        if original in self.mapping:
            return self.mapping[original]
        self._counters[kind] += 1
        n = self._counters[kind]
        if kind == "ip":
            # documentation ranges (RFC 5737)
            replacement = f"203.0.113.{n}" if n < 255 else f"198.51.100.{n - 254}"
        elif kind == "ip6":
            replacement = f"2001:db8::{n:x}"
        elif kind == "serial":
            replacement = f"00180100{n:04d}"
        else:
            replacement = f"{kind}{n}"
        self.mapping[original] = replacement
        return replacement

    def scrub(self, text: str) -> str:
        # MACs first, so their colon-separated bytes are not mistaken for IPv6.
        # They are blanked rather than mapped: nothing here needs them, and a
        # MAC identifies a physical device. A sentinel is used because the
        # blanked value would itself look like an IPv6 address to the pattern
        # further down.
        text = re.sub(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", _MAC_SENTINEL, text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", self._scrub_ip, text)
        text = re.sub(
            r"\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){3,7}\b",
            lambda m: self._placeholder("ip6", m.group(0).lower()),
            text,
        )
        # PAN-OS serials: 12 digits, and the <serial> element
        text = re.sub(r"\b\d{12}\b", lambda m: self._placeholder("serial", m.group(0)), text)
        text = re.sub(
            r"<(hostname|devicename)>([^<]+)</\1>",
            lambda m: f"<{m.group(1)}>{self._placeholder('firewall', m.group(2))}</{m.group(1)}>",
            text,
        )
        return text.replace(_MAC_SENTINEL, BLANK_MAC)

    def _scrub_ip(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return raw
        # keep loopback and the unspecified address, they carry no information
        if addr.is_loopback or addr.is_unspecified:
            return raw
        return self._placeholder("ip", raw)


class ReadOnlySession(requests.Session):
    """A session that physically cannot issue anything but GET.

    This script only ever reads. Any other verb is a bug, so it is refused
    here rather than reaching the firewall.
    """

    def request(self, method: str, *args, **kwargs):  # type: ignore[override]
        if method.upper() != "GET":
            raise RuntimeError(f"refusing to send {method.upper()}: this script is read-only")
        return super().request(method, *args, **kwargs)


class Client:
    def __init__(self, host: str, key: str, port: int, verify: bool, timeout: float) -> None:
        self.base = f"https://{host}:{port}/api/"
        self.session = ReadOnlySession()
        self.session.headers.update({"X-PAN-KEY": key})
        self.verify = verify
        self.timeout = timeout
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def op(self, cmd: str) -> str:
        response = self.session.get(
            self.base,
            params={"type": "op", "cmd": cmd},
            verify=self.verify,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.text


def _status_of(xml: str) -> tuple[str, str]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        return "unparseable", str(exc)
    status = root.get("status", "?")
    if status != "success":
        message = " ".join(t.strip() for t in root.itertext() if t.strip())
        return status, f"code={root.get('code', '?')}: {message[:200]}"
    return status, ""


def _skeleton(element: ET.Element, depth: int = 0, max_depth: int = 4) -> list[str]:
    """Tag structure with child counts, without any text or attribute values."""
    lines = []
    children = list(element)
    counts = Counter(child.tag for child in children)
    for tag, count in sorted(counts.items()):
        lines.append(f"{'  ' * depth}<{tag}> x{count}")
        if depth < max_depth:
            first = next(child for child in children if child.tag == tag)
            lines.extend(_skeleton(first, depth + 1, max_depth))
    return lines


def _reduce_config(xml: str) -> str:
    """Only the shape of the running config, never rule or object names."""
    root = ET.fromstring(xml)
    result = root.find("result")
    config = result.find("config") if result is not None else None
    target = config if config is not None else (result if result is not None else root)
    header = [
        "# Structure of 'show config running' - names and values deliberately omitted.",
        "# The agent only counts elements here; nothing else is read.",
        "",
    ]
    counts = AGENT._count_config_objects(target)
    counted = ["# object counts, computed exactly as the agent computes them"]
    counted.append("# (local vsys + shared + Panorama pre/post rulebases):")
    for obj_type, value in sorted(counts.items()):
        counted.append(f"#   {obj_type:<18} {value}")
    counted.append(f"#   {'shared present':<18} {target.find('shared') is not None}")
    counted.append(f"#   {'panorama present':<18} {target.find('panorama') is not None}")
    counted.append("")

    return "\n".join(header + counted + _skeleton(target)) + "\n"


def _device_header(captures: dict[str, str]) -> list[str]:
    """Name the device a capture came from, so two of them can be compared."""
    xml = captures.get("system_info")
    if xml is None:
        return ["Device: unknown (system info was not captured)", ""]
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return ["Device: unknown (system info did not parse)", ""]
    fields = [
        ("model", "Model"),
        ("family", "Family"),
        ("sw-version", "PAN-OS"),
        ("multi-vsys", "Multi-vsys"),
        ("operational-mode", "Mode"),
    ]
    lines = ["Device this capture came from:"]
    for tag, label in fields:
        value = root.findtext(f".//{tag}")
        if value:
            lines.append(f"  {label:<12} {value.strip()}")
    lines.append("")
    return lines


def _field_report(captures: dict[str, str], errors: dict[str, str]) -> list[str]:
    lines = [
        *_device_header(captures),
        "Fields the agent accepts under more than one name.",
        "'found' is the spelling this firewall uses; 'MISSING' means neither",
        "name is present, so the agent silently records an empty value.",
        "",
    ]
    for source, label, alternatives in HEDGED_FIELDS:
        if source in errors:
            # the command itself was refused - that says nothing about the
            # field names, and must not be reported as if it did
            lines.append(f"  {label:<24} {source:<22} (command failed: {errors[source]})")
            continue
        xml = captures.get(source)
        if xml is None:
            lines.append(f"  {label:<24} {source:<22} (not captured)")
            continue
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            lines.append(f"  {label:<24} {source:<22} (unparseable)")
            continue
        present = [
            alt
            for alt in alternatives
            if root.find(f".//{alt}") is not None
            or any(alt in entry.attrib for entry in root.iter("entry"))
        ]
        if present:
            note = "first choice" if present[0] == alternatives[0] else "!! second choice"
            lines.append(f"  {label:<24} {source:<22} found: {present[0]}  ({note})")
        else:
            lines.append(f"  {label:<24} {source:<22} MISSING ({'/'.join(alternatives)})")

    lines.append("")
    lines.append("Capacity limits the firewall reports (cfg.general.max-*):")
    state = captures.get("system_state_limits", "")
    found_keys = dict(re.findall(r"([\w.\-]+):\s*(.+)", state))
    for obj_type, keys in LIMIT_KEYS.items():
        hit = next((k for k in keys if k in found_keys), None)
        if hit:
            lines.append(f"  {obj_type:<16} {hit} = {found_keys[hit].strip()}")
        else:
            lines.append(f"  {obj_type:<16} MISSING ({'/'.join(keys)})")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture sanitised PAN-OS API responses")
    parser.add_argument("--host", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--no-cert-check", action="store_true")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--out", type=Path, default=Path("capture"))
    parser.add_argument(
        "--skip-config",
        action="store_true",
        help="do not run 'show config running' at all (it is the expensive command)",
    )
    args = parser.parse_args(argv)

    client = Client(args.host, args.api_key, args.port, not args.no_cert_check, args.timeout)
    sanitiser = Sanitiser()
    args.out.mkdir(parents=True, exist_ok=True)

    captures: dict[str, str] = {}
    errors: dict[str, str] = {}
    for name, cmd in COMMANDS.items():
        sys.stderr.write(f"{name:<24} ... ")
        try:
            raw = client.op(cmd)
        except Exception as exc:  # noqa: BLE001 - report and continue
            sys.stderr.write(f"FAILED: {exc}\n")
            (args.out / f"{name}.error").write_text(str(exc), encoding="utf-8")
            errors[name] = f"{type(exc).__name__}"
            continue
        status, detail = _status_of(raw)
        # the response is always kept, but a firewall that refused the command
        # has given us no data, so it does not count as a capture
        (args.out / f"{name}.xml").write_text(sanitiser.scrub(raw), encoding="utf-8")
        if status == "success":
            captures[name] = raw
        else:
            errors[name] = detail.split(":", 1)[-1].strip()[:60] or status
        sys.stderr.write(f"{status} {detail} ({len(raw):,} bytes)\n")

    for name, cmd in REDUCED.items():
        if name == "config_running" and args.skip_config:
            sys.stderr.write(f"{name:<24} ... skipped\n")
            continue
        sys.stderr.write(f"{name:<24} ... ")
        try:
            raw = client.op(cmd)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"FAILED: {exc}\n")
            (args.out / f"{name}.error").write_text(str(exc), encoding="utf-8")
            continue
        try:
            reduced = _reduce_config(raw)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"could not reduce: {exc}\n")
            continue
        (args.out / f"{name}.summary.txt").write_text(sanitiser.scrub(reduced), encoding="utf-8")
        sys.stderr.write(f"reduced from {len(raw):,} bytes\n")

    if not captures:
        sys.stderr.write(
            f"\nerror: every command failed - nothing was captured from {args.host}.\n"
            f"The .error files in {args.out}/ say why; the first one is usually enough.\n"
            "A name that does not resolve or a firewall that is not reachable from this\n"
            "machine are the common causes - try the management IP address.\n"
        )
        return 2

    report = _field_report(captures, errors)
    (args.out / "REPORT.txt").write_text("\n".join(report) + "\n", encoding="utf-8")

    mapping = ["# Local only - do not share. Undoes the sanitising.", ""]
    mapping += [f"{original}\t{replacement}" for original, replacement in sanitiser.mapping.items()]
    (args.out / "MAPPING.txt").write_text("\n".join(mapping) + "\n", encoding="utf-8")

    if errors:
        report = [
            f"WARNING: {len(errors)} of {len(COMMANDS)} commands did not return data.",
            "Their fields below say '(command failed)', which is NOT the same as a",
            "field the firewall names differently.",
            *(f"  {name}: {reason}" for name, reason in sorted(errors.items())),
            "",
            *report,
        ]
        (args.out / "REPORT.txt").write_text("\n".join(report) + "\n", encoding="utf-8")

    sys.stderr.write("\n" + "\n".join(report) + "\n")
    sys.stderr.write(
        f"\nWrote {args.out}/ - share everything EXCEPT MAPPING.txt.\n"
        f"Check the .xml files yourself before sending them anywhere.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
