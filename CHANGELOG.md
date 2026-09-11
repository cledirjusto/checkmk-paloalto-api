# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [1.0.1] - 2026-09-11

### Fixed

- The object-count cache could be written outside the site directory. Without
  `OMD_ROOT` and without an explicit `--cache-dir` it fell back to a temporary
  directory; inside a site that never happened, but writing outside the site is
  something the Checkmk Exchange review rejects, and rightly so. Caching is now
  simply switched off in that case.

### Changed

- The README no longer implies that 2.4 and 2.5 were tested. The extension uses
  only plug-in APIs that are identical across 2.3, 2.4 and 2.5, but it has been
  verified on 2.3.0p49 only.

## [1.0.0] - 2026-09-11

Released as `v1.0.0`. Built on an unreleased internal version of the same
number, whose original feature set is listed at the bottom; everything here is
what changed on the way to the first public release.

### Removed

- The `Power Rail` services: 29 of them on a PA-5410, reporting one thing
  between them, none of which anyone reads individually.
- The ARP query, removed earlier with the `Capacity ARP entries` service, is
  back - but only as an input to the public IP count, filtered to the
  configured blocks. No ARP entries are counted, stored or reported.
- The `Ports <speed>` services and the port counting behind them. Link state
  per port is covered by the SNMP interface checks; a count of how many ports
  are up added nothing on top of that. The interface list is now fetched only
  when public IP prefixes are configured, so a host without them makes one
  API call fewer.
- Everything Checkmk's SNMP checks already cover, so the two do not monitor
  the same thing twice: the `Interface <name>` services and the whole
  interface counter collection, `Fan <...>`, `Temperature <...>`, `Sessions`,
  and the `GlobalProtect Total` item. Decided by comparing a real SNMP walk
  of the same firewall against this plug-in's output, service by service.
  `Throughput`, power supplies, power rails and per-gateway GlobalProtect
  users stay: the SNMP walk has no equivalent for any of them.
- The `paloalto_api_interfaces` section, which the agent emitted on every
  check although no check plug-in ever declared it. The interface list is
  still fetched, because the port counts and the public IP check are built
  from it.

- The `Capacity ARP entries` service and the `show arp entry name all` command
  behind it. Counting ARP entries says nothing about configuration capacity,
  and reading the whole ARP table of the internal network to extract two
  numbers is not worth the cost on a large firewall.

### Changed

- `VPN IPsec` services can be grouped per IKE gateway instead of per tunnel,
  chosen by the new discovery rule *Palo Alto IPsec tunnel discovery*. PAN-OS
  negotiates phase 2 only when traffic arrives unless the tunnel monitor is
  enabled, so on such a firewall a tunnel in `init` is normal and one service
  per tunnel is mostly noise. The grouped service reports how many of a
  gateway's tunnels are active and still records one metric, and therefore one
  graph, per tunnel. Verified on two firewalls where all 23 tunnels have
  `mon: off`.
- `VPN IPsec` services now show the phase 2 networks, read from the proxy IDs
  under `/config/devices/entry/network/tunnel/ipsec`, together with the IKE
  gateway and the IPsec crypto profile.
- Licence expiry now warns at 6 months and goes critical at 3 months, instead
  of 30 and 7 days. Renewing a firewall subscription is not a one-week job.
- `Public IP` now counts addresses instead of checking presence. It used to
  report whether a prefix was configured on an interface with link up; it now
  answers the question the shell script it replaces answered, which is how
  much of an allocated block is in use and therefore when more addresses have
  to be requested. An address counts once if it appears in a NAT rule, in the
  ARP table or on a logical interface. Configuration changes from a prefix
  string (`203.0.113.`) to CIDR (`203.0.113.0/24`), which is what makes the
  remaining capacity computable.
- The NAT rules behind that count are read with `type=config&action=get` on a
  scoped xpath rather than from the full running configuration, and the shared
  rulebase is included - the shell script only looked at `vsys1`, so a NAT
  rule in the shared rulebase was never counted.


### Fixed

Everything below was found by capturing the real API responses of a PA-5410
running PAN-OS 11.2.13-h1 and replaying them through the collectors. The hand
written fixtures did not catch any of it, because they encoded the same
assumptions the code made.

- Capacity limits were dropped whenever the firewall reported them in hex.
  `show system state` mixes notations: 45 of the 111 `cfg.general.max-*`
  values come back as `0x13880`, the rest as plain decimal. `_to_int` parsed
  neither hex form, so six of nine capacity services showed "no limit
  reported by device". The `0x` prefix is now handled explicitly, in front of
  the existing decimal and float paths, so nothing that parsed before changes.
- The limit for NAT DIPP rules was never found: it is reported as
  `cfg.general.max-dip-nat-policy-rule`, which was not among the names looked
  for. All nine object types now get a limit from the device.
- IPsec SAs were attached to a tunnel that does not exist. PAN-OS names both
  the flow entry and the SA `<tunnel>:<proxy-id>`, but the SA was looked up
  under the part before the colon only. On the test device this produced 14
  tunnel services reporting "active but no IPsec SA installed" plus one
  invented service holding every SA. SAs are now matched on the full name,
  then on the tunnel id the two records share, and only then on the shortened
  name for older releases.
- IKE gateways showed no peer or local address. Both live in a nested `<v1>`
  or `<v2>` element as `peer-id` / `local-id`, formatted
  `203.0.113.60(ipaddr:203.0.113.60)`. The element name is also the only
  place the IKE version is stated, so it is used for that too.
- The IKE version of an SA is reported as `mode`, which was not read.
- IPsec SA SPIs are reported as `i_spi` / `o_spi`, not `i-spi` / `o-spi`.
- No `Fan` services were discovered on hardware that reports `<fans>` rather
  than `<fan>` - the PA-5410 does. Six fans were invisible.
- No `GlobalProtect` services were discovered at all. The gateways are
  `<Gateway>` elements, not `<entry>`, so the gateway list came back empty,
  and discovery then also dropped the `Total` item. Three gateways and 260
  connected users produced nothing.
- The rule *Palo Alto high availability* did not load at all: the choices for
  the expected HA state used `active-primary` / `active-secondary` as element
  names, and Checkmk requires valid Python identifiers there. The whole rule
  spec was rejected, which also left the `paloalto_api_ha` check plug-in
  pointing at a non-existent ruleset. The names now use an underscore and the
  check plug-in translates them back to the PAN-OS spelling. Caught by
  `cmk-validate-plugins` on a 2.3.0p49 site.

### Added

- `BGP Peer <name>` services: session state, remote AS, peer address, session
  uptime and prefixes received/sent, with a rule to set the state for a peer
  that is down versus one still coming up. PAN-OS does not expose BGP over
  SNMP. Confirmed against a PA-5410 on PAN-OS 11.2.13-h1: the peer name and
  virtual router are attributes of `<entry>`, and `<prefix-counter>` nests one
  `<entry>` per address family two levels below the peer, so the counters have
  to be read from the XML rather than from the flattened dictionary. Devices
  without Advanced Routing answer the newer command with "advanced routing
  mode is not enabled", which is why the legacy command is tried first.
  Also reports the configured prefix limit, the session flap counter and the
  last error.

- Repository layout around the existing extension: `local/` tree mirroring the
  site, `package.manifest`, `pyproject.toml`, `scripts/build_mkp.py`, unit
  tests and CI.
- `tests/panos_api_stub.py`, an HTTPS stand-in for the PAN-OS XML API, so the
  special agent can be run end to end without a firewall.

## [0.1.0] - 2026-09-10 (internal, never released)

### Added

- Special agent `agent_paloalto_api` querying the PAN-OS XML API. The API key
  is read from the Checkmk password store and sent in the `X-PAN-KEY` header.
- Services: `PAN-OS System`, `HA State`, `Sessions`, `Throughput`,
  `Capacity <type>`, `Ports <speed>`, `Power Supply`, `Fan`, `Temperature`,
  `Power Rail`, `Public IP <prefix>`, `VPN IKE <gateway>`,
  `VPN IPsec <tunnel>`, `License <feature>`, `GlobalProtect <gateway>` and
  `Interface <name>`.
- `Interface` services use `cmk.plugins.lib.interfaces`, so the built-in
  interface discovery and parameter rules apply.
- VPN services stay OK on the passive HA member by default.
- Check parameter rules for capacity, ports, sessions, throughput, HA, VPN
  phase 1/2, public IP, power supplies, fans, temperature, licenses and
  GlobalProtect.
- Metrics, graphs and perf-o-meters for all numeric values, plus a
  `paloalto_healthy` 1/0 metric on the state-only services.

[Unreleased]: https://github.com/cledirjusto/checkmk-paloalto-api/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/cledirjusto/checkmk-paloalto-api/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/cledirjusto/checkmk-paloalto-api/releases/tag/v1.0.0
