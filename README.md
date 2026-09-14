# Palo Alto Networks firewalls via PAN-OS XML API – Checkmk extension

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
![Checkmk 2.3+](https://img.shields.io/badge/Checkmk-2.3%2B-green)

A Checkmk special agent plus check plug-ins for Palo Alto Networks firewalls,
built to **complement Checkmk's SNMP checks rather than duplicate them**.

Monitor the firewall over SNMP as usual. That already gives you interfaces with
their real names and aliases, CPU, memory, filesystems, fans, temperature
sensors and the session table. Add this extension for what the PAN-OS MIB does
not expose: configuration capacity, licences, BGP peers, per-tunnel VPN state,
per-gateway GlobalProtect users, public IP address usage, HA detail and power
supplies.

The API key is read from the **Checkmk password store**, so it never appears on
the command line, in the process list or in the fetcher configuration.

Verified against a **PA-5410 (PAN-OS 11.2.13-h1)** and a **PA-5220 (PAN-OS
11.2.13)**, both in active/passive HA pairs, on a **Checkmk 2.3.0p49** site. It
uses only plug-in APIs that are identical on 2.3, 2.4 and 2.5, so it should run
unchanged there, but 2.4 and 2.5 have not been tested. It should work with any
PAN-OS 9.x–11.x device, including VM-Series, that exposes the XML API.

## Services

| Service | What it does |
| --- | --- |
| `Capacity <type>` | Security rules, NAT rules, NAT DIPP rules, address objects/groups, service objects/groups, zones and virtual systems, each against the limit the firewall reports for itself |
| `License <feature>` | Subscription and support expiry (default warn 6 months, crit 3 months; expired = CRIT) |
| `VPN IPsec <tunnel>` | Phase 2 state, installed SAs, tunnel monitor, SA lifetime and the phase 2 networks. One service per tunnel, or one per IKE gateway – see *Discovery* below |
| `VPN IKE <gateway>` | Phase 1 – an IKE SA exists for the gateway, with IKE version and peer address |
| `BGP Peer <name>` | Session state, remote AS, session uptime, prefixes received against the configured prefix limit, flap counter and last error |
| `GlobalProtect <gateway>` | Connected users per gateway |
| `Public IP <network>` | How many addresses of an allocated public block are in use, so a block filling up is seen before it runs out |
| `HA State` | Local **and peer** state, peer connection, config sync, optional expected role |
| `Throughput` | Dataplane throughput (bit/s) and packets/s, with levels in Mbit/s |
| `Power Supply <slot> <name>` | Alarm and inserted state |
| `PAN-OS System` | Model, serial, PAN-OS version, uptime and the content versions (applications, threats, antivirus, WildFire, URL filtering) |

On the **passive member of an HA pair** VPN tunnels are down by design; the VPN
services are OK there by default.

## Requirements

* Checkmk 2.3.0 or newer. Raw, Pro/Enterprise and Cloud editions.
* Network access from the Checkmk site to the firewall management interface
  (HTTPS, port 443 by default).
* A PAN-OS administrator with API access. A **read-only superuser** is
  sufficient. If you use a custom admin role, enable *XML API → Operational
  Requests* and *XML API → Configuration* (read). Nothing is ever written: the
  agent issues `show` commands, `request license info` and read-only config
  queries.

## Installation

1. Download the latest `paloalto_api-<version>.mkp` from the
   [releases page](../../releases), or build it yourself (see below).
2. Install it on the central site:

   ```
   OMD[mysite]:~$ mkp add paloalto_api-1.0.1.mkp
   OMD[mysite]:~$ mkp enable paloalto_api 1.0.1
   ```

   or use *Setup → Maintenance → Extension packages* in the commercial editions.

3. Restart Apache so the new rulesets show up: `omd restart apache` (only needed
   once after installation).
4. Check that everything loaded: `cmk-validate-plugins` should report success
   for all categories.

## Configuration

### 1. Generate an API key on the firewall

Create the monitoring admin (e.g. `checkmk`, role *Superuser (read-only)*), then
generate the key:

```
curl -sk -X POST 'https://<firewall>/api/?type=keygen' \
     --data-urlencode 'user=checkmk' --data-urlencode 'password=<password>'
```

The key stays valid until that admin's password changes or it is revoked
(*Device → Setup → Management → Authentication Settings → API Key Lifetime*).
For an HA pair generate the key once; it works on both members because the admin
configuration is synchronised.

### 2. Store the key in the password store

*Setup → General → Passwords → Add password*. Give it a title like
`PAN-OS API key HQ`.

### 3. Create the hosts

One host per firewall, with the management IP as address. Set *Checkmk agent /
API integrations* to **"API integrations, no Checkmk agent"**. Leave SNMP
enabled if you monitor the firewall over SNMP as well – the two are designed to
run side by side.

### 4. Create the special agent rule

*Setup → Agents → Other integrations → Palo Alto Networks firewall (PAN-OS XML
API)*:

* **PAN-OS API key** – choose *From password store* and select the entry.
* **Management address** – optional; defaults to the host's IP.
* **TLS certificate verification** – untick for the factory self-signed
  certificate, or install a proper certificate on the management interface.
* **Re-read the running configuration at most every** – see *Cost* below.
  Defaults to one day.
* **Sections to collect** – leave all enabled, or restrict them.
* **Public IP networks allocated to you** – your allocations in CIDR notation,
  e.g. `203.0.113.0/24` and `198.51.100.224/27`. One service per network counts
  how many addresses are in use. Leave empty to skip: no service is created and
  neither the NAT nor the ARP query is sent.

  Only list blocks the firewall itself can see. An address that lives on another
  device, a border router for example, appears in none of the sources and would
  be reported as unused.

Apply the rule, activate, then run a service discovery.

### 5. Discovery: how VPN tunnels become services

*Setup → Services → Discovery rules → Palo Alto IPsec tunnel discovery* chooses
between two shapes, per host:

* **One service per tunnel** (default) – suits always-on site-to-site links,
  where one tunnel being down is a fault that deserves its own alert,
  acknowledgement and availability report.
* **One service per IKE gateway** – suits on-demand tunnels. PAN-OS negotiates
  phase 2 only when traffic arrives unless the **tunnel monitor** is enabled, so
  a tunnel sitting in `init` is normal, not a fault. The service then reports
  `Active: 5 of 10 tunnels` and still records one metric, and one graph, per
  tunnel.

To find out which case you are in, check whether the tunnel monitor is on:

```
> show vpn flow
```

`mon: off` means the tunnel comes up on demand. Note that this only tells you
about *this* firewall – on a one-way VPN the far side may be running the
monitor, keeping the tunnel up without this side knowing.

### 6. Tune thresholds (optional)

*Setup → Services → Service monitoring rules → Networking*:

* **Palo Alto capacity** – levels in % of the limit (default 80/90), absolute
  levels, or a *Maximum (override)* for object types the device does not report
  a limit for.
* **Palo Alto public IP addresses** – levels on the percentage used or on the
  number of free addresses, plus whether the network and broadcast address count
  as usable (they do not by default; set it if the block is routed to the
  firewall rather than on-link).
* **Palo Alto BGP peers** – state for a peer that is down versus one still
  coming up, state on the standby of an HA pair, lower levels on session uptime
  to catch a flapping peer, and on prefixes received.
* **Palo Alto VPN IKE gateways / IPsec tunnels** – state when down, state on the
  passive HA member, remaining SA lifetime, and for grouped services the lower
  levels on active tunnels per gateway.
* **Palo Alto high availability** – expected local state, state on config
  out-of-sync.
* **Palo Alto licenses**, **throughput**, **power supplies**, **GlobalProtect
  gateways**.

### 7. Monitoring both members of an HA pair

Each firewall is its own host, with its own management address and its own
special agent rule. The standby cannot be reached through the active member,
and the two do not report the same thing.

Two points that are easy to miss:

* **The discovery rule from step 5 has to cover both members.** If it names
  hosts, add the standby to the list. In a pair where one member groups IPsec
  tunnels by gateway and the other creates one service per tunnel, the service
  list changes on every failover.
* **On the standby, BGP peers and VPN tunnels report OK while they are down.**
  A firewall that is not the active member keeps its dataplane links down and
  runs no routing protocol, so nothing comes up until it takes over. Those
  services carry `HA passive member` in their summary, and step 6 lets you make
  the standby alarm instead. The `HA State` service tells you which member you
  are looking at.

## Cost, and the configuration cache

Eleven of the twelve API calls are cheap. The exception is `show config
running`, which returns the whole configuration and is what the `Capacity`
services count.

The agent therefore caches the object counts. **Re-read the running
configuration at most every** (default one day) controls how often that command
is actually sent; in between, the counts come from a cache under
`$OMD_ROOT/var/check_mk/paloalto_api`, written `0600` in a `0700` directory.

Only the counts are cached — nine integers. The configuration itself is counted
in memory and discarded, and never reaches the disk of the monitoring server.
The device limits and everything else stay live on every check, so nothing else
goes stale.

At a one minute check interval this is the difference between 1440 full
configuration reads a day and one.

## How it works

`agent_paloalto_api` issues these commands and prints one JSON section per
topic:

| Section | PAN-OS command(s) |
| --- | --- |
| `system` | `show system info` |
| `ha` | `show high-availability state` |
| `sessions` | `show session info` |
| `capacity` | `show config running` (counted locally, cached), `show system state filter cfg.general.max-*` |
| `environmentals` | `show system environmentals` |
| `vpn_ike` | `show vpn gateway`, `show vpn ike-sa` |
| `vpn_ipsec` | `show vpn flow`, `show vpn ipsec-sa`, plus the proxy IDs from the config for the phase 2 networks |
| `bgp` | `show routing protocol bgp peer`, falling back to `show advanced-routing bgp peer-status` |
| `licenses` | `request license info` |
| `globalprotect` | `show global-protect-gateway statistics` (skipped if not configured) |
| `public_ip` | NAT rulebases via a scoped `type=config&action=get`, `show arp all`, `show interface logical` (only when networks are configured) |

Test the agent by hand as the site user (the plain-text key is for testing only;
rules always use the password store reference):

```
OMD[mysite]:~$ ~/local/lib/python3/cmk_addons/plugins/paloalto_api/libexec/agent_paloalto_api \
      --host 10.1.1.1 --api-key 'LUFRPT…' --no-cert-check \
      --public-ip-network 203.0.113.0/24
```

and check the command line Checkmk generates with `cmk -D <host> | grep -A2 Program`.

## Notes from testing against real hardware

Worth knowing, because they are not obvious and they cost real debugging time:

* **`show system state` mixes hexadecimal and decimal, per platform.** On the
  PA-5410 forty-five of the hundred-odd `cfg.general.max-*` values come back as
  `0x13880`; on the PA-5220, running the same PAN-OS build, every value is plain
  decimal. The agent handles both. A plug-in that only parses decimal silently
  loses six of the nine capacity limits — but only on some models.
* **Configuration limits are per PAN-OS version, not per model.** A PA-5410 and
  a PA-5220 on 11.2.13 report identical maximums, even though the PA-5410 has
  3.5× the throughput. Palo Alto's own knowledge base lists 20,000 security
  rules for the PA-5220, while the device on 11.2.13 reports 30,000 — the
  published tables are snapshots, and their own advice is to ask the device with
  `show system state filter cfg.general.max*`, which is what this does.
* **Phase 2 tunnels and their SAs are both named `<tunnel>:<proxy-id>`.**
  Matching an SA to the part before the colon finds nothing and invents a tunnel
  that does not exist.
* **The GlobalProtect statistics return `<Gateway>` elements, not `<entry>`,**
  and some hardware reports `<fans>` rather than `<fan>`. Both fail silently:
  you get no services rather than an error.
* **BGP peer name and virtual router are attributes of `<entry>`,** and the
  prefix counters sit two levels below the peer, one entry per address family.

## Reporting a problem on hardware we have not tested

PAN-OS answers differently across models and versions, and not in ways the
documentation warns you about. Two firewalls on the *same* PAN-OS build
returned the configuration limits in different number bases; one model names
the fan section `<fans>` where another uses `<fan>`. Every one of those
differences produced missing services rather than an error message.

So if a service is missing or a value looks wrong on your device, the useful
thing to attach to an issue is not a description, it is what your firewall
actually replied:

```
python3 -m venv .venv && .venv/bin/pip install requests
.venv/bin/python scripts/capture_panos.py --host <ip> --api-key '<key>' \
      --no-cert-check --out capture/
cat capture/REPORT.txt
```

`REPORT.txt` names your model and PAN-OS version, then lists every field the
agent accepts under more than one spelling and says which one your firewall
uses. It also separates a field that is genuinely absent from one whose
command the device refused, which look identical in the data and mean opposite
things. That one file is usually enough to find the problem.

**It is safe to share.** The tool issues GET only, and any other verb is
refused before it leaves your machine. IP addresses, serial numbers and
hostnames are replaced by stable placeholders and MAC addresses are blanked;
the mapping that would undo this is written to `capture/MAPPING.txt`, which
stays on your machine and should not be attached. `show config running` is
reduced to element counts and a tag skeleton, never rule or object names, and
the ARP table is not queried at all. Read the `.xml` files before posting them
anyway: zone, tunnel and gateway names are kept, because they are what make the
structure readable, and yours may be more revealing than ours.

## Development

Nothing in this section ships to a site: the `.mkp` contains only the files
under `local/`. `tests/` and `scripts/` exist for working on the extension.

```
git clone https://github.com/cledirjusto/checkmk-paloalto-api
cd checkmk-paloalto-api
python3 -m venv .venv && .venv/bin/pip install pytest pydantic requests ruff
.venv/bin/python -m pytest -q
.venv/bin/ruff check . && .venv/bin/ruff format --check .
python3 scripts/build_mkp.py --update-manifest   # -> dist/paloalto_api-<version>.mkp
```

The repository mirrors the site layout, so everything under `local/` can also be
copied 1:1 into `~/local/` of a site and packaged there with
`mkp package package.manifest`.

### Running the agent without a firewall

`tests/panos_api_stub.py` serves canned PAN-OS responses over HTTPS, so changes
can be tried end to end without pointing anything at production:

```
.venv/bin/python tests/panos_api_stub.py --port 8443 &
.venv/bin/python local/lib/python3/cmk_addons/plugins/paloalto_api/libexec/agent_paloalto_api \
      --host 127.0.0.1 --port 8443 --api-key TESTKEY --no-cert-check
```

The check functions are covered too, against `tests/cmk_stub.py`, a stand-in for
`cmk.agent_based.v2` that keeps the real API's validation rules. Without it they
could only be exercised inside a site, which is how a `Result` built with two
mutually exclusive arguments once reached a production firewall.

To release, bump `version` in `package.manifest`, `pyproject.toml` and
`__version__` in the agent, update `CHANGELOG.md`, tag `v<version>`; the GitHub
workflow builds the `.mkp` and attaches it to the release.

## Compatibility notes

* Uses only the stable plug-in APIs (`cmk.agent_based.v2`, `cmk.rulesets.v1`,
  `cmk.server_side_calls.v1`, `cmk.graphing.v1`), which are identical on 2.3,
  2.4 and 2.5.
* Password store access: on 2.5+ the public `cmk.password_store.v1_unstable`
  API is used, on 2.3/2.4 the legacy helper. The agent picks whichever exists.
* The MKP does not conflict with the SNMP-based `palo_alto*` checks shipped with
  Checkmk — different plug-in family, different service names, and by design
  different data.

## License

GNU General Public License v2 (GPL-2.0-or-later) – see [LICENSE](LICENSE).
Checkmk plug-in APIs are GPL v2 licensed, so extensions published on the Checkmk
Exchange are subject to the same license.

Palo Alto Networks and PAN-OS are trademarks of Palo Alto Networks, Inc. This
project is not affiliated with or endorsed by Palo Alto Networks or Checkmk
GmbH.
