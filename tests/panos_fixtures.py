#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Canned PAN-OS API responses.

Kept free of imports so that both the unit tests and the stand-alone API stub
(which runs inside a Checkmk site, without pytest) can use them.

Each key is the beginning of an operational command, each value the XML that
PAN-OS puts inside ``<response status="success"><result>...</result></response>``.
"""

# command fragment -> the XML inside <response><result>...</result></response>
RESPONSES: dict[str, str] = {
    "<show><system><info/>": """
      <system>
        <hostname>fw01</hostname>
        <model>PA-5220</model>
        <serial>001801000123</serial>
        <sw-version>10.2.9-h1</sw-version>
        <app-version>8811-8541</app-version>
        <threat-version>8811-8541</threat-version>
        <av-version>4712-5230</av-version>
        <family>5200</family>
        <multi-vsys>off</multi-vsys>
        <operational-mode>normal</operational-mode>
        <ip-address>10.1.1.1</ip-address>
        <uptime>45 days, 3:12:55</uptime>
      </system>""",
    "<show><high-availability>": """
      <enabled>yes</enabled>
      <group>
        <local-info>
          <mode>Active-Passive</mode>
          <state>active</state>
          <state-reason>User requested</state-reason>
          <priority>100</priority>
          <build-rel>10.2.9-h1</build-rel>
        </local-info>
        <peer-info>
          <state>passive</state>
          <state-reason>User requested</state-reason>
          <priority>110</priority>
          <build-rel>10.2.9-h1</build-rel>
          <conn-status>up</conn-status>
        </peer-info>
        <running-sync>synchronized</running-sync>
        <running-sync-enabled>yes</running-sync-enabled>
        <link-monitoring><enabled>yes</enabled></link-monitoring>
        <path-monitoring><enabled>no</enabled></path-monitoring>
      </group>""",
    "<show><session><info/>": """
      <num-active>128,540</num-active>
      <num-max>3200000</num-max>
      <num-tcp>90000</num-tcp>
      <num-udp>38000</num-udp>
      <num-icmp>540</num-icmp>
      <pps>420000</pps>
      <kbps>3500000</kbps>
      <cps>7200</cps>""",
    "<show><system><state>": """
cfg.general.max-address: 80000
cfg.general.max-address-group: 8000
cfg.general.max-service: 4000
cfg.general.max-service-group: 2000
cfg.general.max-zone: 200
cfg.general.max-policy-rule: 20000
cfg.general.max-nat-policy-rule: 8000
cfg.general.max-vsys: 10
""",
    "<show><config><running/>": """
      <config>
        <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
          <zone><entry name="trust"/><entry name="untrust"/></zone>
          <address><entry name="a1"/><entry name="a2"/></address>
          <rulebase><security><rules>
            <entry name="r1"/><entry name="r2"/><entry name="r3"/>
          </rules></security></rulebase>
        </entry></vsys></entry></devices>
      </config>""",
    "<show><system><environmentals/>": """
      <thermal>
        <Slot1>
          <entry>
            <slot>1</slot><description>Temperature @ U48</description>
            <alarm>False</alarm><DegreesC>41.0</DegreesC>
            <min>5.0</min><max>65.0</max>
          </entry>
        </Slot1>
      </thermal>
      <fan>
        <Slot1>
          <entry>
            <description>Fan #1 RPM</description><alarm>False</alarm>
            <RPMs>3600</RPMs><min>2000</min>
          </entry>
        </Slot1>
      </fan>
      <power>
        <Slot1>
          <entry>
            <description>Power Rail 3.3v</description><alarm>False</alarm>
            <Volts>3.31</Volts><min>3.0</min><max>3.6</max>
          </entry>
        </Slot1>
      </power>
      <power-supply>
        <Slot1>
          <entry>
            <description>Power Supply #1</description>
            <alarm>False</alarm><Inserted>True</Inserted>
          </entry>
          <entry>
            <description>Power Supply #2</description>
            <alarm>True</alarm><Inserted>False</Inserted>
          </entry>
        </Slot1>
      </power-supply>""",
    "<show><interface>all": """
      <hw>
        <entry>
          <name>ethernet1/1</name><id>16</id><speed>10000</speed>
          <duplex>full</duplex><state>up</state>
          <mac>00:11:22:33:44:55</mac><mode>autoneg</mode><type>0</type>
        </entry>
        <entry>
          <name>ethernet1/2</name><id>17</id><speed>10000</speed>
          <duplex>full</duplex><state>down</state>
          <mac>00:11:22:33:44:56</mac><mode>autoneg</mode><type>0</type>
        </entry>
      </hw>
      <ifnet>
        <entry>
          <name>ethernet1/1</name><id>16</id><zone>untrust</zone>
          <vsys>1</vsys><ip>203.0.113.10/24</ip><addr>N/A</addr>
        </entry>
      </ifnet>""",
    "<show><vpn><gateway/>": """
      <entries>
        <entry>
          <name>gw-branch-a</name><gwid>1</gwid>
          <peer-address>198.51.100.7</peer-address>
          <local-address>203.0.113.10</local-address>
          <interface>ethernet1/1</interface>
        </entry>
        <entry>
          <name>gw-branch-b</name><gwid>2</gwid>
          <peer-address>198.51.100.8</peer-address>
          <local-address>203.0.113.10</local-address>
          <interface>ethernet1/1</interface>
        </entry>
      </entries>""",
    "<show><vpn><ike-sa/>": """
      <entries>
        <entry>
          <name>gw-branch-a</name><role>Initiator</role>
          <created>Sep.09 10:00:00</created><expires>Sep.10 10:00:00</expires>
          <algo-enc>AES-256-CBC</algo-enc><algo-hash>SHA256</algo-hash>
          <algo-dh>DH group 14</algo-dh><ike-version>IKEv2</ike-version>
        </entry>
      </entries>""",
    "<show><vpn><flow/>": """
      <IPSec>
        <entry>
          <name>tun-branch-a</name><id>1</id><gwid>1</gwid>
          <state>active</state><inner-if>tunnel.1</inner-if>
          <outer-if>ethernet1/1</outer-if>
          <localip>203.0.113.10</localip><peerip>198.51.100.7</peerip>
          <mon>on</mon><mon-status>up</mon-status>
        </entry>
        <entry>
          <name>tun-branch-b</name><id>2</id><gwid>2</gwid>
          <state>inactive</state><inner-if>tunnel.2</inner-if>
          <outer-if>ethernet1/1</outer-if>
          <localip>203.0.113.10</localip><peerip>198.51.100.8</peerip>
          <mon>off</mon>
        </entry>
      </IPSec>""",
    "<show><vpn><ipsec-sa/>": """
      <entries>
        <entry>
          <name>tun-branch-a:proxy-1</name><tid>1</tid><gwid>1</gwid>
          <i-spi>0x1234abcd</i-spi><o-spi>0xabcd1234</o-spi>
          <proto>ESP</proto><enc>aes-256-cbc</enc><hash>sha256</hash>
          <remain>2400</remain><life>3600</life>
        </entry>
      </entries>""",
    "<request><license><info/>": """
      <licenses>
        <entry>
          <feature>Threat Prevention</feature>
          <description>Threat Prevention</description>
          <serial>001801000123</serial>
          <issued>March 15, 2024</issued>
          <expires>March 15, 2027</expires>
          <expired>no</expired>
        </entry>
        <entry>
          <feature>PAN-DB URL Filtering</feature>
          <description>PAN-DB URL Filtering</description>
          <expires>Never</expires>
          <expired>no</expired>
        </entry>
      </licenses>""",
    "<show><global-protect-gateway>": """
      <TotalCurrentUsers>142</TotalCurrentUsers>
      <TotalPreviousUsers>150</TotalPreviousUsers>
      <entry>
        <name>gp-gw-hq</name>
        <CurrentUsers>100</CurrentUsers><PreviousUsers>110</PreviousUsers>
      </entry>
      <entry>
        <name>gp-gw-dr</name>
        <CurrentUsers>42</CurrentUsers><PreviousUsers>40</PreviousUsers>
      </entry>""",
    # NAT rulebase read through a scoped xpath. Addresses repeat across rules
    # and private source addresses are mixed in, exactly as on a real device.
    "<config-get:/config/devices/entry/vsys/entry/rulebase/nat/rules": """
      <rules>
        <entry name="r1">
          <source><member>10.1.1.18</member></source>
          <destination><member>203.0.113.11</member></destination>
          <source-translation><dynamic-ip-and-port><translated-address>
            <member>203.0.113.11</member><member>203.0.113.12</member>
          </translated-address></dynamic-ip-and-port></source-translation>
        </entry>
        <entry name="r2">
          <source><member>10.1.1.19</member></source>
          <destination><member>203.0.113.12</member></destination>
          <source-translation><dynamic-ip-and-port><translated-address>
            <member>203.0.113.12</member>
          </translated-address></dynamic-ip-and-port></source-translation>
        </entry>
        <entry name="r3">
          <destination><member>198.51.100.252</member></destination>
        </entry>
      </rules>""",
    "<show><arp>": """
      <max>32000</max><total>3</total>
      <entries>
        <entry><status>c</status><ip>203.0.113.11</ip><mac>00:11:22:33:44:55</mac></entry>
        <entry><status>c</status><ip>203.0.113.20</ip><mac>00:11:22:33:44:56</mac></entry>
        <entry><status>c</status><ip>10.1.1.18</ip><mac>00:11:22:33:44:57</mac></entry>
      </entries>""",
    "<show><interface>logical": """
      <ifnet>
        <entry><name>ethernet1/1</name><ip>203.0.113.1/24</ip></entry>
        <entry><name>ethernet1/2</name><ip>198.51.100.225/27</ip></entry>
        <entry><name>ethernet1/3</name><ip>10.1.1.1/24</ip></entry>
      </ifnet>""",
    # BGP peers, verbatim from a PA-5410 on 11.2.13-h1 (addresses anonymised).
    # 'peer' and 'vr' are attributes of <entry>, and <prefix-counter> nests one
    # <entry> per address family two levels down.
    "<show><routing><protocol><bgp><peer/>": """
      <entry peer="core-01" vr="default">
        <peer-group>cores</peer-group>
        <peer-router-id>203.0.113.62</peer-router-id>
        <remote-as>65000</remote-as>
        <status>Established</status>
        <status-duration>2020586</status-duration>
        <password-set>no</password-set>
        <passive>no</passive>
        <multi-hop-ttl>1</multi-hop-ttl>
        <peer-address>203.0.113.63:34912</peer-address>
        <local-address>203.0.113.54:179</local-address>
        <prefix-limit>5000</prefix-limit>
        <holdtime>90</holdtime>
        <keepalive>30</keepalive>
        <status-flap-counts>1</status-flap-counts>
        <established-counts>1</established-counts>
        <last-error></last-error>
        <prefix-counter>
          <entry afi-safi="bgpAfiIpv4-unicast">
            <incoming-total>0</incoming-total>
            <incoming-accepted>0</incoming-accepted>
            <incoming-rejected>0</incoming-rejected>
            <policy-rejected>0</policy-rejected>
            <outgoing-total>54</outgoing-total>
            <outgoing-advertised>54</outgoing-advertised>
          </entry>
        </prefix-counter>
      </entry>
      <entry peer="border-01" vr="default">
        <peer-group>border</peer-group>
        <remote-as>33261</remote-as>
        <status>Established</status>
        <status-duration>2020593</status-duration>
        <peer-address>203.0.113.66:179</peer-address>
        <local-address>203.0.113.56:51000</local-address>
        <prefix-limit>1</prefix-limit>
        <holdtime>90</holdtime>
        <keepalive>30</keepalive>
        <status-flap-counts>1</status-flap-counts>
        <prefix-counter>
          <entry afi-safi="bgpAfiIpv4-unicast">
            <incoming-total>1</incoming-total>
            <incoming-accepted>1</incoming-accepted>
            <incoming-rejected>0</incoming-rejected>
            <outgoing-total>4</outgoing-total>
            <outgoing-advertised>4</outgoing-advertised>
          </entry>
        </prefix-counter>
      </entry>
      <entry peer="edge-01" vr="default">
        <peer-group>edge</peer-group>
        <remote-as>65010</remote-as>
        <status>Active</status>
        <status-duration>31</status-duration>
        <peer-address>203.0.113.70:179</peer-address>
        <prefix-limit>5000</prefix-limit>
        <status-flap-counts>7</status-flap-counts>
        <last-error>Hold Timer Expired</last-error>
      </entry>""",
    "<show><counter><interface>": """
      <hw>
        <entry>
          <name>ethernet1/1</name>
          <ibytes>1000000</ibytes><obytes>2000000</obytes>
          <ipackets>5000</ipackets><opackets>6000</opackets>
          <ierrors>1</ierrors><oerrors>0</oerrors>
          <idrops>2</idrops><odrops>3</odrops>
        </entry>
      </hw>
      <ifnet>
        <entry>
          <name>tunnel.1</name>
          <ibytes>100</ibytes><obytes>200</obytes>
        </entry>
      </ifnet>""",
}


# ---------------------------------------------------------------------------
# Shapes taken from a real PA-5410 running PAN-OS 11.2.13-h1. Every one of
# these broke an assumption the plug-in made, so they are kept verbatim
# (addresses and names anonymised) to stop the bugs coming back.
# ---------------------------------------------------------------------------

REAL_RESPONSES: dict[str, str] = {
    # 'show system state' mixes hex and decimal in the same answer
    "<show><system><state>": """
cfg.general.max-address: 0x13880
cfg.general.max-address-group: 0x9c40
cfg.general.max-service: 0x1f40
cfg.general.max-service-group: 0xfa0
cfg.general.max-zone: 0xfa0
cfg.general.max-vsys: 0x15
cfg.general.max-policy-rule: 30000
cfg.general.max-nat-policy-rule: 6000
cfg.general.max-dip-nat-policy-rule: 4000
""",
    # the gateway parameters live in a nested <v2> element
    "<show><vpn><gateway/>": """
      <entries>
        <entry>
          <id>1</id><name>to_partner_p1</name><sock>1024</sock><natt>0</natt>
          <v2>
            <peer-id>203.0.113.60(ipaddr:203.0.113.60)</peer-id>
            <local-id>203.0.113.57(ipaddr:203.0.113.57)</local-id>
            <auth>PSK</auth><dh>DH14</dh>
            <enc>AES192-CBC,AES256-CBC</enc><hash>SHA256,SHA384</hash>
            <life>43200</life>
          </v2>
        </entry>
      </entries>
      <all>True</all><ngw>1</ngw>""",
    # the IKE version is called 'mode', the algorithms are one string
    "<show><vpn><ike-sa/>": """
      <entry>
        <gwid>1</gwid><name>to_partner_p1</name><role>Init</role>
        <mode>IKEv2</mode><algo>PSK/DH14/AES192-CBC/SHA256</algo>
        <created>Sep.10 09:29:53</created><expires>Sep.10 21:29:53</expires>
      </entry>""",
    # flow entries are named '<tunnel>:<proxy-id>', same as the SAs
    "<show><vpn><flow/>": """
      <dp>dp0</dp><num_ipsec>2</num_ipsec>
      <IPSec>
        <entry>
          <name>to_partner_p2:Net-A</name><id>2</id><gwid>1</gwid>
          <inner-if>tunnel.3</inner-if><outer-if>ae2.1070</outer-if>
          <localip>203.0.113.57</localip><peerip>203.0.113.60</peerip>
          <state>active</state><mon>off</mon>
        </entry>
        <entry>
          <name>to_partner_p2:Net-B</name><id>3</id><gwid>1</gwid>
          <inner-if>tunnel.3</inner-if><outer-if>ae2.1070</outer-if>
          <localip>203.0.113.57</localip><peerip>203.0.113.60</peerip>
          <state>init</state><mon>off</mon>
        </entry>
      </IPSec>""",
    # SPIs use underscores, and 'kb' is the word 'Unlimited'
    "<show><vpn><ipsec-sa/>": """
      <entries>
        <entry>
          <gwid>1</gwid><gateway>to_partner_p1</gateway><tid>2</tid>
          <remote>203.0.113.60      </remote><name>to_partner_p2:Net-A</name>
          <proto>ESP</proto><enc>A192</enc><hash>SHA256</hash>
          <i_spi>2160946712</i_spi><o_spi>3067743524</o_spi><dh>DH14</dh>
          <kb>Unlimited</kb><life>3600</life><remain>1898</remain>
        </entry>
      </entries>""",
    # this hardware reports <fans> and <fan-tray>, not <fan>
    "<show><system><environmentals/>": """
      <thermal><Slot1><entry>
        <slot>1</slot><description>CPU Die temperature sensor</description>
        <alarm>False</alarm><DegreesC>35.625</DegreesC><min>0.0</min><max>95.0</max>
      </entry></Slot1></thermal>
      <fans><Slot1>
        <entry>
          <slot>1</slot><description>Inlet fan of Fan unit #1</description>
          <alarm>False</alarm><RPMs>2436</RPMs><min>2000</min>
        </entry>
        <entry>
          <slot>1</slot><description>Outlet fan of Fan unit #1</description>
          <alarm>False</alarm><RPMs>2203</RPMs><min>1400</min>
        </entry>
      </Slot1></fans>
      <fan-tray><Slot1><entry>
        <slot>1</slot><description>Fan Tray #1 (left)</description>
        <alarm>False</alarm><Inserted>True</Inserted><min>1</min>
      </entry></Slot1></fan-tray>
      <power><Slot1><entry>
        <slot>1</slot><description>VDD12V0</description><alarm>False</alarm>
        <Volts>12.046875</Volts><min>11.4</min><max>12.6</max>
      </entry></Slot1></power>
      <power-supply><Slot1><entry>
        <slot>1</slot><description>Power Supply #1</description>
        <alarm>False</alarm><Inserted>True</Inserted>
      </entry></Slot1></power-supply>""",
    # the gateways are <Gateway> elements, not <entry>
    "<show><global-protect-gateway>": """
      <Gateway>
        <name>gp-gateway-a</name><CurrentUsers>0</CurrentUsers><PreviousUsers>5</PreviousUsers>
      </Gateway>
      <Gateway>
        <name>gp-gateway-b</name><CurrentUsers>259</CurrentUsers><PreviousUsers>898</PreviousUsers>
      </Gateway>
      <TotalCurrentUsers>259</TotalCurrentUsers>
      <TotalPreviousUsers>903</TotalPreviousUsers>""",
}
