# Design decisions

Decisions on review items, agreed with the team before they were changed.

## B6. Exposure evaluation uses explicit zone mappings

Exposure evaluation consumes graph data and caller-supplied JSON only. VLAN zones
come from `zones.vlans`, keyed by the JSON string encoding of
`[site, component, vid]` from the attack-path VLAN key; for example,
`[null, "device:synthetic-core", 10]`. `zones.prefixes` can classify a device's
recorded management IP address. Missing mappings become `unknown` and are listed in
`zone_gaps`. Zone names are limited to `mgmt`, `oob`, `backbone`, `customer`,
`user`, `dmz`, and `unknown`. `unknown` is never ranked. The default trust ranks
set `mgmt` and `oob` equally highest; other zones are compared only when the
mapping file supplies numeric `trust_order` values. For example:

```json
{
  "trust_order": {"mgmt": 100, "oob": 100, "backbone": 80, "user": 20},
  "vlans": {"[null, \"device:synthetic-core\", 10]": "mgmt"},
  "prefixes": {"192.0.2.0/24": "user"}
}
```

The class registry is data with source title, date, and verification state.
`verified: true` means the lead fetched and read that source and received HTTP
200. A cited source that was not read, including sources shown as 403 in F5A,
is unverified. An item is marked `source_pending` when all its references are
unverified; E9 therefore emits `source_pending: true`. E12 reports a two-zone
device as a pivot candidate, not an attack route; an unknown side always makes
its confidence inferred. It lists every qualifying pair, ordered by observed
confidence, widest known trust gap, then zone names. For multiple keys in one
zone, an observed key takes precedence over inferred keys while all keys remain
in evidence. `weakness_present` separately records whether another emitted
exposure class exists on that node.
The registry classifies E6 as both entry and pivot; E14 is an entry class and
retains `persistence: true`.
Evidence keys are whitelisted per class, so secret values never enter exposure
evidence. E1 replaces community values with `community_count` and retains only
its `found_by` label.

The current graph supports the following classes. Classes marked not observable
do not emit items until their named source data is added:

| Class | Status | Evidence or exact missing field and supplying phase |
|---|---|---|
| E1 | IMPLEMENTED (observed) | Whitelisted `snmp-default-community` finding ID, `found_by`, and `community_count`; community values are omitted |
| E2 | NOT OBSERVABLE | `management_service_reachability_by_zone` and control-plane filter conditions; nmap F3.6 from a lower-trust proxy plus oxidized configuration conditions |
| E3 | IMPLEMENTED (observed) | `config_findings` evidence for `mgmt-telnet-enabled`, `mgmt-http-enabled`, or `snmp-no-auth` |
| E4 | NOT OBSERVABLE | tcp/4786 listener or `no vstack` configuration condition; nmap F3.6 or oxidized configuration conditions |
| E5 | NOT OBSERVABLE | tcp/80 or tcp/443 reachability by source zone plus IOS XE access condition; nmap F3.6 and oxidized configuration conditions |
| E6 | NOT OBSERVABLE | VPN listener and affected product/version association; nmap F3.6 and F5.4 version matching |
| E7 | NOT OBSERVABLE | Edge/client-port classification and `lldpLocPortTable`; IP-MIB/NetBox zone assignment and crawl port-role data |
| E8 | NOT OBSERVABLE | `dot1qPvid`, untagged egress membership, native VLAN, and trunk/DTP mode; Q-BRIDGE F3.5a and oxidized configuration conditions |
| E9 | IMPLEMENTED (observed) | `config_findings` evidence for `bpdu-guard-missing`; source pending |
| E10 | IMPLEMENTED (inferred) | Spare-port checklist finding plus `ports[].admin`, `ports[].oper`, `neighbor_ports`, and graph endpoint links. Checklist evidence lists at most 20 ports per device. Learned MAC absence is judged only from endpoint links; the forwarding table is not read. `ports[].oper: down` is the producer's collapsed state for ifOperStatus down(2), notPresent(6), or lowerLayerDown(7), not the raw enum. |
| E11 | NOT OBSERVABLE | Per-interface management IP-to-VLAN association; IP-MIB and NetBox interface/VLAN mapping |
| E12 | IMPLEMENTED (observed/inferred) | Attack-path L3 VLAN keys joined to explicit zone mappings; all qualifying pairs are listed. Unknown-side candidates are inferred. L2-only membership awaits Q-BRIDGE F3.5a. Prefix presence uses the management IP. |
| E13 | IMPLEMENTED (observed) | `top_cves[].cve` joined only to the explicitly supplied CISA KEV JSON `vulnerabilities[].cveID`; EPSS and EoL/EoS are not evaluated |
| E14 | NOT OBSERVABLE | Central AAA and local-fallback configuration conditions; oxidized `junos-config-conditions` and vendor configuration checks |
| E15 | NOT OBSERVABLE | BGP peer state and tunnel interface/mode; BGP4-MIB and oxidized configuration conditions |

The mapping fields reflect the standards that define the collected VLAN and
interface data: [RFC 2863](https://www.rfc-editor.org/rfc/rfc2863),
[RFC 4363](https://www.rfc-editor.org/rfc/rfc4363), and
[IEEE 802.1Q](https://standards.ieee.org/ieee/802.1q/10323/). KEV membership
uses the CISA feed's `vulnerabilities[].cveID` format from the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
No feed is fetched by this evaluator.

## B2. Attack-path reachability uses administratively up ports and scoped VLANs

An `ifAdminStatus` of down(2) means an interface is administratively disabled,
so it cannot be an attack start even when the spare-port hygiene finding still
reports it. The finding keeps its result and includes `admin` on each listed
port. This follows [RFC 2863, The Interfaces Group MIB](https://www.rfc-editor.org/rfc/rfc2863).

VLAN membership is keyed by `(site, L2 component, VID)` when a site is present,
and `(L2 component, VID)` otherwise. Only role `router` cuts graph components;
an `l3-switch` remains in its bridged component, consistent with
[IEEE 802.1Q, Bridges and Bridged Networks](https://standards.ieee.org/ieee/802.1q/10323/).
This VLAN context is represented by [RFC 4363, Q-BRIDGE-MIB](https://www.rfc-editor.org/rfc/rfc4363).

A router's VLAN key uses the neighbor's component and site. A sub-interface VID
is assigned to that side as observed only when its base interface matches the
router-side port on an LLDP or endpoint edge. If the edge port matches a
sub-interface base, only a matching `<base>.<vid>` is assigned; a different VID
on that port is excluded. If no sub-interface base matches the edge port, the
names are not comparable and a VID observed in the neighbor component is
assigned as inferred. SVI-style interfaces and edges without a router-side port
also use inferred sides. Inferred sides are labelled on transit steps and
counted in metadata. When no neighbor side is available, the router's own site
and component are used. Existing output `vlans` remains a list of integer VIDs;
`vlan_keys` also exposes the scoped identity.

The same VID on both router sides is valid transit when observed sub-interface
evidence identifies a routed sub-interface on each side. For SVI/IRB VLANs,
the side remains inferred because the graph has no per-port VLAN membership;
[IEEE 802.1Q](https://standards.ieee.org/ieee/802.1q/10323/) and [RFC 4363,
`dot1qVlanCurrentEgressPorts`](https://www.rfc-editor.org/rfc/rfc4363) describe
the evidence that would identify those ports. Such routes carry
`router_side: "inferred"` and are counted, never hidden or marked observed.

An explicitly classified CVE row may set `requires_peer` to a protocol such as
`bgp`. The CVE lookup/catalogue can supply this field; the attack-path engine
does not infer it from descriptions or CVSS. Such a weakness is usable only if
the source node ID is listed in the target's matching peer field, for example
`bgp_peers`. Missing peer data is unknown and does not qualify. The peer list
must represent established peers, as defined by `bgpPeerState` established(6)
in [RFC 4273, Definitions of Managed Objects for BGP-4](https://www.rfc-editor.org/rfc/rfc4273).

## Q3. Automatic rescan: off by default (was on)

`vulnmapper.liveness.autoRescan` now defaults to false. Liveness itself is
unchanged: with `vulnmapper.liveness.enabled` it still runs its quick up/down
checks every interval and the map shows them. What is now opt-in is the full
scan a liveness pass could start when it saw something appear that is not on
the map (a port coming up with nothing linked, a new Wi-Fi client, a Wazuh
agent missing from the graph). A full scan crawls every device, looks up
NVD and cve.org and may run nmap, which is a lot to start unasked; an owner
who wants the map to follow the network by itself sets `autoRescan: true`.

## D4. Liveness interval: default 60 s (was 10 s)

Each liveness pass starts a new Python process, which imports pysnmp,
networkx and requests; every 10 s that is a noticeable CPU load on the
dashboard server. `vulnmapper.liveness.intervalSeconds` now defaults to 60.
The minimum stays 10, so an owner who wants faster detection can still set
it. A long-lived liveness process was the other option; it was not taken.

## D3. TLS verification stays off by default, with a visible warning

The default is unchanged: Wazuh Manager API and Indexer calls skip
certificate verification unless `VULNMAPPER_VERIFY_TLS=1` or a
`*_CA_BUNDLE` is set, because the lab's certificates are self-signed. A live
scan now adds a `tls_unverified` warning to `metadata.warnings`, naming each
service it did not verify, so the gap is visible outside a lab instead of
silent. Since it is the lab default, the Overview shows it as a small info
note the user can dismiss (remembered in the browser, per kind of note), and
Scan settings lists it permanently under "Connection security".

## D6. CI runs the backend tests

`.github/workflows/backend-tests.yml` runs on every push and pull request:
Python 3.12, `backend/requirements.txt` plus pytest, then `pytest` and
`python -m unittest discover -s tests` (the two runners the project uses).
It needs no secret and the tests never reach the network. The plugin's Jest
suite needs an OpenSearch Dashboards checkout and is not run in CI.

## D7. The Wazuh Overview card comes from our plugin, not a patch to Wazuh's

Wazuh's Overview page builds its module cards from a list compiled into
Wazuh's own plugin. Changing that list would mean patching Wazuh's bundle,
which every Wazuh upgrade overwrites and which we would have to rebuild for
each version. Instead our plugin's browser side (`public/wazuhCard.ts`)
watches the page while Wazuh's `wz-home` app is open, finds the section by the
name in its header, copies one of Wazuh's cards there (so it looks the same),
puts our icon and text in it and appends it after Wazuh's cards. If Wazuh
re-renders the section the card is put back; if the section or a card to copy
is not there within 10 s it gives up with one console.debug line and the page
is left as Wazuh drew it. The cost: it depends on Wazuh 4.14's markup (an
OuiCard per section, the name in its beta badge); a Wazuh release that
changes it silently loses the card, which the menu entry (Security) and the
home-page card still cover. The section is a setting,
`vulnmapper.wazuhCard.section`.

## D8. File layout on the Wazuh server

The scanner and its venv go in `/opt/vulnmapper` (root-owned; the service
user only reads it), everything the scanner writes (graph, caches, history,
schedule) in `/var/lib/vulnmapper` (owned by `wazuh-dashboard`, 750), and the
credentials in `/etc/vulnmapper/vulnmapper.env` (root:wazuh-dashboard, 640).
The dashboard gets the credentials through a systemd drop-in
(`EnvironmentFile=`) rather than `opensearch_dashboards.yml`, which holds
only our non-secret settings in a marked block, so the yml can be shared or
backed up without leaking anything and the uninstall can remove exactly what
the install added. Nothing is under a home folder, because the dashboard runs
as a system user.

## D9. A typed SNMP community comes first, and a fallback is shown

The crawl always tried the community typed in the scan form before the
server's SNMP settings, but nothing said which one a device answered, so a
mistyped community silently worked through the environment's and looked as if
the environment file had priority. The order stays (typed, then the server's,
for the scan and the liveness passes; automatic and scheduled scans use the
server's only) and each polled device now records the source it answered as a
label, `entered` or `server`, in `metadata.snmp`. When a community was typed
and any device answered only the server's, an `snmp_fallback` warning names
those devices in the scan toast, on the Overview (not dismissible for that
scan) and on Scan settings. No extra SNMP request is sent: the next credential
is tried only on a device that did not answer the one before, as before.

## D10. The NVD API key can be saved from Scan settings

Setting `NVD_API_KEY` meant editing `/etc/vulnmapper/vulnmapper.env` and
restarting the dashboard. The key can now be saved on Scan settings: the
plugin writes it to `nvd-key` beside the graph (atomic, mode 600, owned by the
service user) and passes it as `NVD_API_KEY` in the environment of the
scanner and the rescore it spawns, never in argv. A saved key beats the
environment's; removing it brings the environment's back. The key never goes
back to the browser, into a log or an API response: the page shows only where
the key comes from, and "Test key" makes one NVD request and reports valid,
invalid or unreachable. The file lives with the data, so the installer keeps
it and `uninstall --purge` removes it.

## D11. Junos devices are decided from Juniper's own CVE records

NVD answered no Junos lookup: the CPE name had 14 components, which NVD
rejects with HTTP 404, and it kept the build number, for which NVD returns
fewer CVEs. Even the correct name misses many CVEs, because NVD's
applicability data for Junos lags Juniper's advisories and lists only some
releases. Juniper is the CNA for its products
and states the affected Junos releases in every CVE record (CVE JSON 5), so
those records decide a Junos device, with NVD's cpeName answer adding only the
CVEs Juniper did not assign. The records are taken from the CVE Services API
(cveawg.mitre.org). Choices made on the way:

- The index (ids Juniper assigned) is pulled from NVD with its own NVD client
  and a 60 s budget, so a slow pull never spends the device lookups' budget or
  marks NVD unreachable for them. The first full pull and the record fetch
  happen inside a scan; the refresh command with `--budget 600` fills an
  empty cache in one run.
- A device is decided only from a complete set of records. A partial set
  would give an `ok` that silently misses CVEs, so the device is `unavailable`
  until the gaps are filled.
- "Train not listed" is judged over the whole record, not per affected block:
  records often split one statement over several platform blocks, and a train
  fixed or stated unaffected in one of them is assessed.
- Records that use `changes` as a timeline over one train (status from the
  train's start, flipping at `lessThan` and at each change) are read as such.
- A model that cannot be placed among a record's platforms matches every
  platform block, and platform limits stated only in description text are not
  read. Both can over-report for a given model; neither can hide a CVE.
- Anything not parsed is listed in `cve_lookup.undecided`, never guessed.
  `cve_lookup` gained `reason` (why a lookup is not `ok`) and `undecided`, and
  the plugin says both in plain words.
- Every Junos device is compared with every record (about 1200), so the
  stage keeps the parsed version strings for the scan and assesses each
  release and model pair once. Without that, a scan with many Junos devices
  took over a minute of CPU; the decisions are the same either way.

## D12. Every identified family is named, even without an NVD product

A device whose software family and version are known was reported the same
way as one with nothing known, when NVD had no product name for that family.
The family table now covers more vendors, and a family without a product name
that can be trusted is still identified (`match: none`, status `unverified`,
reason `no_cpe_rule`). The plugin says the device is identified but its CVEs
are not looked up, instead of saying its software is unknown. Choices made on
the way:

- No CPE rule for Brocade Network OS, DCN switches, IBM Networking OS and the
  HP GbE2c blade switch. The CPE dictionary has no product that fits them
  (`brocade:fabric_os` is the Fibre Channel product, IBM has only single
  per-model firmware entries). A near name would report another product's
  CVEs.
- No CPE rule for ProCurve software before ArubaOS-Switch 16. The dictionary
  writes those releases with their train letters, and NVD compares versions
  as strings, so a release on one train matches ranges stated for another.
- ArubaOS-Switch 16.x is asked under two names, `hpe:arubaos-switch` and the
  per-model `arubanetworks:<line>_firmware`. Each lists CVEs the other does
  not, so the answers are merged. When the model names no product line (only
  a part number), the per-model half cannot be asked and the device is
  `unverified` (`model_not_mapped`) rather than reported with half its CVEs.
- The CPE dictionary check is set per family (`listed`): the exact release
  (the default), the product with any release (ArubaOS-Switch, whose
  dictionary lists only some releases while NVD still evaluates the version
  ranges), or none (FortiOS, for the same reason; this was a special case in
  the lookup before).
- Junos OS Evolved is its own family (`juniper_junos_evolved`, CPE
  `juniper:junos_os_evolved`), recognised by the `-EVO` suffix. It is decided
  from the Evolved blocks of Juniper's records (D11), never from the Junos OS
  blocks, and a release of one branch is never matched against the other.
  Records cached before the Evolved blocks were kept are fetched again, and
  Evolved devices stay `unavailable` until that is done.
