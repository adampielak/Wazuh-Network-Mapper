"""Offline exposure evaluation over graph data and explicit zone/KEV files."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Optional

from ..attackpaths import AttackPathEngine


def _ref(source_id: str, title: str, date: str, verified: bool) -> dict:
    return {"id": source_id, "title": title, "date": date, "verified": verified}


CLASS_REGISTRY = {
    "E1": {
        "id": "E1", "title": "Weak or writable SNMP management", "use": "both",
        "source_refs": [_ref("CISA-AA23-108", "CISA AA23-108", "2023-04-18", True)],
        "attack": ["T1602.001", "T1078.001"],
    },
    "E2": {
        "id": "E2", "title": "Management plane reachable from a lower-trust zone", "use": "both",
        "source_refs": [_ref("CISA-AA24-038A", "CISA AA24-038A", "2024-02-07", True),
                        _ref("CISA-AA25-239A", "CISA AA25-239A", "2025-08-27", True),
                        _ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False)],
        "attack": ["T1133"],
    },
    "E3": {
        "id": "E3", "title": "Unencrypted management protocol", "use": "entry",
        "source_refs": [_ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False),
                        _ref("FORTIOS-HARDENING-7.4", "FortiOS 7.4 Hardening your FortiGate", "7.4", True)],
        "attack": ["T1040", "T1133"],
    },
    "E4": {
        "id": "E4", "title": "Cisco Smart Install enabled", "use": "both",
        "source_refs": [_ref("US-CERT-TA18-106A", "US-CERT TA18-106A", "2018-04-16", True),
                        _ref("CISCO-SA-20180328-SMI", "Cisco cisco-sa-20180328-smi", "2018-03-28", True)],
        "attack": ["T1190", "T1602.002"],
    },
    "E5": {
        "id": "E5", "title": "Device web UI reachable outside management zones", "use": "entry",
        "source_refs": [_ref("CISCO-SA-IOSXE-WEBUI-PRIVESC-J22SAA4Z", "cisco-sa-iosxe-webui-privesc-j22SaA4z", "2023-10-16", True)],
        "attack": ["T1190"],
    },
    "E6": {
        "id": "E6", "title": "VPN gateway with a KEV vulnerability", "use": "entry",
        "source_refs": [_ref("FORTIGUARD-FG-IR-24-015", "FortiGuard FG-IR-24-015", "2024-02-09", True),
                        _ref("CVE-2024-3400", "CVE-2024-3400", "2024", True),
                        _ref("CISA-AA24-060A", "CISA AA24-060A", "2024-02-29", True)],
        "attack": ["T1190", "T1133"],
    },
    "E7": {
        "id": "E7", "title": "LLDP or CDP enabled at a client or edge port", "use": "pivot",
        "source_refs": [_ref("IEEE-802.1AB-2016", "IEEE 802.1AB-2016", "2016", False),
                        _ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False)],
        "attack": ["T1590"],
    },
    "E8": {
        "id": "E8", "title": "VLAN hopping conditions", "use": "pivot",
        "source_refs": [_ref("CISCO-C9300-17.9-SECURITY", "Cisco Catalyst 9300 17.9 Security Configuration Guide", "17.9", False),
                        _ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False),
                        _ref("IEEE-802.1Q-2018", "IEEE 802.1Q-2018", "2018", False)],
        "attack": [],
    },
    "E9": {
        "id": "E9", "title": "BPDU Guard missing on edge ports", "use": "pivot",
        "source_refs": [_ref("IEEE-802.1D-2004", "IEEE 802.1D-2004", "2004", False),
                        _ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False)],
        "attack": ["T1557"],
    },
    "E10": {
        "id": "E10", "title": "Unused port administratively enabled", "use": "entry",
        "source_refs": [_ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False)],
        "attack": ["T1200"],
    },
    "E11": {
        "id": "E11", "title": "Management interface in a user or customer VLAN", "use": "entry",
        "source_refs": [_ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False)],
        "attack": ["T1133"],
    },
    "E12": {
        "id": "E12", "title": "Device present in differently trusted zones", "use": "pivot",
        "source_refs": [_ref("CISA-AA25-239A", "CISA AA25-239A", "2025-08-27", True)],
        "attack": ["T1599"],
    },
    "E13": {
        "id": "E13", "title": "CVE listed in CISA KEV", "use": "entry",
        "source_refs": [_ref("CISA-KEV-2026.11.17", "CISA Known Exploited Vulnerabilities catalog", "2026-11-17", True)],
        "attack": ["T1190"],
    },
    "E14": {
        "id": "E14", "title": "Central AAA missing or local fallback only", "use": "both",
        "source_refs": [_ref("NSA-NISG-2022", "NSA Network Infrastructure Security Guide", "2022-06-15", False),
                        _ref("CISA-AA25-239A", "CISA AA25-239A", "2025-08-27", True)],
        "attack": ["T1556.004", "T1078.001"],
    },
    "E15": {
        "id": "E15", "title": "Unlisted tunnels or routing peers", "use": "pivot",
        "source_refs": [_ref("CISA-AA25-239A", "CISA AA25-239A", "2025-08-27", True),
                        _ref("US-CERT-TA18-106A", "US-CERT TA18-106A", "2018-04-16", True)],
        "attack": ["T1599.001"],
    },
}


CLASS_STATUS = {
    "E1": {"status": "IMPLEMENTED (observed)", "detail": "config_findings evidence for snmp-default-community"},
    "E2": {"status": "NOT OBSERVABLE", "detail": "management_service_reachability_by_zone and control-plane filter conditions; nmap F3.6 from a lower-trust proxy plus oxidized configuration conditions"},
    "E3": {"status": "NOT OBSERVABLE", "detail": "management service listener/banner tied to a device and protocol; nmap F3.6 or oxidized configuration conditions"},
    "E4": {"status": "NOT OBSERVABLE", "detail": "tcp/4786 listener or no-vstack configuration condition; nmap F3.6 or oxidized configuration conditions"},
    "E5": {"status": "NOT OBSERVABLE", "detail": "tcp/80 or tcp/443 reachability by source zone and IOS XE access condition; nmap F3.6 plus oxidized configuration conditions"},
    "E6": {"status": "NOT OBSERVABLE", "detail": "VPN listener and affected product/version association; nmap F3.6 and F5.4 device-version matching"},
    "E7": {"status": "NOT OBSERVABLE", "detail": "edge/client-port classification and lldpLocPortTable state; IP-MIB/NetBox zone assignment and crawl port-role data"},
    "E8": {"status": "NOT OBSERVABLE", "detail": "dot1qPvid, untagged egress membership, native VLAN and port trunk/DTP mode; Q-BRIDGE F3.5a and oxidized configuration conditions"},
    "E9": {"status": "IMPLEMENTED (observed)", "detail": "config_findings evidence for bpdu-guard-missing; source pending"},
    "E10": {"status": "IMPLEMENTED (inferred)", "detail": "spare-port checklist evidence plus IF-MIB port state and absence of a graph neighbour or endpoint link"},
    "E11": {"status": "NOT OBSERVABLE", "detail": "per-interface management IP-to-VLAN association; IP-MIB and NetBox interface/VLAN mapping"},
    "E12": {"status": "IMPLEMENTED (observed/inferred)", "detail": "attackpaths L3 VLAN keys joined to explicit zone mappings; all qualifying zone pairs are reported and unknown-side candidates are inferred"},
    "E13": {"status": "IMPLEMENTED (observed)", "detail": "top_cves CVE IDs joined to the explicitly supplied CISA KEV JSON"},
    "E14": {"status": "NOT OBSERVABLE", "detail": "central AAA and local-fallback configuration conditions; oxidized junos-config-conditions and vendor configuration checks"},
    "E15": {"status": "NOT OBSERVABLE", "detail": "BGP peer state and tunnel interface/mode configuration; BGP4-MIB and oxidized configuration conditions"},
}

ALLOWED_ZONES = {"mgmt", "oob", "backbone", "customer", "user", "dmz", "unknown"}
DEFAULT_TRUST_ORDER = {"mgmt": 100, "oob": 100}
LIMITS = [
    "Zone membership is only as complete as the explicit VLAN and prefix mappings; missing keys remain unknown.",
    "The default trust order ranks mgmt and oob equally highest; other zones require explicit trust_order values to compare.",
    "Unknown-zone E12 items are inferred candidates, not attack routes; weakness_present marks a separate emitted weakness on the same node.",
    "E10 uses graph absence of a neighbour or endpoint link as evidence; it does not prove an uncollected forwarding table was empty.",
    "EPSS and firmware end-of-life status are not evaluated because those values are not available as explicit inputs to this function.",
]


def _read_json(value, label: str):
    if isinstance(value, (str, Path)):
        with Path(value).open(encoding="utf-8") as handle:
            return json.load(handle)
    if isinstance(value, dict):
        return value
    raise TypeError(f"{label} must be a JSON path or object")


def _vlan_key_text(key: tuple) -> str:
    site, component, vid = key
    return f"{site or ''}|{component}|{vid}"


def _load_zones(zones):
    doc = _read_json(zones, "zones")
    vlan_map = doc.get("vlans") or {}
    prefix_map = doc.get("prefixes") or {}
    if not isinstance(vlan_map, dict) or not isinstance(prefix_map, dict):
        raise ValueError("zones vlans and prefixes must be JSON objects")
    if any(zone not in ALLOWED_ZONES for zone in [*vlan_map.values(), *prefix_map.values()]):
        raise ValueError("zone name is not allowed")
    trust = dict(DEFAULT_TRUST_ORDER)
    trust.update(doc.get("trust_order") or {})
    if "unknown" in trust:
        raise ValueError("unknown must not have a trust rank")
    if any(zone not in ALLOWED_ZONES or not isinstance(rank, (int, float))
           for zone, rank in trust.items()):
        raise ValueError("trust_order must map allowed zone names to numeric ranks")
    prefixes = []
    for prefix, zone in prefix_map.items():
        prefixes.append((ipaddress.ip_network(prefix, strict=False), zone))
    prefixes.sort(key=lambda item: (-item[0].prefixlen, str(item[0])))
    return vlan_map, prefixes, trust


def _prefix_zone(ip: Optional[str], prefixes) -> Optional[str]:
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((zone for network, zone in prefixes if address.version == network.version and address in network), None)


def _port_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _port_has_graph_link(graph: dict, node_id: str, port_name: str) -> tuple[bool, bool]:
    target = _port_key(port_name)
    neighbor = False
    endpoint = False
    for edge in graph.get("edges") or []:
        if edge.get("type") == "lldp":
            device_port = (edge.get("local_port") if edge.get("source") == node_id
                           else edge.get("remote_port") if edge.get("target") == node_id else None)
            if device_port and _port_key(device_port) == target:
                neighbor = True
        if edge.get("type") == "endpoint_link":
            device_port = edge.get("local_port")
            if node_id in (edge.get("source"), edge.get("target")) and device_port \
                    and _port_key(device_port) == target:
                endpoint = True
    for node in graph.get("nodes") or []:
        if node.get("node_id") == node_id:
            if any(_port_key(name) == target for name in node.get("neighbor_ports") or []):
                neighbor = True
    return neighbor, endpoint


def _item(class_id: str, evidence: dict, confidence: str = "observed", **extra) -> dict:
    row = CLASS_REGISTRY[class_id]
    item = {"class": class_id, "evidence": evidence,
            "source_ref": [ref["id"] for ref in row["source_refs"]],
            "confidence": confidence,
            "source_pending": all(not ref["verified"] for ref in row["source_refs"])}
    item.update(extra)
    return item


def _findings(node: dict, finding_id: str) -> list:
    return [finding for finding in node.get("config_findings") or []
            if finding.get("id") == finding_id]


def compute_exposure(graph: dict, zones, kev=None) -> dict:
    """Return deterministic exposure candidates from graph data and supplied JSON inputs."""
    vlan_zones, prefixes, trust_order = _load_zones(zones)
    kev_ids = set()
    kev_rows = {}
    if kev is not None:
        feed = _read_json(kev, "kev")
        rows = feed.get("vulnerabilities") if isinstance(feed, dict) else None
        if not isinstance(rows, list):
            raise ValueError("KEV input must contain vulnerabilities[]")
        for row in rows:
            if isinstance(row, dict) and row.get("cveID"):
                kev_ids.add(row["cveID"])
                kev_rows[row["cveID"]] = row

    nodes = {node["node_id"]: [] for node in graph.get("nodes") or []
             if node.get("kind") == "device" and node.get("node_id")}
    gaps = set()
    engine = AttackPathEngine(graph, None, None)
    node_by_id = {node["node_id"]: node for node in graph.get("nodes") or []
                  if node.get("node_id")}
    zone_presence = {}

    for node_id in sorted(nodes):
        node = node_by_id[node_id]
        items = nodes[node_id]

        snmp_findings = _findings(node, "snmp-default-community")
        for finding in snmp_findings:
            items.append(_item("E1", {"config_findings.id": finding["id"],
                                      "config_findings.evidence": finding.get("evidence")}))

        bpdu_findings = _findings(node, "bpdu-guard-missing")
        for finding in bpdu_findings:
            items.append(_item("E9", {"config_findings.id": finding["id"],
                                      "config_findings.evidence": finding.get("evidence")}))

        for finding in _findings(node, "spare-ports-in-used-vlan"):
            for port in (finding.get("evidence") or {}).get("ports") or []:
                name = port.get("port")
                matching = next((entry for entry in node.get("ports") or []
                                 if _port_key(entry.get("name", "")) == _port_key(name or "")), None)
                if not name or port.get("admin") != "up" or not matching \
                        or matching.get("admin") != "up" or matching.get("oper") != "down":
                    continue
                neighbor, endpoint_link = _port_has_graph_link(graph, node_id, name)
                if neighbor or endpoint_link or matching.get("mac") or matching.get("macs"):
                    continue
                items.append(_item("E10", {
                    "ports.name": name, "ports.admin": matching.get("admin"),
                    "ports.oper": matching.get("oper"),
                    "config_findings.evidence.port": port.get("port"),
                    "config_findings.evidence.vlan": port.get("vlan"),
                    "config_findings.evidence.admin": port.get("admin"),
                    "neighbor_link": False, "endpoint_link": False,
                    "ports.mac": matching.get("mac"), "ports.macs": matching.get("macs"),
                    "config_findings.id": finding["id"],
                }, confidence="inferred"))

        cves = sorted({row.get("cve") for row in node.get("top_cves") or []
                       if isinstance(row, dict) and row.get("cve")})
        for cve_id in cves:
            if cve_id in kev_ids:
                kev_row = kev_rows[cve_id]
                items.append(_item("E13", {
                    "top_cves.cve": cve_id,
                    "kev.vulnerabilities[].cveID": kev_row.get("cveID"),
                    "kev.vulnerabilities[].knownRansomwareCampaignUse": kev_row.get("knownRansomwareCampaignUse"),
                }))

        zone_rows = []
        keys = sorted(engine.vlan_keys.get(node_id, set()), key=lambda key: (key[0] or "", key[1], key[2]))
        for key in keys:
            key_text = _vlan_key_text(key)
            zone = vlan_zones.get(key_text)
            if zone is None:
                gaps.add(f"vlan:{key_text}")
                zone = "unknown"
            confidence = "observed"
            if node.get("role") == "router":
                confidence = engine.router_vlan_sides.get(node_id, {}).get(key, "inferred")
            zone_rows.append({"key": key_text, "zone": zone, "confidence": confidence})

        ip_zone = _prefix_zone(node.get("ip"), prefixes)
        if node.get("ip") and ip_zone is None:
            gaps.add(f"prefix:{node['ip']}")
        if ip_zone is not None and not any(row["zone"] == ip_zone for row in zone_rows):
            zone_rows.append({"key": f"prefix:{node['ip']}", "zone": ip_zone, "confidence": "observed"})

        unique = {}
        for zone in sorted({row["zone"] for row in zone_rows}):
            zone_keys = sorted((row for row in zone_rows if row["zone"] == zone),
                               key=lambda row: row["key"])
            unique[zone] = {
                "zone": zone,
                "confidence": ("observed" if any(row["confidence"] == "observed"
                                                   for row in zone_keys) else "inferred"),
                "keys": zone_keys,
            }
        zone_presence[node_id] = [unique[zone] for zone in sorted(unique)]

    for node_id in sorted(nodes):
        presence = zone_presence[node_id]
        pairs = []
        for index, left in enumerate(presence):
            for right in presence[index + 1:]:
                if left["zone"] == right["zone"]:
                    continue
                if "unknown" in (left["zone"], right["zone"]):
                    confidence = "inferred"
                    trust_gap = None
                else:
                    left_rank, right_rank = trust_order.get(left["zone"]), trust_order.get(right["zone"])
                    if left_rank is None or right_rank is None or left_rank == right_rank:
                        continue
                    confidence = "observed" if left["confidence"] == right["confidence"] == "observed" else "inferred"
                    trust_gap = abs(left_rank - right_rank)
                pairs.append({
                    "zone_a": left["zone"], "zone_b": right["zone"],
                    "presence_a": left, "presence_b": right,
                    "confidence": confidence, "trust_gap": trust_gap,
                })
        if not pairs:
            continue
        pairs.sort(key=lambda pair: (
            0 if pair["confidence"] == "observed" else 1,
            -(pair["trust_gap"] if pair["trust_gap"] is not None else -1),
            pair["zone_a"], pair["zone_b"],
        ))
        best = pairs[0]
        pair_evidence = [{key: value for key, value in pair.items()}
                         for pair in pairs]
        weakness_present = any(item["class"] != "E12" for item in nodes[node_id])
        nodes[node_id].append(_item("E12", {
            "presence_a": best["presence_a"], "presence_b": best["presence_b"],
            "trust_order": {best["zone_a"]: trust_order.get(best["zone_a"]),
                            best["zone_b"]: trust_order.get(best["zone_b"])},
            "pairs": pair_evidence,
            "weakness_present": weakness_present,
        }, confidence=best["confidence"], weakness_present=weakness_present))

    for node_id in nodes:
        nodes[node_id].sort(key=lambda item: (item["class"], json.dumps(item["evidence"], sort_keys=True)))

    limits = list(LIMITS)
    if kev is None:
        limits.append("KEV membership was not evaluated because no KEV JSON path or object was supplied.")
    return {"nodes": nodes, "zone_gaps": sorted(gaps), "classes": CLASS_STATUS,
            "limits": limits}


__all__ = ["CLASS_REGISTRY", "CLASS_STATUS", "compute_exposure"]
