"""Synthetic-only tests for offline exposure classification."""

import json
import os
import tempfile
import unittest

from vulnmapper.exposure import CLASS_REGISTRY, CLASS_STATUS, compute_exposure


HERE = os.path.dirname(os.path.abspath(__file__))
KEV = os.path.join(HERE, "fixtures", "exposure", "synthetic_kev.json")
with open(KEV, encoding="utf-8") as handle:
    SYNTHETIC_CVE = json.load(handle)["vulnerabilities"][0]["cveID"]


def device(node_id, role="l2-switch", port_status=None, ports=None, **extra):
    return {
        "node_id": node_id,
        "kind": "device",
        "role": role,
        "site": "synthetic-site",
        "ip": "192.0.2.10",
        "port_status": port_status or {},
        "ports": ports or [],
        "neighbor_ports": [],
        "config_findings": [],
        "top_cves": [],
        **extra,
    }


def graph(nodes, edges=None):
    return {"nodes": nodes, "edges": edges or [], "metadata": {}}


def vlan_key(site, component, vid):
    return json.dumps([site, component, vid])


def routed_graph():
    router = device("device:synthetic-router", "router", {
        "Gi0/0.10": "up", "Gi0/1.20": "up",
    })
    left = device("device:synthetic-a", "l3-switch", {"Vlan10": "up"})
    right = device("device:synthetic-b", "l3-switch", {"Vlan20": "up"})
    edges = [
        {"source": router["node_id"], "target": left["node_id"], "type": "lldp",
         "local_port": "Gi0/0", "remote_port": "Gi1/0"},
        {"source": router["node_id"], "target": right["node_id"], "type": "lldp",
         "local_port": "Gi0/1", "remote_port": "Gi1/0"},
    ]
    return graph([router, left, right], edges)


def routed_four_zones_graph():
    router = device("device:synthetic-router", "router", {
        "Gi0/0.10": "up", "Gi0/1.20": "up", "Gi0/2.30": "up", "Gi0/3.40": "up",
    })
    sides = [device(f"device:synthetic-{name}", "l3-switch", {f"Vlan{vid}": "up"})
             for name, vid in (("a", 10), ("b", 20), ("c", 30), ("d", 40))]
    edges = [{"source": router["node_id"], "target": side["node_id"], "type": "lldp",
              "local_port": f"Gi0/{index}", "remote_port": "Gi1/0"}
             for index, side in enumerate(sides)]
    return graph([router, *sides], edges)


def routed_same_zone_graph():
    router = device("device:synthetic-router", "router", {
        "Gi0/0.10": "up", "Gi0/1.20": "up", "Gi0/2.30": "up",
    })
    sides = [device(f"device:synthetic-{name}", "l3-switch", {f"Vlan{vid}": "up"})
             for name, vid in (("a", 10), ("b", 20), ("c", 30))]
    edges = [
        {"source": router["node_id"], "target": sides[0]["node_id"], "type": "lldp",
         "local_port": "UnknownPort0", "remote_port": "Gi1/0"},
        {"source": router["node_id"], "target": sides[1]["node_id"], "type": "lldp",
         "local_port": "Gi0/1", "remote_port": "Gi1/0"},
        {"source": router["node_id"], "target": sides[2]["node_id"], "type": "lldp",
         "local_port": "Gi0/2", "remote_port": "Gi1/0"},
    ]
    return graph([router, *sides], edges)


def zone_file(doc):
    handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False)
    json.dump(doc, handle)
    handle.close()
    return handle.name


class TestExposure(unittest.TestCase):
    def test_no_zone_mapping_reports_gaps_without_observed_pivot(self):
        result = compute_exposure(routed_graph(), {"vlans": {}, "prefixes": {}})
        self.assertTrue(any(key.startswith("vlan:") for key in result["zone_gaps"]))
        self.assertFalse(any(item["class"] == "E12" and item["confidence"] == "observed"
                             for rows in result["nodes"].values() for item in rows))

    def test_two_mapped_l3_zones_produce_observed_pivot(self):
        zones = {
            "trust_order": {"mgmt": 100, "user": 20},
            "vlans": {
                vlan_key("synthetic-site", "device:synthetic-a", 10): "mgmt",
                vlan_key("synthetic-site", "device:synthetic-b", 20): "user",
            },
        }
        result = compute_exposure(routed_graph(), zones)
        pivot = next(item for item in result["nodes"]["device:synthetic-router"]
                     if item["class"] == "E12")
        self.assertEqual(pivot["confidence"], "observed")
        self.assertFalse(pivot["weakness_present"])

    def test_observed_widest_pair_precedes_inferred_unknown_pairs(self):
        zones = {"trust_order": {"mgmt": 100, "customer": 40, "user": 20}, "vlans": {
            vlan_key("synthetic-site", "device:synthetic-a", 10): "mgmt",
            vlan_key("synthetic-site", "device:synthetic-b", 20): "user",
            vlan_key("synthetic-site", "device:synthetic-c", 30): "customer",
        }}
        result = compute_exposure(routed_four_zones_graph(), zones)
        pivot = next(item for item in result["nodes"]["device:synthetic-router"]
                     if item["class"] == "E12")
        self.assertEqual(pivot["confidence"], "observed")
        self.assertEqual((pivot["evidence"]["presence_a"]["zone"],
                          pivot["evidence"]["presence_b"]["zone"]), ("mgmt", "user"))
        pairs = pivot["evidence"]["pairs"]
        self.assertEqual([(pair["zone_a"], pair["zone_b"], pair["confidence"])
                          for pair in pairs], [
            ("mgmt", "user", "observed"),
            ("customer", "mgmt", "observed"),
            ("customer", "user", "observed"),
            ("customer", "unknown", "inferred"),
            ("mgmt", "unknown", "inferred"),
            ("unknown", "user", "inferred"),
        ])

    def test_same_zone_presence_prefers_observed_key_and_keeps_all_keys(self):
        zones = {"trust_order": {"mgmt": 100, "user": 20}, "vlans": {
            vlan_key("synthetic-site", "device:synthetic-a", 10): "mgmt",
            vlan_key("synthetic-site", "device:synthetic-b", 20): "mgmt",
            vlan_key("synthetic-site", "device:synthetic-c", 30): "user",
        }}
        result = compute_exposure(routed_same_zone_graph(), zones)
        pivot = next(item for item in result["nodes"]["device:synthetic-router"]
                     if item["class"] == "E12")
        mgmt = pivot["evidence"]["presence_a"]
        self.assertEqual(mgmt["zone"], "mgmt")
        self.assertEqual(mgmt["confidence"], "observed")
        self.assertEqual([row["confidence"] for row in mgmt["keys"]], ["inferred", "observed"])
        self.assertEqual(len(mgmt["keys"]), 2)

    def test_unknown_zone_side_produces_inferred_pivot(self):
        zones = {"trust_order": {"mgmt": 100, "user": 20}, "vlans": {
            vlan_key("synthetic-site", "device:synthetic-a", 10): "mgmt",
        }}
        result = compute_exposure(routed_graph(), zones)
        pivot = next(item for item in result["nodes"]["device:synthetic-router"]
                     if item["class"] == "E12")
        self.assertEqual(pivot["confidence"], "inferred")

    def test_admin_up_unused_port_emits_if_mib_evidence(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "Gi1/0/7", "admin": "up", "oper": "down"},
        ], config_findings=[{"id": "spare-ports-in-used-vlan", "evidence": {
            "ports": [{"port": "Gi1/0/7", "vlan": 10, "admin": "up"}],
        }}])
        result = compute_exposure(graph([node]), {})
        item = next(item for item in result["nodes"][node["node_id"]]
                    if item["class"] == "E10")
        self.assertEqual(item["confidence"], "inferred")
        self.assertEqual(item["evidence"]["ports.admin"], "up")
        self.assertEqual(item["evidence"]["ports.oper"], "down")
        self.assertFalse(item["source_pending"])
        self.assertEqual(item["source_ref"], ["NSA-NISG-1.2"])

    def test_e10_uses_shared_port_key_for_neighbor_names(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "GigabitEthernet1/0/7", "admin": "up", "oper": "down"},
        ], neighbor_ports=["Gi1/0/7"], config_findings=[{
            "id": "spare-ports-in-used-vlan", "evidence": {
                "ports": [{"port": "GigabitEthernet1/0/7", "vlan": 10, "admin": "up"}],
            },
        }])
        result = compute_exposure(graph([node]), {})
        self.assertFalse(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_e10_matches_neighbor_through_port_alias(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "Ethernet1/0/7", "alias": "Gi1/0/7", "admin": "up", "oper": "down"},
        ], neighbor_ports=["Gi1/0/7"], config_findings=[{
            "id": "spare-ports-in-used-vlan", "evidence": {
                "ports": [{"port": "Ethernet1/0/7", "vlan": 10, "admin": "up"}],
            },
        }])
        result = compute_exposure(graph([node]), {})
        self.assertFalse(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_e10_prefers_port_name_when_another_port_uses_it_as_alias(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "Gi1/0/7", "alias": "Gi1/0/8", "admin": "up", "oper": "down"},
            {"name": "Gi1/0/8", "alias": "", "admin": "up", "oper": "up"},
        ], config_findings=[{
            "id": "spare-ports-in-used-vlan", "evidence": {
                "ports": [{"port": "Gi1/0/8", "vlan": 10, "admin": "up"}],
            },
        }])
        result = compute_exposure(graph([node]), {})
        self.assertFalse(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_e10_alias_cannot_hide_another_ports_exposure(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "Gi1/0/7", "alias": "Gi1/0/8", "admin": "up", "oper": "down"},
            {"name": "Gi1/0/8", "alias": "", "admin": "up", "oper": "up"},
        ], neighbor_ports=["Gi1/0/8"], config_findings=[{
            "id": "spare-ports-in-used-vlan", "evidence": {
                "ports": [{"port": "Gi1/0/7", "vlan": 10, "admin": "up"}],
            },
        }])
        result = compute_exposure(graph([node]), {})
        self.assertTrue(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_e10_distinguishes_dot_subinterface_from_slash_port(self):
        node = device("device:synthetic-router", "router", {"Gi0/0.100": "up"}, ports=[
            {"name": "Gi0/0.100", "admin": "up", "oper": "down"},
        ], neighbor_ports=["Gi0/0/100"], config_findings=[{
            "id": "spare-ports-in-used-vlan", "evidence": {
                "ports": [{"port": "Gi0/0.100", "vlan": 100, "admin": "up"}],
            },
        }])
        result = compute_exposure(graph([node]), {})
        self.assertTrue(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_e10_excludes_link_lost_port(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "Gi1/0/7", "admin": "up", "oper": "down", "state": "link_lost"},
        ], config_findings=[{
            "id": "spare-ports-in-used-vlan", "evidence": {
                "ports": [{"port": "Gi1/0/7", "vlan": 10, "admin": "up"}],
            },
        }])
        result = compute_exposure(graph([node]), {})
        self.assertFalse(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_e10_neighbor_edges_use_shared_port_key(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "GigabitEthernet1/0/7", "admin": "up", "oper": "down"},
        ], config_findings=[{
            "id": "spare-ports-in-used-vlan", "evidence": {
                "ports": [{"port": "GigabitEthernet1/0/7", "vlan": 10, "admin": "up"}],
            },
        }])
        peer = device("device:synthetic-peer")
        edge = {"source": node["node_id"], "target": peer["node_id"], "type": "lldp",
                "local_port": "Gi1/0/7", "remote_port": "Gi1/0/1"}
        result = compute_exposure(graph([node, peer], [edge]), {})
        self.assertFalse(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_e3_emits_safe_evidence_for_each_checklist_finding(self):
        cases = {
            "mgmt-telnet-enabled": {"port": 23, "found_by": "synthetic check"},
            "mgmt-http-enabled": {"port": 80},
            "snmp-no-auth": {"snmp_version": "v2c"},
        }
        for finding_id, finding_evidence in cases.items():
            with self.subTest(finding_id=finding_id):
                node = device("device:synthetic-cleartext", config_findings=[{
                    "id": finding_id, "evidence": finding_evidence,
                }])
                result = compute_exposure(graph([node]), {})
                item = next(item for item in result["nodes"][node["node_id"]]
                            if item["class"] == "E3")
                self.assertEqual(item["evidence"]["config_findings.id"], finding_id)
                self.assertFalse(item["source_pending"])

    def test_e1_never_returns_community_values(self):
        node = device("device:synthetic-secret", config_findings=[{
            "id": "snmp-default-community",
            "evidence": {"communities": ["synthetic-community"], "found_by": "synthetic probe"},
        }])
        result = compute_exposure(graph([node]), {})
        encoded = json.dumps(result)
        item = next(item for item in result["nodes"][node["node_id"]]
                    if item["class"] == "E1")
        self.assertNotIn("synthetic-community", encoded)
        self.assertEqual(item["evidence"]["community_count"], 1)
        self.assertEqual(item["evidence"]["found_by"], "synthetic probe")

    def test_zone_gaps_include_endpoint_vlan_keys(self):
        switch = device("device:synthetic-switch", "l3-switch", {"Vlan10": "up"})
        endpoint = {"node_id": "endpoint:synthetic-agent", "kind": "endpoint",
                    "site": "synthetic-site", "vlan": 30}
        edge = {"source": endpoint["node_id"], "target": switch["node_id"],
                "type": "endpoint_link", "local_port": "Gi1/0/1"}
        result = compute_exposure(graph([switch, endpoint], [edge]), {})
        self.assertIn(f"vlan:{vlan_key('synthetic-site', switch['node_id'], 10)}", result["zone_gaps"])
        self.assertIn(f"vlan:{vlan_key('synthetic-site', switch['node_id'], 30)}", result["zone_gaps"])

    def test_malformed_graph_and_zone_inputs_raise_labeled_value_errors(self):
        cases = [
            ({}, "graph nodes"),
            ({"nodes": [{"kind": "device"}]}, r"nodes\[0\]\.node_id"),
            ({"nodes": [{"node_id": "device:synthetic",}]}, r"nodes\[0\]\.kind"),
        ]
        for graph_doc, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    compute_exposure(graph_doc, {})
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "zones.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump([], handle)
            with self.assertRaisesRegex(ValueError, "zones file"):
                compute_exposure(graph([]), path)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"prefixes": {"not-a-prefix": "user"}}, handle)
            with self.assertRaisesRegex(ValueError, "zones prefixes entry"):
                compute_exposure(graph([]), path)

    def test_malformed_edges_and_config_findings_raise_labeled_value_errors(self):
        valid_node = device("device:synthetic-validation")
        for edges, message in (([None], r"edges\[0\]"), ({"edge": {}}, "graph edges")):
            with self.subTest(edges=edges):
                with self.assertRaisesRegex(ValueError, message):
                    compute_exposure({"nodes": [valid_node], "edges": edges}, {})
        cases = [
            ("x", r"device:synthetic-validation config_findings must be"),
            (["x"], r"device:synthetic-validation config_findings\[0\] must be"),
            ([{"id": "spare-ports-in-used-vlan", "evidence": {"ports": "x"}}],
             r"config_findings\[0\]\.evidence\.ports must be"),
            ([{"id": "spare-ports-in-used-vlan", "evidence": {"ports": [None]}}],
             r"config_findings\[0\]\.evidence\.ports\[0\] must be"),
            ([{"id": "spare-ports-in-used-vlan", "evidence": {"ports": [{"vlan": 10}]}}],
             r"config_findings\[0\]\.evidence\.ports\[0\] must contain port and vlan"),
            ([{"id": "spare-ports-in-used-vlan", "evidence": {"ports": [{"port": "Gi1/0/7"}]}}],
             r"config_findings\[0\]\.evidence\.ports\[0\] must contain port and vlan"),
        ]
        for findings, message in cases:
            with self.subTest(findings=findings):
                node = {**valid_node, "config_findings": findings}
                with self.assertRaisesRegex(ValueError, message):
                    compute_exposure(graph([node]), {})

    def test_invalid_node_ip_is_rejected_with_node_id(self):
        node = device("device:synthetic-invalid-ip", ip="not-an-ip")
        with self.assertRaisesRegex(ValueError, "device:synthetic-invalid-ip.*invalid ip"):
            compute_exposure(graph([node]), {"prefixes": {"192.0.2.0/24": "user"}})

    def test_ipv4_and_ipv6_prefix_presence_can_form_e12_pairs(self):
        graph_v4 = routed_graph()
        zones_v4 = {"trust_order": {"mgmt": 100, "user": 20},
                    "vlans": {vlan_key("synthetic-site", "device:synthetic-a", 10): "mgmt"},
                    "prefixes": {"192.0.2.0/24": "user"}}
        v4 = compute_exposure(graph_v4, zones_v4)
        pair_keys = [key for pair in next(item for item in v4["nodes"]["device:synthetic-router"]
                                          if item["class"] == "E12")["evidence"]["pairs"]
                     for side in ("presence_a", "presence_b")
                     for key in pair[side]["keys"]]
        self.assertIn("prefix:192.0.2.10", [row["key"] for row in pair_keys])

        graph_v6 = routed_graph()
        graph_v6["nodes"][0]["ip"] = "2001:db8::10"
        zones_v6 = {"trust_order": {"mgmt": 100, "customer": 40},
                    "vlans": {vlan_key("synthetic-site", "device:synthetic-a", 10): "mgmt"},
                    "prefixes": {"2001:db8::/32": "customer"}}
        v6 = compute_exposure(graph_v6, zones_v6)
        ipv6_pivot = next(item for item in v6["nodes"]["device:synthetic-router"]
                          if item["class"] == "E12")
        self.assertTrue(any(row["key"] == "prefix:2001:db8::10"
                            for pair in ipv6_pivot["evidence"]["pairs"]
                            for side in ("presence_a", "presence_b")
                            for row in pair[side]["keys"]))

    def test_vlan_key_encoding_distinguishes_null_and_empty_site(self):
        self.assertNotEqual(vlan_key(None, "device:synthetic", 10),
                            vlan_key("", "device:synthetic", 10))

    def test_registry_metadata_and_status_result_are_copied(self):
        self.assertEqual(CLASS_REGISTRY["E6"]["use"], "both")
        self.assertEqual(CLASS_REGISTRY["E14"]["use"], "entry")
        self.assertIs(CLASS_REGISTRY["E14"]["persistence"], True)
        result = compute_exposure(graph([]), {})
        result["classes"]["E1"]["status"] = "changed"
        self.assertEqual(CLASS_STATUS["E1"]["status"], "IMPLEMENTED (observed)")

    def test_limits_describe_collection_bounds(self):
        limits = compute_exposure(graph([]), {})["limits"]
        self.assertTrue(any("at most those listed ports" in line for line in limits))
        self.assertTrue(any("L2-only membership" in line for line in limits))
        self.assertTrue(any("management address" in line for line in limits))
        self.assertTrue(any("notPresent(6)" in line and "lowerLayerDown(7)" in line
                            for line in limits))

    def test_bpdu_guard_finding_has_pending_source(self):
        node = device("device:synthetic-bpdu", config_findings=[
            {"id": "bpdu-guard-missing", "title": "Synthetic finding", "evidence": {"ports": ["Gi1/0/1"]}},
        ])
        result = compute_exposure(graph([node]), {})
        item = next(item for item in result["nodes"][node["node_id"]]
                    if item["class"] == "E9")
        self.assertTrue(item["source_pending"])

    def test_admin_down_port_does_not_emit(self):
        node = device("device:synthetic-switch", ports=[
            {"name": "Gi1/0/7", "admin": "down", "oper": "down"},
        ], config_findings=[{"id": "spare-ports-in-used-vlan", "evidence": {
            "ports": [{"port": "Gi1/0/7", "vlan": 10, "admin": "down"}],
        }}])
        result = compute_exposure(graph([node]), {})
        self.assertFalse(any(item["class"] == "E10" for item in result["nodes"][node["node_id"]]))

    def test_kev_membership_requires_explicit_feed(self):
        node = device("device:synthetic-cve", top_cves=[{"cve": SYNTHETIC_CVE}])
        found = compute_exposure(graph([node]), {}, KEV)
        self.assertTrue(any(item["class"] == "E13" for item in found["nodes"][node["node_id"]]))
        absent = compute_exposure(graph([node]), {}, {"vulnerabilities": []})
        self.assertFalse(any(item["class"] == "E13" for item in absent["nodes"][node["node_id"]]))
        unset = compute_exposure(graph([node]), {})
        self.assertFalse(any(item["class"] == "E13" for item in unset["nodes"][node["node_id"]]))
        self.assertTrue(any("no KEV JSON" in line for line in unset["limits"]))

    def test_every_item_references_a_registered_class_and_source(self):
        node = device("device:synthetic-evidence", top_cves=[{"cve": SYNTHETIC_CVE}],
                      config_findings=[
                          {"id": "snmp-default-community", "evidence": {"communities": ["public"]}},
                          {"id": "bpdu-guard-missing", "evidence": {"ports": ["Gi1/0/1"]}},
                      ], ports=[{"name": "Gi1/0/7", "admin": "up", "oper": "down"}],
                      neighbor_ports=[])
        node["config_findings"].append({"id": "spare-ports-in-used-vlan", "evidence": {
            "ports": [{"port": "Gi1/0/7", "vlan": 10, "admin": "up"}],
        }})
        result = compute_exposure(graph([node]), {}, KEV)
        items = result["nodes"][node["node_id"]]
        for item in items:
            self.assertIn(item["class"], CLASS_REGISTRY)
            self.assertTrue(item["source_ref"])
        e10 = [item for item in items if item["class"] == "E10"]
        self.assertTrue(e10)
        self.assertFalse(any(item["source_pending"] for item in e10))
        e9 = [item for item in items if item["class"] == "E9"]
        self.assertTrue(e9)
        self.assertTrue(all(item["source_pending"] for item in e9))

    def test_not_observable_classes_never_emit(self):
        graph_doc = routed_graph()
        graph_doc["nodes"][0].update({
            "config_findings": [
                {"id": "snmp-default-community", "title": "Synthetic finding", "evidence": {}},
                {"id": "bpdu-guard-missing", "title": "Synthetic finding", "evidence": {}},
                {"id": "spare-ports-in-used-vlan", "title": "Synthetic finding", "evidence": {"ports": []}},
            ],
            "ports": [{"name": "Gi1/0/7", "admin": "up", "oper": "down"}],
            "top_cves": [{"cve": SYNTHETIC_CVE}],
            "bgp_peers": [],
            "hostname": "switch.example",
        })
        mapping = {"trust_order": {"mgmt": 100, "user": 20}, "vlans": {
            vlan_key("synthetic-site", "device:synthetic-a", 10): "mgmt",
            vlan_key("synthetic-site", "device:synthetic-b", 20): "user",
        }}
        result = compute_exposure(graph_doc, mapping, KEV)
        emitted = {item["class"] for rows in result["nodes"].values() for item in rows}
        for class_id, status in CLASS_STATUS.items():
            if status["status"] == "NOT OBSERVABLE":
                self.assertNotIn(class_id, emitted)


if __name__ == "__main__":
    unittest.main()
