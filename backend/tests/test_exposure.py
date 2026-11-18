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
                "synthetic-site|device:synthetic-a|10": "mgmt",
                "synthetic-site|device:synthetic-b|20": "user",
            },
        }
        result = compute_exposure(routed_graph(), zones)
        pivot = next(item for item in result["nodes"]["device:synthetic-router"]
                     if item["class"] == "E12")
        self.assertEqual(pivot["confidence"], "observed")
        self.assertFalse(pivot["weakness_present"])

    def test_observed_widest_pair_precedes_inferred_unknown_pairs(self):
        zones = {"trust_order": {"mgmt": 100, "customer": 40, "user": 20}, "vlans": {
            "synthetic-site|device:synthetic-a|10": "mgmt",
            "synthetic-site|device:synthetic-b|20": "user",
            "synthetic-site|device:synthetic-c|30": "customer",
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
            "synthetic-site|device:synthetic-a|10": "mgmt",
            "synthetic-site|device:synthetic-b|20": "mgmt",
            "synthetic-site|device:synthetic-c|30": "user",
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
            "synthetic-site|device:synthetic-a|10": "mgmt",
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
        self.assertTrue(item["source_pending"])

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
        self.assertTrue(all(item["source_pending"] for item in items if item["class"] == "E10"))

    def test_not_observable_classes_never_emit(self):
        graph_doc = routed_graph()
        graph_doc["nodes"][0].update({
            "config_findings": [
                {"id": "snmp-default-community", "title": "Synthetic finding", "evidence": {}},
                {"id": "bpdu-guard-missing", "title": "Synthetic finding", "evidence": {}},
                {"id": "spare-ports-in-used-vlan", "title": "Synthetic finding", "evidence": {"ports": []}},
            ],
            "ports": [{"name": "Gi1/0/7", "admin": "up", "oper": "down",
                       "mac": None, "macs": []}],
            "top_cves": [{"cve": SYNTHETIC_CVE}],
            "bgp_peers": [],
            "hostname": "switch.example",
        })
        mapping = {"trust_order": {"mgmt": 100, "user": 20}, "vlans": {
            "synthetic-site|device:synthetic-a|10": "mgmt",
            "synthetic-site|device:synthetic-b|20": "user",
        }}
        result = compute_exposure(graph_doc, mapping, KEV)
        emitted = {item["class"] for rows in result["nodes"].values() for item in rows}
        for class_id, status in CLASS_STATUS.items():
            if status["status"] == "NOT OBSERVABLE":
                self.assertNotIn(class_id, emitted)


if __name__ == "__main__":
    unittest.main()
