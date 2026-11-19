"""A MAC for every polled device, and the label of how it was first reached.

A device with no LLDP chassis id (the lab's access point speaks only CDP) used
to get the node id device:ip:<address>, which changes with the address. Its
base MAC, chosen from its own interface MACs, now names it.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from test_cdp import AP_IP, L2_CID, L3_CID, crawl, lab
from vulnmapper.assemble import assemble
from vulnmapper.liveness import liveness_pass
from vulnmapper.network import parse
from vulnmapper.network import identity
from vulnmapper.network.identity import base_mac, juniper_model, vendor_from_descr
from vulnmapper.network.snmp import OID_SYS_DESCR, OID_SYS_NAME, OID_SYS_OBJECT_ID

AP_MAC = "54:75:d0:ab:bd:1a"        # Gi0 (and its sub-interfaces) of the access point
AP_NODE = f"device:{AP_MAC}"


class TestBaseMac(unittest.TestCase):
    def test_the_mac_most_interfaces_share(self):
        self.assertEqual(base_mac(["aca016bb23d0", "a40cc31a1e20", "5475d0abbd1a",
                                   "aca016bb23d0", "5475d0abbd1a", "5475d0abbd1a"]),
                         "54:75:d0:ab:bd:1a")

    def test_a_tie_goes_to_the_lowest(self):
        self.assertEqual(base_mac(["00:23:ac:e5:74:02", "00:23:ac:e5:74:01"]),
                         "00:23:ac:e5:74:01")

    def test_zero_multicast_and_locally_administered_are_skipped(self):
        self.assertEqual(base_mac(["000000000000", "ffffffffffff", "01005e000001",
                                   "020000000001", "020000000001", "00aabbccddee"]),
                         "00:aa:bb:cc:dd:ee")

    def test_no_usable_mac(self):
        self.assertIsNone(base_mac([]))
        self.assertIsNone(base_mac(["000000000000", "not a mac"]))


class TestLabIdentity(unittest.TestCase):
    def setUp(self):
        self.doc = crawl(lab())
        self.by_cid = {n["chassis_id"]: n for n in self.doc["nodes"]}

    def test_access_point_is_named_by_its_mac(self):
        self.assertIn(AP_MAC, self.by_cid)
        self.assertNotIn(f"ip:{AP_IP}", self.by_cid)
        ap = self.by_cid[AP_MAC]
        self.assertEqual((ap["mac"], ap["ip"], ap["pollable"]), (AP_MAC, AP_IP, True))
        self.assertFalse(any(cid.startswith("ip:") for cid in self.by_cid))

    def test_discovery_label_says_how_it_was_first_reached(self):
        self.assertEqual(self.by_cid[AP_MAC]["discovery_method"], "snmp_cdp")
        self.assertEqual(self.by_cid[L3_CID]["discovery_method"], "snmp_lldp")   # the seed
        self.assertEqual(self.by_cid[L2_CID]["discovery_method"], "snmp_lldp")   # LLDP first

    def test_lldp_chassis_ids_are_unchanged(self):
        for cid in (L3_CID, L2_CID):
            self.assertEqual(self.by_cid[cid]["mac"], cid)

    def test_every_reference_uses_the_new_id(self):
        graph = assemble([], self.doc)
        ids = {n["node_id"] for n in graph["nodes"]}
        self.assertIn(AP_NODE, ids)
        self.assertFalse(any(i.startswith("device:ip:") for i in ids))
        for edge in graph["edges"]:
            self.assertIn(edge["source"], ids)
            self.assertIn(edge["target"], ids)
        self.assertTrue(any({e["source"], e["target"]} == {AP_NODE, f"device:{L3_CID}"}
                            for e in graph["edges"]))
        clients = [n for n in graph["nodes"] if n.get("wifi")]
        self.assertTrue(clients)
        for n in clients:
            self.assertEqual(n["wifi"]["access_point"], AP_NODE)
            self.assertEqual(n["parent_id"], AP_NODE)
        for n in graph["nodes"]:
            if n.get("parent_id"):
                self.assertIn(n["parent_id"], ids)

    def test_no_second_node_for_the_device_mac(self):
        graph = assemble([], self.doc)
        self.assertNotIn(f"host:{AP_MAC}", {n["node_id"] for n in graph["nodes"]})
        with_mac = [n for n in graph["nodes"] if n.get("mac") == AP_MAC]
        self.assertEqual([n["node_id"] for n in with_mac], [AP_NODE])

    def test_liveness_keys_the_device_by_the_same_id(self):
        class Silent:
            has_snmp = False

            async def icmp(self, ip):
                return False

        graph = assemble([], self.doc)
        doc = asyncio.run(liveness_pass(graph, {}, Silent(), 2, now="2026-10-09T00:00:00+00:00"))
        self.assertIn(AP_NODE, doc["nodes"])


class TestNoMacAtAll(unittest.TestCase):
    def test_address_id_only_when_no_mac_can_be_read(self):
        client = lab()
        client.devices[AP_IP] = [(o, v) for o, v in client.devices[AP_IP]
                                 if not o.startswith(parse.IFPHYS_BASE + ".")]
        by_cid = {n["chassis_id"]: n for n in crawl(client)["nodes"]}
        self.assertIn(f"ip:{AP_IP}", by_cid)
        self.assertIsNone(by_cid[f"ip:{AP_IP}"]["mac"])


if __name__ == "__main__":
    unittest.main()


class TestJuniperModel(unittest.TestCase):
    """A Juniper chassis that reports a part number as its inventory model
    name gets the model its sysDescr names."""

    MX = "Juniper Networks, Inc. mx480 internet router, kernel JUNOS 21.2R3-S8.5, Build date: 2025-01-01"

    def test_part_number_replaced_by_sysdescr_model(self):
        self.assertEqual(juniper_model("750-047862", self.MX), "mx480")

    def test_missing_model_filled_from_sysdescr(self):
        self.assertEqual(juniper_model(None, self.MX), "mx480")

    def test_real_model_kept(self):
        self.assertEqual(juniper_model("MX10003", self.MX), "MX10003")
        self.assertEqual(juniper_model("ex3300-48t", self.MX), "ex3300-48t")

    def test_unplaceable_sysdescr_token_keeps_the_model(self):
        descr = "Juniper Networks, Inc. jnp10003 internet router"
        self.assertEqual(juniper_model("750-047862", descr), "750-047862")
        self.assertIsNone(juniper_model(None, "Juniper Networks, Inc."))
        self.assertEqual(juniper_model("750-047862", None), "750-047862")

    def test_bracketed_model_after_product_number(self):
        descr = ("Juniper Networks, Inc. JNP10003 [MX10003] internet router, kernel JUNOS "
                 "20.4R3-S6.3, Build date: 2023-01-12 20:26:57 UTC")
        self.assertEqual(juniper_model("750-074276", descr), "MX10003")
        self.assertEqual(juniper_model(None, descr), "MX10003")
        self.assertEqual(juniper_model("MX10003", descr), "MX10003")

    def test_unplaceable_bracketed_model_keeps_the_model(self):
        descr = "Juniper Networks, Inc. JNP10003 [M10003] internet router"
        self.assertEqual(juniper_model("750-074276", descr), "750-074276")

    def test_family_check_agrees_with_devicecves(self):
        from vulnmapper.devicecves.junos import model_family
        for token in ("mx480", "srx345", "SRX340", "VSRX", "qfx5110-48s-4c", "ex3300-48t",
                      "ptx10003", "acx710", "jnp10003", "750-047862", "m320", "exa1"):
            descr = f"Juniper Networks, Inc. {token} internet router"
            placed = model_family(token) is not None
            self.assertEqual(juniper_model(None, descr), token if placed else None, token)

    def _fetch(self, sys_descr, sys_object_id, inventory):
        values = {OID_SYS_DESCR: sys_descr, OID_SYS_OBJECT_ID: sys_object_id,
                  OID_SYS_NAME: "dev1"}

        class Client:
            async def get_many(self, ip, oids):
                return {oid: values.get(oid) for oid in oids}

        with patch("vulnmapper.network.entity.collect_inventory",
                   AsyncMock(return_value=inventory)):
            return asyncio.run(identity.fetch(Client(), "192.0.2.1"))

    def test_fetch_uses_sysdescr_model_for_juniper_part_number(self):
        got = self._fetch(self.MX, "1.3.6.1.4.1.2636.1.1.1.2.25", {"model": "750-047862"})
        self.assertEqual((got["vendor"], got["model"]), ("Juniper", "mx480"))

    def test_fetch_leaves_other_vendors_alone(self):
        descr = "Arista Networks EOS version 4.30 running on an Arista DCS-7050"
        got = self._fetch(descr, "1.3.6.1.4.1.30065.1.1", {"model": "750-047862"})
        self.assertEqual(got["model"], "750-047862")

    def test_fetch_identifies_vyos_from_sysdescr(self):
        for descr, firmware in (("VyOS 1.5-stream-2025-Q2", "1.5-stream-2025-Q2"),
                                ("VyOS 2025.11", "2025.11"),
                                ("VyOS 1.4.3", "1.4.3")):
            got = self._fetch(descr, "1.3.6.1.4.1.8072.3.2.10", {})
            self.assertEqual((got["vendor"], got["software_family"], got["firmware"]),
                             ("VyOS", "vyos", firmware), descr)

    def test_vendor_from_descr_names_vyos(self):
        self.assertEqual(vendor_from_descr("VyOS 2025.11"), "VyOS")
