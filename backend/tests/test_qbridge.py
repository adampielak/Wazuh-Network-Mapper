"""Q-BRIDGE VLAN membership parsing and collection with synthetic SNMP rows."""

import asyncio
import unittest

from snmp_fakes import FakeSnmpClient, load_rows
from vulnmapper.checklist.tables import DOT1Q_PVID
from vulnmapper.network import parse
from vulnmapper.network.model import Device
from vulnmapper.schema import KIND_DEVICE, Node


IP = "192.0.2.10"
EGRESS = parse.DOT1Q_VLAN_CURRENT_EGRESS_PORTS_BASE
UNTAGGED = parse.DOT1Q_VLAN_CURRENT_UNTAGGED_PORTS_BASE
BASEPORT = parse.DOT1D_BASEPORT_IFINDEX_BASE


class TestPortList(unittest.TestCase):
    def test_decodes_octets_most_significant_bit_first(self):
        self.assertEqual(parse.decode_portlist("0x80"), [1])
        self.assertEqual(parse.decode_portlist("0x01"), [8])
        self.assertEqual(parse.decode_portlist("0x8001"), [1, 16])
        self.assertEqual(parse.decode_portlist("0x80010000"), [1, 16])
        self.assertEqual(parse.decode_portlist(""), [])

    def test_all_printable_octets_arrive_as_text_not_hex(self):
        # the SNMP layer renders b"@" as "@" and b"AB" as "AB", never as hex
        self.assertEqual(parse.decode_portlist("@"), [2])
        self.assertEqual(parse.decode_portlist("U"), [2, 4, 6, 8])
        self.assertEqual(parse.decode_portlist("AB"), [2, 8, 10, 15])
        self.assertEqual(parse.decode_portlist(b"\x80\x01"), [1, 16])


class TestQBridgeCollection(unittest.TestCase):
    def test_latest_timemark_membership_pvid_and_unmapped_ports(self):
        client = FakeSnmpClient({IP: load_rows("qbridge/switch.snmp")})
        membership = asyncio.run(parse.collect_vlan_membership(client, IP))
        self.assertEqual(membership, {
            "source": "q-bridge",
            "vlans": {
                "10": {"tagged": ["Gi0/1"], "untagged": ["Gi0/2"]},
                "20": {"tagged": ["Gi0/1", "bridge_port:16"], "untagged": []},
            },
            "pvid": {"Gi0/1": 10, "bridge_port:9": 20},
            "unmapped_bridge_ports": 2,
        })
        walk = next(c for c in client.calls if c[0] == "walk_columns")
        self.assertEqual(walk[2], (EGRESS, UNTAGGED, BASEPORT, DOT1Q_PVID))

    def test_reuses_checklist_pvid_without_a_second_walk(self):
        client = FakeSnmpClient({IP: load_rows("qbridge/switch.snmp")})
        membership = asyncio.run(parse.collect_vlan_membership(client, IP, {1: 10, 9: 20}))
        self.assertEqual(membership["pvid"], {"Gi0/1": 10, "bridge_port:9": 20})
        walk = next(c for c in client.calls if c[0] == "walk_columns")
        self.assertNotIn(DOT1Q_PVID, walk[2])

    def test_reuses_port_reader_ifname_rows_without_a_second_walk(self):
        rows = [r for r in load_rows("qbridge/switch.snmp")
                if not r[0].startswith(parse.IFNAME_BASE + ".")]
        ifname_rows = [r for r in load_rows("qbridge/switch.snmp")
                       if r[0].startswith(parse.IFNAME_BASE + ".")]
        client = FakeSnmpClient({IP: rows})
        membership = asyncio.run(parse.collect_vlan_membership(
            client, IP, ifname_rows=ifname_rows, ifdescr_rows=[]))
        self.assertEqual(membership["vlans"]["10"], {"tagged": ["Gi0/1"], "untagged": ["Gi0/2"]})
        self.assertEqual([c for c in client.calls if c[0] == "walk"], [])

    def test_unmapped_count_ignores_interface_names_that_look_like_bridge_ports(self):
        membership = parse.build_vlan_membership(
            [(f"{EGRESS}.0.10", "0xc0")], [], [],
            [(f"{BASEPORT}.1", "1"), (f"{BASEPORT}.2", "2")],
            ifname_rows=[(f"{parse.IFNAME_BASE}.1", "bridge_port:7"),
                         (f"{parse.IFNAME_BASE}.2", "Gi0/2")])
        self.assertEqual(membership["unmapped_bridge_ports"], 0)

    def test_no_qbridge_rows_omits_optional_node_field(self):
        client = FakeSnmpClient({IP: [("1.3.6.1.2.1.1.5.0", "synthetic-switch")]})
        self.assertIsNone(asyncio.run(parse.collect_vlan_membership(client, IP)))
        node = Device(chassis_id="00:00:5e:00:53:01", ip=IP, hostname="synthetic-switch",
                      port_status={"Gi0/1": "up"}).to_node()
        self.assertEqual(node["port_status"], {"Gi0/1": "up"})
        self.assertNotIn("vlan_membership", node)

    def test_schema_serializes_membership_only_when_present(self):
        node = Node(node_id="device:synthetic-switch", kind=KIND_DEVICE,
                    discovery_method="snmp_lldp", chassis_id="00:00:5e:00:53:01")
        self.assertNotIn("vlan_membership", node.to_dict())
        node.vlan_membership = {"source": "q-bridge", "vlans": {}, "pvid": {},
                                "unmapped_bridge_ports": 0}
        self.assertEqual(node.to_dict()["vlan_membership"], node.vlan_membership)


if __name__ == "__main__":
    unittest.main()
