"""An LLDP neighbour that is queued by its management address but never answers
a poll keeps the name, vendor and MAC it advertised to its neighbours.

The lab firewall (172.20.100.1) is in the L3 switch's LLDP table with a system
name, a FortiGate description and a MAC chassis id, and serves no SNMP.
"""

import unittest

from test_cdp import L2_CID, crawl, lab

FW_CID = "90:6c:ac:d7:43:7f"
FW_NODE = f"device:{FW_CID}"
FW_ADVERTISED = {"hostname": "CYFOR-Firewall.cyfor.lab", "vendor": "Fortinet", "mac": FW_CID}
L2_NAME_ROW = "1.0.8802.1.1.2.1.4.1.1.9.0.4.2"     # L3's entry for the L2 switch


def with_advertised_identity(graph: dict, vulnerabilities: dict | None = None) -> None:
    """Bring a pipeline baseline frozen before this change up to date, in place:
    the lab firewall now carries the name, vendor and MAC it advertised, and the
    edge into it and its host entry carry that name."""
    for node in graph["nodes"]:
        if node["node_id"] == FW_NODE:
            node.update(FW_ADVERTISED)
    for edge in graph["edges"]:
        if edge["target"] == FW_NODE:
            edge["target_name"] = FW_ADVERTISED["hostname"]
    if vulnerabilities is not None:
        vulnerabilities["hosts"][FW_NODE]["hostname"] = FW_ADVERTISED["hostname"]


class TestAdvertisedIdentity(unittest.TestCase):
    def nodes(self, client):
        return {n["chassis_id"]: n for n in crawl(client)["nodes"]}

    def test_unpolled_neighbour_keeps_what_it_advertised(self):
        fw = self.nodes(lab())[FW_CID]
        self.assertFalse(fw["pollable"])
        self.assertEqual(fw["status"], "unreachable")
        self.assertEqual((fw["ip"], fw["hostname"], fw["vendor"], fw["mac"]),
                         ("172.20.100.1", *FW_ADVERTISED.values()))

    def test_polled_device_keeps_its_own_identity(self):
        client = lab()
        own = self.nodes(client)[L2_CID]["hostname"]
        for ip, rows in client.devices.items():
            client.devices[ip] = [(o, "Name-A-Neighbour-Gave") if o == L2_NAME_ROW else (o, v)
                                  for o, v in rows]
        l2 = self.nodes(client)[L2_CID]
        self.assertTrue(l2["pollable"])
        self.assertEqual(l2["hostname"], own)


if __name__ == "__main__":
    unittest.main()
