"""Configuration-conditioned Junos CVEs: the conservative reading of the
records' ``configurations`` text and the reading of a device backup."""

import offline  # noqa: F401  (no test reaches the internet)
import json
import unittest

from vulnmapper.devicecves import conditions as c
from vulnmapper.devicecves import junosconfig as jc

ANY = c.ANY
SECRET = "S3ntinel-Secret-Value"

CONFIG = f"""## Last commit: some date
version 20.4R3-S5.3;
system {{
    host-name LF1;
}}
inactive: protocols {{
    lldp;
}}
interfaces {{
    inactive: ge-0/0/9 {{ description x; }}
}}
set version 20.4R3-S5.3
set system host-name LF1
set system root-authentication encrypted-password "$6${SECRET}"
set snmp community {SECRET} authorization read-only
set protocols lldp interface all
set protocols bgp group UP neighbor 192.0.2.1
set routing-instances VRF1 protocols ospf area 0.0.0.0 interface ge-0/0/1.0
set interfaces xe-0/0/38 description "2AA8YO_CUSTOMER_K2.1S.207u10"
set interfaces xe-0/0/38 unit 0 family ethernet-switching interface-mode access
set interfaces xe-0/0/38 unit 0 family ethernet-switching vlan members 2108
set interfaces mge-0/0/25 description "2KOCTT_CUST/NIC_NOC"
set interfaces mge-0/0/25 native-vlan-id 2029
set interfaces mge-0/0/25 unit 0 family ethernet-switching interface-mode trunk
set interfaces ge-0/0/2 description "---"
set interfaces ge-0/0/3 unit 0 description "unit level customer"
set interfaces ge-0/0/9 description "deactivated description"
set interfaces ge-0/0/10 unit 0 family ethernet-switching port-mode trunk
set interfaces interface-range R1 member ge-0/0/20
set interfaces interface-range R1 member-range ge-0/0/30 to ge-0/0/32
set interfaces interface-range R1 member "ge-0/0/*"
set interfaces interface-range R1 description "range customer"
set interfaces interface-range R1 unit 0 family ethernet-switching interface-mode trunk
set interfaces irb unit 10 family inet address 10.0.0.1/24
deactivate protocols lldp
deactivate interfaces ge-0/0/9
# comment at the tail
"""
FW = "JUNOS 20.4R3-S5.3"


def conds(**values):
    """{CVE id: Condition} from {id: [configurations values]} (ids with _ for -)."""
    out = {}
    for k, v in values.items():
        parsed = c.parse(v)
        assert parsed is not None, k
        out[k.replace("_", "-")] = parsed
    return out


class TestParse(unittest.TestCase):
    def test_bracket_statement(self):
        self.assertEqual(c.parse(["[ system extended-echo ]"]).statements,
                         (("system", "extended-echo"),))

    def test_lead_in_and_two_statements(self):
        v = ("For a device to be affected both of the following two lines of configuration "
             "need to be present on at least two revenue interfaces:\n\n"
             "  [ interfaces <interface> family mpls ]\n  [ interfaces <interface> family inet6 ]")
        self.assertEqual(c.parse([v]).statements, (("interfaces", ANY, "family"),))

    def test_set_line_and_edit_form(self):
        self.assertEqual(c.parse(["set services security-metadata-streaming policy p1"]).statements,
                         (("services", "security-metadata-streaming"),))
        self.assertEqual(c.parse(["[edit protocols bgp group G]"]).statements,
                         (("protocols", "bgp"),))
        self.assertEqual(c.parse(["[ set protocols pim ]"]).statements, (("protocols", "pim"),))

    def test_connectors_and_trailing_or(self):
        v = "[ protocols ldp ] or\n[ protocols rsvp ]\nor\n[ protocols mpls ]"
        self.assertEqual(len(c.parse([v]).statements), 3)

    def test_anchor_stops_at_second_literal(self):
        st = c.parse(["[ protocols bgp group <name> neighbor <address> ]"]).statements
        self.assertEqual(st, (("protocols", "bgp"),))
        st = c.parse(["[ services web-filter profile profile-name dns-filter-template x ]"]).statements
        self.assertEqual(st, (("services", "web-filter"),))

    def test_interface_name_is_a_placeholder(self):
        self.assertEqual(c.parse(["[ interfaces ae0 aggregated-ether-options lacp ]"]).statements,
                         (("interfaces", ANY, "aggregated-ether-options"),))

    def test_ambiguous(self):
        for v in [
            "This vulnerability is only exploitable on interfaces with LLDP enabled.\n\n"
            "[ protocols lldp interface ]",                              # lead-in without ':'
            "[ protocols bgp ... ] is configured and more than 32 peers",  # prose after
            "And [ system processes routing bgp update-threading ] is not configured!",
            "a minimal IPv6 configuration like in the following example:\n[ interfaces x ]",
            "The following is not required:\n[ system services ssh ]",   # negation
            "routing-instance evpn10 {\n vlan-id 10;\n}",                 # hierarchy block
            "The following minimum configuration is required:\n  services application-identification",
            "set protocols bgp group [FLOWSPEC]",                         # bracket in a set line
            "[ procotol bgp family inet flow ]",                          # vendor typo
            "[ protocols ]",                                              # too coarse
            "[ <a> <b> ]",
            "",
        ]:
            self.assertIsNone(c.parse([v]), v)
        self.assertIsNone(c.parse([]))
        self.assertIsNone(c.parse([None]))
        self.assertIsNone(c.parse(["[ system extended-echo ]", "prose without colon"]))

    def test_digest_stable(self):
        a = conds(X=["[ system extended-echo ]"])
        self.assertEqual(c.digest(a), c.digest(dict(a)))
        self.assertNotEqual(c.digest(a), c.digest(conds(X=["[ protocols bgp ]"])))


class TestMatch(unittest.TestCase):
    def test_subsequence_with_gaps_and_placeholder(self):
        st = ("interfaces", ANY, "family")
        self.assertTrue(c._subsequence(st, ("interfaces", "xe-0/0/1", "unit", "0", "family", "inet6")))
        self.assertTrue(c._subsequence(("protocols", "ospf"),
                                       ("routing-instances", "v", "protocols", "ospf", "area")))
        self.assertFalse(c._subsequence(("system", "extended-echo"), ("system", "host-name", "x")))
        self.assertFalse(c._subsequence(("protocols", "bgp"), ("bgp", "protocols")))


class TestConfig(unittest.TestCase):
    def test_complete(self):
        cfg = jc.JunosConfig(CONFIG)
        self.assertEqual(cfg.completeness(FW), (True, None))
        self.assertEqual(cfg.completeness("JUNOS 21.1R1.1"), (False, "version_mismatch"))

    def test_incomplete_reasons(self):
        self.assertEqual(jc.JunosConfig("version 1;\n").completeness(FW), (False, "no_set_section"))
        no_ver = CONFIG.replace("set version 20.4R3-S5.3\n", "")
        self.assertEqual(jc.JunosConfig(no_ver).completeness(FW), (False, "no_version"))
        no_host = CONFIG.replace("set system host-name LF1\n", "")
        self.assertEqual(jc.JunosConfig(no_host).completeness(FW), (False, "no_host_name"))
        extra = CONFIG.replace("deactivate protocols lldp\n", "")
        self.assertEqual(jc.JunosConfig(extra).completeness(FW), (False, "deactivate_mismatch"))

    def test_condition_states(self):
        cfg = jc.JunosConfig(CONFIG)
        st = lambda v: cfg.condition_state(c.parse([v]))
        self.assertEqual(st("[ system extended-echo ]"), "absent")
        self.assertEqual(st("[ protocols bgp group <name> neighbor <address> ]"), "present")
        self.assertEqual(st("[ protocols ospf area ]"), "present")       # under a routing instance
        self.assertEqual(st("[ protocols lldp ]"), "inactive_only")
        self.assertEqual(st("[ protocols isis ] or\n[ protocols bgp ]"), "present")

    def test_evaluate(self):
        e = jc.evaluate(CONFIG, conds(CVE_1=["[ system extended-echo ]"],
                                      CVE_2=["[ protocols bgp ]"],
                                      CVE_3=["[ protocols lldp ]"]), FW)
        self.assertTrue(e["complete"])
        self.assertEqual(e["absent"], ["CVE-1"])
        self.assertEqual(e["inactive_only"], ["CVE-3"])
        self.assertEqual(e["version"], "20.4R3-S5.3")

    def test_evaluate_incomplete_claims_nothing(self):
        e = jc.evaluate(CONFIG, conds(CVE_1=["[ system extended-echo ]"]), "JUNOS 21.1R1.1")
        self.assertFalse(e["complete"])
        self.assertEqual(e["reason"], "version_mismatch")
        self.assertEqual(e["absent"], [])

    def test_ports(self):
        p = jc.JunosConfig(CONFIG).ports()
        self.assertEqual(p["xe-0/0/38"], {"described": True, "trunk": False})
        self.assertEqual(p["mge-0/0/25"], {"described": True, "trunk": True})
        self.assertEqual(p["ge-0/0/2"], {"described": False, "trunk": False})   # placeholder text
        self.assertTrue(p["ge-0/0/3"]["described"])                              # unit description
        self.assertFalse(p["ge-0/0/9"]["described"])                             # deactivated
        self.assertTrue(p["ge-0/0/10"]["trunk"])                                 # port-mode trunk
        for name in ("ge-0/0/20", "ge-0/0/30", "ge-0/0/31", "ge-0/0/32"):
            self.assertEqual(p[name], {"described": True, "trunk": True}, name)
        self.assertNotIn("ge-0/0/33", p)
        self.assertNotIn("irb", p)
        self.assertFalse(any("*" in k for k in p))

    def test_expand(self):
        self.assertEqual(jc._expand("xe-0/0/1", "xe-0/0/3"), ["xe-0/0/1", "xe-0/0/2", "xe-0/0/3"])
        self.assertEqual(jc._expand("xe-0/0/1", "xe-0/1/3"), [])
        self.assertEqual(jc._expand("xe-0/0/5", "xe-0/0/1"), [])

    def test_no_secret_leaves(self):
        e = jc.evaluate(CONFIG, conds(CVE_1=["[ system extended-echo ]"],
                                      CVE_2=["[ snmp community ]"]), FW)
        blob = json.dumps(e)
        for leak in (SECRET, "2AA8YO", "CUSTOMER", "192.0.2.1", "VRF1", "authorization"):
            self.assertNotIn(leak, blob)


if __name__ == "__main__":
    unittest.main()
