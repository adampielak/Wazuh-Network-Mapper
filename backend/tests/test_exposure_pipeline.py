"""Pipeline and standalone CLI wiring for synthetic exposure data."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import offline  # noqa: F401

from vulnmapper import pipeline
from vulnmapper.exposure.__main__ import main as exposure_main
from vulnmapper.pipeline import Pipeline


HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


class TestExposurePipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.graph_path = os.path.join(self.tmp, "graph.json")
        self.exposure_path = os.path.join(self.tmp, "exposure.json")
        self.zones_path = os.path.join(self.tmp, "zones.json")
        with open(self.zones_path, "w", encoding="utf-8") as f:
            json.dump({"trust_order": {}, "vlans": {}, "prefixes": {}}, f)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def scan(self, *extra):
        argv = ["--no-endpoints", "--network", os.path.join(FIXTURES, "offline_network.json"),
                "--no-device-cves", "--no-cve-vectors", "--no-checklist", "--no-name-lookup",
                "--no-attack-paths", "-o", self.graph_path, *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)
        with open(self.graph_path, encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def stage(graph, name="Exposure"):
        return next(row for row in graph["metadata"]["stages"] if row["name"] == name)

    def test_without_zones_has_no_exposure_trace_or_file(self):
        without = self.scan()
        self.assertNotIn("Exposure", [row["name"] for row in without["metadata"]["stages"]])
        self.assertNotIn("exposure_s", without["metadata"]["timing"])
        self.assertFalse(os.path.exists(self.exposure_path))
        with_zones = self.scan("--zones", self.zones_path)
        self.assertEqual(without["nodes"], with_zones["nodes"])
        self.assertEqual(without["edges"], with_zones["edges"])
        self.assertTrue(os.path.exists(self.exposure_path))

    def test_zones_and_kev_write_separate_document_with_counts_and_source(self):
        graph = self.scan("--zones", self.zones_path, "--kev",
                          os.path.join(FIXTURES, "exposure", "synthetic_kev.json"))
        with open(self.exposure_path, encoding="utf-8") as f:
            document = json.load(f)
        self.assertEqual(document["source_scan"], graph["metadata"]["scan_time"])
        self.assertEqual(set(document), {"source_scan", "nodes", "zone_gaps", "classes", "limits", "counts"})
        self.assertEqual(document["counts"], {
            "nodes_with_items": sum(bool(items) for items in document["nodes"].values()),
            "items": sum(len(items) for items in document["nodes"].values()),
            "zone_gaps": len(document["zone_gaps"]),
        })
        self.assertEqual(self.stage(graph)["status"], "ran")
        self.assertIn("item", self.stage(graph)["note"])

    def test_stdout_graph_without_explicit_exposure_output_skips(self):
        argv = ["--no-endpoints", "--network", os.path.join(FIXTURES, "offline_network.json"),
                "--no-device-cves", "--no-cve-vectors", "--no-checklist", "--no-name-lookup",
                "--no-attack-paths", "--zones", self.zones_path]
        with contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)
        graph = json.loads(stdout.getvalue())
        self.assertEqual(self.stage(graph), {
            "name": "Exposure", "status": "skipped", "seconds": None,
            "note": "no output file given",
        })
        self.assertFalse(os.path.exists(self.exposure_path))

    def test_malformed_zones_fail_only_exposure_stage(self):
        with open(self.zones_path, "w", encoding="utf-8") as f:
            json.dump({"prefixes": {"invalid-prefix": "user"}}, f)
        previous = b'{"source_scan":"previous-scan"}\n'
        with open(self.exposure_path, "wb") as f:
            f.write(previous)
        with self.assertLogs("vulnmapper.pipeline", "ERROR"):
            graph = self.scan("--zones", self.zones_path)
        self.assertEqual(self.stage(graph)["status"], "failed")
        self.assertIn({"type": "stage_failed", "stage": "Exposure", "error": "ValueError"},
                      graph["metadata"]["warnings"])
        with open(self.exposure_path, "rb") as f:
            self.assertEqual(f.read(), previous)

    def test_missing_zones_file_fails_only_exposure_stage(self):
        missing = os.path.join(self.tmp, "missing-zones.json")
        with self.assertLogs("vulnmapper.pipeline", "ERROR"):
            graph = self.scan("--zones", missing)
        self.assertEqual(self.stage(graph)["status"], "failed")
        self.assertIn({"type": "stage_failed", "stage": "Exposure", "error": "FileNotFoundError"},
                      graph["metadata"]["warnings"])
        self.assertFalse(os.path.exists(self.exposure_path))

    def test_kev_without_zones_is_parser_error(self):
        argv = ["--no-endpoints", "--network", os.path.join(FIXTURES, "offline_network.json"),
                "--kev", os.path.join(FIXTURES, "exposure", "synthetic_kev.json")]
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as raised:
                Pipeline().run(argv)
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--kev requires --zones", stderr.getvalue())

    def test_standalone_cli_happy_path_and_value_error(self):
        graph = {"nodes": [], "edges": [], "metadata": {"scan_time": "2026-01-01T00:00:00+00:00"}}
        graph_path = os.path.join(self.tmp, "input.json")
        output_path = os.path.join(self.tmp, "cli-exposure.json")
        with open(graph_path, "w", encoding="utf-8") as f:
            json.dump(graph, f)
        self.assertEqual(exposure_main(["--graph", graph_path, "--zones", self.zones_path,
                                        "--out", output_path]), 0)
        with open(output_path, encoding="utf-8") as f:
            document = json.load(f)
        self.assertEqual(document["source_scan"], graph["metadata"]["scan_time"])
        self.assertEqual(document["counts"], {"nodes_with_items": 0, "items": 0, "zone_gaps": 0})

        with open(self.zones_path, "w", encoding="utf-8") as f:
            json.dump({"prefixes": {"invalid-prefix": "user"}}, f)
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(exposure_main(["--graph", graph_path, "--zones", self.zones_path,
                                            "--out", output_path]), 1)
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertTrue(stderr.getvalue().startswith("exposure:"))

    def test_standalone_cli_missing_inputs_are_labelled_errors(self):
        graph = {"nodes": [], "edges": [], "metadata": {"scan_time": "synthetic"}}
        graph_path = os.path.join(self.tmp, "input.json")
        with open(graph_path, "w", encoding="utf-8") as f:
            json.dump(graph, f)
        cases = [
            ["--graph", os.path.join(self.tmp, "missing-graph.json"), "--zones", self.zones_path],
            ["--graph", graph_path, "--zones", os.path.join(self.tmp, "missing-zones.json")],
            ["--graph", graph_path, "--zones", self.zones_path, "--kev",
             os.path.join(self.tmp, "missing-kev.json")],
        ]
        for argv in cases:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(exposure_main(argv), 1)
            self.assertEqual(len(stderr.getvalue().splitlines()), 1)
            self.assertTrue(stderr.getvalue().startswith("exposure:"))


if __name__ == "__main__":
    unittest.main()
