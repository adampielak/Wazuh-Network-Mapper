"""Standalone, files-only exposure evaluation."""

from __future__ import annotations

import argparse
import json
import os
import sys

from ..common import write_json_atomic
from . import compute_exposure


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnmapper.exposure")
    parser.add_argument("--graph", required=True, metavar="PATH")
    parser.add_argument("--zones", required=True, metavar="PATH")
    parser.add_argument("--kev", metavar="PATH")
    parser.add_argument("--out", metavar="PATH")
    return parser


def _document(graph: dict, zones: dict, kev: dict | None) -> dict:
    result = compute_exposure(graph, zones, kev)
    counts = {
        "nodes_with_items": sum(bool(items) for items in result["nodes"].values()),
        "items": sum(len(items) for items in result["nodes"].values()),
        "zone_gaps": len(result["zone_gaps"]),
    }
    return {
        "source_scan": (graph.get("metadata") or {}).get("scan_time"),
        "nodes": result["nodes"],
        "zone_gaps": result["zone_gaps"],
        "classes": result["classes"],
        "limits": result["limits"],
        "counts": counts,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open(args.graph, encoding="utf-8") as f:
            graph = json.load(f)
        with open(args.zones, encoding="utf-8") as f:
            zones = json.load(f)
        kev = None
        if args.kev:
            with open(args.kev, encoding="utf-8") as f:
                kev = json.load(f)
        document = _document(graph, zones, kev)
    except ValueError as exc:
        print(f"exposure: {exc}", file=sys.stderr)
        return 1

    output = args.out or os.path.join(os.path.dirname(os.path.abspath(args.graph)), "exposure.json")
    write_json_atomic(output, document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
