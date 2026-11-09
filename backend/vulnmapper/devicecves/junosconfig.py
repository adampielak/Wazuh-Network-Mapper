"""A Junos device's saved configuration, read for two questions: which
configuration-conditioned CVEs it cannot have (:mod:`conditions`), and which
physical ports carry a description or run as trunks (the checklist).

The input is the text of a configuration backup that holds a ``display set``
section: only lines starting with ``set `` or ``deactivate `` are read, every
other line (the hierarchical form, comments) is ignored. A path is the token
list of one ``set`` line; a ``deactivate`` line marks every path it prefixes
inactive.

The configuration is used only when it is *complete*: a ``set version`` line,
a ``system host-name`` statement, as many ``deactivate`` lines as ``inactive:``
markers in the hierarchical part, and a version equal to the release the
device reports (a backup older than the last upgrade is not the running
configuration). Otherwise :func:`evaluate` reports why and claims nothing.

Nothing from the configuration leaves this module except CVE ids, interface
names and two booleans per interface: no statement, value or description.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from . import conditions as cond

log = logging.getLogger("vulnmapper.devicecves")

FORMAT = 1

_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\S+')
_PLACEHOLDER_DESC = re.compile(
    r"^(?:-+|n/?a|none|unused|spare|free|vacant|empty|reserved?|not[ _-]?used|nc)$", re.I)
_PHYSICAL = re.compile(r"^[a-z]+-\d+/\d+/\d+(?::\d+)?$")
_RANGE_END = re.compile(r"^(.*/)(\d+)$")


def _tokens(line: str) -> list:
    return _TOKEN.findall(line)


def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] == '"':
        return tok[1:-1]
    return tok


def _norm_version(text: str) -> str:
    v = (text or "").strip().strip(";").strip().lower()
    if v.startswith("junos"):
        v = v[5:].strip()
    return v


def _prefixed(path: tuple, prefixes: list) -> bool:
    return any(path[:len(p)] == p for p in prefixes)


class JunosConfig:
    """The ``set``/``deactivate`` lines of one backup."""

    def __init__(self, text: str) -> None:
        self.raw_paths = []           # original-case tokens, one list per set line
        self.deactivated = []         # lower-case token tuples
        self.inactive_markers = 0
        self.version: Optional[str] = None
        for line in (text or "").splitlines():
            if line.startswith("set "):
                toks = _tokens(line)[1:]
                if toks:
                    self.raw_paths.append(toks)
                    if toks[0] == "version" and len(toks) > 1:
                        self.version = _unquote(toks[1])
            elif line.startswith("deactivate "):
                toks = _tokens(line)[1:]
                if toks:
                    self.deactivated.append(tuple(t.lower() for t in toks))
            elif "inactive:" in line and not line.lstrip().startswith("#"):
                self.inactive_markers += 1
        self.paths = [tuple(t.lower() for t in p) for p in self.raw_paths]
        self.active = [not _prefixed(p, self.deactivated) for p in self.paths]
        self._index: dict = {}        # token -> indices of the paths holding it
        for i, p in enumerate(self.paths):
            for t in set(p):
                self._index.setdefault(t, []).append(i)

    # -- completeness ------------------------------------------------------

    def completeness(self, firmware: str) -> tuple:
        """``(complete, reason)``; reason is None when complete."""
        if not self.paths:
            return False, "no_set_section"
        if self.version is None:
            return False, "no_version"
        if not any(cond._subsequence(("system", "host-name"), p) for p in self.paths):
            return False, "no_host_name"
        if len(self.deactivated) != self.inactive_markers:
            return False, "deactivate_mismatch"
        if _norm_version(self.version) != _norm_version(firmware):
            return False, "version_mismatch"
        return True, None

    # -- configuration conditions -----------------------------------------

    def condition_state(self, condition: "cond.Condition") -> str:
        """``present`` (a statement found in an active path), ``inactive_only``
        (found only in deactivated paths) or ``absent``."""
        found_inactive = False
        for st in condition.statements:
            literals = [t for t in st if t != cond.ANY]
            candidates = set(self._index.get(literals[0], ()))
            for t in literals[1:]:
                candidates &= set(self._index.get(t, ()))
            for i in sorted(candidates):
                if cond._subsequence(st, self.paths[i]):
                    if self.active[i]:
                        return "present"
                    found_inactive = True
        return "inactive_only" if found_inactive else "absent"

    # -- ports -------------------------------------------------------------

    def ports(self) -> dict:
        """``{physical ifname: {"described": bool, "trunk": bool}}``, from
        ``interfaces`` statements and ``interface-range`` members. Groups are
        not read."""
        out: dict = {}
        ranges: dict = {}          # range name -> {"members": set, "described", "trunk"}

        def mark(meta: dict, rest: list, active: bool) -> None:
            low = [t.lower() for t in rest]
            if active and "description" in low:
                i = low.index("description")
                text = _unquote(rest[i + 1]).strip() if i + 1 < len(rest) else ""
                if text and not _PLACEHOLDER_DESC.match(text):
                    meta["described"] = True
            if active and any(low[i] in ("interface-mode", "port-mode") and low[i + 1] == "trunk"
                              for i in range(len(low) - 1)):
                meta["trunk"] = True

        for raw, active in zip(self.raw_paths, self.active):
            if len(raw) < 3 or raw[0] != "interfaces":
                continue
            name = raw[1]
            if name == "interface-range":
                if len(raw) < 4:
                    continue
                r = ranges.setdefault(raw[2], {"members": set(), "described": False, "trunk": False})
                rest = raw[3:]
                if not active:
                    continue
                if rest[0] == "member" and len(rest) > 1:
                    r["members"].add(_unquote(rest[1]))
                elif rest[0] == "member-range" and len(rest) > 3 and rest[2] == "to":
                    r["members"].update(_expand(rest[1], rest[3]))
                else:
                    mark(r, rest, active)
                continue
            if not _PHYSICAL.match(name):
                continue
            meta = out.setdefault(name, {"described": False, "trunk": False})
            mark(meta, raw[2:], active)
        for r in ranges.values():
            for member in r["members"]:
                if not _PHYSICAL.match(member):
                    continue       # a wildcard member: not expanded
                meta = out.setdefault(member, {"described": False, "trunk": False})
                meta["described"] = meta["described"] or r["described"]
                meta["trunk"] = meta["trunk"] or r["trunk"]
        return out


def _expand(first: str, last: str) -> list:
    """The interfaces of ``member-range first to last`` when both share the
    prefix up to the last number, else []."""
    a, b = _RANGE_END.match(first), _RANGE_END.match(last)
    if not a or not b or a.group(1) != b.group(1):
        return []
    lo, hi = int(a.group(2)), int(b.group(2))
    if hi < lo or hi - lo > 512:
        return []
    return [f"{a.group(1)}{i}" for i in range(lo, hi + 1)]


def evaluate(text: str, conditions: dict, firmware: str) -> dict:
    """One device's sidecar entry from its backup text, the usable conditions
    (``{cve id: Condition}``) and the firmware string the device reports."""
    cfg = JunosConfig(text)
    complete, reason = cfg.completeness(firmware)
    entry = {"complete": complete, "reason": reason, "version": cfg.version,
             "absent": [], "inactive_only": [], "ports": cfg.ports() if cfg.paths else {}}
    if not complete:
        return entry
    for cve_id in sorted(conditions):
        state = cfg.condition_state(conditions[cve_id])
        if state == "absent":
            entry["absent"].append(cve_id)
        elif state == "inactive_only":
            entry["inactive_only"].append(cve_id)
    return entry


def build_index(devices: dict, conditions: dict, generated_at: str, records: int) -> dict:
    """The sidecar document from ``{chassis id: evaluate() entry}``."""
    return {"format": FORMAT, "generated_at": generated_at,
            "conditions": {"records": records, "usable": len(conditions),
                           "hash": cond.digest(conditions),
                           "ids": {k: cond.fingerprint(v) for k, v in sorted(conditions.items())}},
            "devices": devices}


class DeviceConfig:
    """One device's sidecar entry, as the device CVE stage uses it."""

    def __init__(self, entry: dict, fingerprints: dict) -> None:
        self.complete = bool(entry.get("complete"))
        self.reason = entry.get("reason")
        self.absent = set(entry.get("absent") or ()) if self.complete else set()
        self._fingerprints = fingerprints

    def excludes(self, record: dict) -> bool:
        """Whether ``record`` (a trimmed Juniper record) needs configuration
        this device does not have: its id is in the device's ``absent`` list,
        its text still parses, and to the same anchors the sidecar used."""
        cve_id = record.get("id")
        if cve_id not in self.absent:
            return False
        parsed = cond.parse(record.get("configurations") or [])
        return parsed is not None and cond.fingerprint(parsed) == self._fingerprints.get(cve_id)


class ConfigIndex:
    """The sidecar (``--junos-config-index``): per device, the configuration
    conditions it lacks and its port metadata."""

    def __init__(self, doc: dict) -> None:
        if not isinstance(doc, dict) or doc.get("format") != FORMAT \
                or not isinstance(doc.get("devices"), dict):
            raise ValueError("not a Junos configuration index")
        self.generated_at = doc.get("generated_at")
        self.devices = doc["devices"]
        self._fingerprints = dict(((doc.get("conditions") or {}).get("ids")) or {})

    @classmethod
    def load(cls, path: Optional[str]) -> Optional["ConfigIndex"]:
        """The index at ``path``, or None (with a warning) when there is none or
        it cannot be read: the stages then behave as without it."""
        if not path:
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return cls(json.load(f))
        except (OSError, ValueError) as e:
            log.warning("Junos configuration index %s not used (%s)", path, type(e).__name__)
            return None

    def device(self, chassis_id: Optional[str]) -> Optional[DeviceConfig]:
        entry = self.devices.get(chassis_id) if chassis_id else None
        if not isinstance(entry, dict):
            return None
        return DeviceConfig(entry, self._fingerprints)

    def ports(self, chassis_id: Optional[str]) -> Optional[dict]:
        """``{ifname: {"described", "trunk"}}`` for a device whose backup is
        complete, or None."""
        entry = self.devices.get(chassis_id) if chassis_id else None
        if not isinstance(entry, dict) or not entry.get("complete") \
                or not isinstance(entry.get("ports"), dict):
            return None
        return entry["ports"]
