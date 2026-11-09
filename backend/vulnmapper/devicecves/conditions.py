"""The configuration a Juniper CVE record says a device needs, read
conservatively.

Juniper's CVE JSON 5 records carry ``containers.cna.configurations``: free
text, most often a lead-in sentence followed by one or more configuration
statements in brackets (``[ system extended-echo ]``) or as ``set`` lines.
:func:`parse` turns a record's values into a :class:`Condition` only when every
line of every value is one this module understands; anything else (prose after
a statement, a hierarchy block, a negation, "for example", "is not
configured") makes the record *ambiguous*, and an ambiguous record is never
used to drop a CVE.

A usable condition is a list of statements, each a list of tokens. The
statements are joined by OR whatever the text says ("and", "both of the
following"): a CVE is dropped only when *none* of its statements is found in
the device configuration, so reading an AND as an OR can keep a CVE that does
not apply, never drop one that does.

Only a statement's *anchor* is matched: its tokens up to and including the
second literal one (``[ protocols bgp group <name> neighbor <address> ]`` ->
``protocols bgp``). The vendor text names placeholders without brackets at
times (``profile profile-name``) and has typos; past the anchor neither can make
a statement look absent. A statement whose first token is not a Junos
top-level hierarchy in :data:`TOP_LEVEL` makes the record ambiguous (this
catches ``procotol bgp``); a missing hierarchy there only keeps more CVEs.

An anchor matches a configuration path (the tokens of one ``set`` line) when
its tokens appear in the path *in order*, gaps allowed. Gaps cover the levels a
statement leaves out (``[ interfaces <interface> family inet6 ]`` against
``interfaces xe-0/0/1 unit 0 family inet6``), ``...`` in the statement, and a
statement placed under ``routing-instances``, ``logical-systems`` or
``groups``. A placeholder (``<name>``, a token with a ``/`` or a quote) stands
for exactly one token. Literal tokens compare case-insensitively.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

ANY = "<any>"          # a placeholder token: matches exactly one path token
ANCHOR_LITERALS = 2    # literal tokens kept from the start of a statement

# Junos top-level configuration hierarchies a statement may start with
TOP_LEVEL = frozenset({
    "access", "access-profile", "accounting-options", "applications", "bridge-domains",
    "chassis", "class-of-service", "dynamic-profiles", "ethernet-switching-options",
    "event-options", "firewall", "forwarding-options", "interfaces", "logical-systems",
    "multi-chassis", "poe", "policy-options", "protocols", "routing-instances",
    "routing-options", "security", "services", "snmp", "switch-options", "system",
    "virtual-chassis", "vlans",
})

# a statement line: "[ a b c ]" (optionally "[edit a b c]", optionally a
# trailing "or"), or "set a b c"
_BRACKET = re.compile(r"^\[\s*(?:edit\s+)?(.+?)\s*\](?:\s+or)?\s*$", re.I)
_SET = re.compile(r"^set\s+(.+?)\s*;?\s*$", re.I)
_CONNECTOR = re.compile(r"^(?:or|and)$", re.I)
# words that make a lead-in (and so the record) ambiguous: the text no longer
# states a plain "this configuration is needed"
_AMBIGUOUS_WORDS = re.compile(
    r"\b(?:include|includes|including|similar|examples?|e\.g|such\s+as|some|dependent|depends?"
    r"|vary|varies|platforms?|among|like|sample|default|implicit|implicitly|verify|show|refer"
    r"|see|documentation|optional|either|not|no|without|unless|except|disabled?|neither|nor"
    r"|n't)\b", re.I)
_PLACEHOLDER = re.compile(r"<[^<>]*>")
_QUOTED = re.compile(r"\"[^\"]*\"|'[^']*'")
_LITERAL = re.compile(r"^[A-Za-z0-9_.:-]+$")
_IFNAME = re.compile(r"^[a-z]+(?:-\d|\d)")


@dataclass(frozen=True)
class Condition:
    """A usable record: its statements' anchors (tuples of tokens, ANY for a
    placeholder), joined by OR."""
    statements: tuple = field(default_factory=tuple)


def _statement(body: str) -> Optional[tuple]:
    """The tokens of one statement body, or None when a token is not one this
    module reads."""
    body = _QUOTED.sub(" <q> ", body)
    body = _PLACEHOLDER.sub(" <p> ", body)
    # "..." and a double-space gap are gaps; the matcher allows gaps anywhere
    body = body.replace("…", " ").replace("...", " ")
    tokens = []
    for tok in body.split():
        if tok in ("<p>", "<q>"):
            tokens.append(ANY)
        elif "/" in tok or '"' in tok or "'" in tok:
            tokens.append(ANY)
        elif _LITERAL.match(tok):
            tokens.append(tok.lower())
        else:
            return None
    if tokens and tokens[0] == "set":
        tokens = tokens[1:]
    if len(tokens) > 1 and tokens[0] == "interfaces" and _IFNAME.match(tokens[1]):
        tokens[1] = ANY     # "interfaces ae0": an example name, not a requirement
    if not tokens or tokens[0] not in TOP_LEVEL:
        return None
    anchor, literals = [], 0
    for tok in tokens:
        anchor.append(tok)
        literals += tok != ANY
        if literals == ANCHOR_LITERALS:
            break
    if literals < ANCHOR_LITERALS:
        return None         # "[ protocols ]" alone: too coarse to rely on
    return tuple(anchor)


def parse(values: Iterable) -> Optional[Condition]:
    """A record's ``configurations`` values -> its :class:`Condition`, or None
    when the record is ambiguous (or has no statement)."""
    statements = []
    for value in values or []:
        if not isinstance(value, str):
            return None
        for raw in value.splitlines():
            line = raw.strip()
            if not line:
                continue
            m = _BRACKET.match(line) or _SET.match(line)
            if m:
                st = _statement(m.group(1))
                if st is None:
                    return None
                statements.append(st)
                continue
            if _CONNECTOR.match(line):
                continue
            if line.endswith(":") and not _AMBIGUOUS_WORDS.search(line) \
                    and "[" not in line and "]" not in line and "{" not in line:
                continue
            return None
    if not statements:
        return None
    return Condition(tuple(dict.fromkeys(statements)))


def _subsequence(statement: tuple, path: tuple) -> bool:
    """Whether ``statement``'s tokens appear in ``path`` in order (gaps
    allowed); ANY takes exactly one path token."""
    i = 0
    for tok in path:
        if i == len(statement):
            break
        if statement[i] == ANY or statement[i] == tok:
            i += 1
    return i == len(statement)


def matches(condition: Condition, paths: Iterable) -> bool:
    """Whether any statement of ``condition`` is found in any of ``paths``
    (each a tuple of lower-case tokens)."""
    paths = list(paths)
    return any(_subsequence(st, p) for st in condition.statements for p in paths)


def usable(records: dict) -> dict:
    """``{cve id: Condition}`` for the records whose ``configurations`` parse,
    from ``{cve id: record}``."""
    out = {}
    for cve_id, record in records.items():
        cond = parse((record or {}).get("configurations") or [])
        if cond is not None:
            out[cve_id] = cond
    return out


def fingerprint(condition: Condition) -> str:
    """A short hash of one condition's anchors: the sidecar and the stage
    compare it so a record whose text changed in between is never dropped on
    the older reading."""
    blob = json.dumps([list(s) for s in condition.statements], separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def digest(conditions: dict) -> str:
    """A short hash of the usable conditions, for cache keys."""
    blob = json.dumps({k: [list(s) for s in v.statements] for k, v in sorted(conditions.items())},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
