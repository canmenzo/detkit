"""Evaluate a Sigma rule against labelled events.

Rules are rendered to SQL by pySigma's SQLite backend and run against an
in-memory table of events. See ADR 0003 for why this engine, and for the three
semantics it pins down — all of which are implemented here.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

TABLE = "events"
INDEX_COLUMN = "__case_index__"


class EvaluationError(Exception):
    """A rule could not be evaluated."""


def _detection_fields(detection: Any) -> set[str]:
    fields: set[str] = set()
    for item in getattr(detection, "detection_items", []):
        field = getattr(item, "field", None)
        if field:
            fields.add(field)
        if hasattr(item, "detection_items"):
            fields |= _detection_fields(item)
    return fields


def referenced_fields(collection: SigmaCollection) -> set[str]:
    """Every field name the rule addresses.

    These are materialised as NULL columns so a field the data never carries
    simply does not match, instead of raising "no such column".
    """
    fields: set[str] = set()
    for rule in collection.rules:
        # Correlation rules carry no detection of their own; they aggregate
        # others. None exist in this corpus yet, and one would need its own
        # evaluation path rather than falling through silently here.
        detections = getattr(rule, "detection", None)
        if detections is None:
            continue
        for detection in detections.detections.values():
            fields |= _detection_fields(detection)
    return fields


def compile_rule(rule_path: Path) -> tuple[str, set[str]]:
    """Render a rule to SQL, with the field names it references."""
    try:
        collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
        queries = sqliteBackend().convert(collection)
    except Exception as exc:
        raise EvaluationError(f"{rule_path}: cannot convert to SQL: {exc}") from exc
    if not queries:
        raise EvaluationError(f"{rule_path}: backend produced no query")
    return queries[0], referenced_fields(collection)


def normalise(value: Any) -> Any:
    """Render an event value as text, so comparison is loose in both directions.

    Every value is stored as text and every column is declared TEXT, which makes
    SQLite apply TEXT affinity to the rule's literal before comparing. A rule
    written `EventID: 4697` therefore matches the string "4697" that EVTX
    EventData actually carries, and a rule written `ResultType: '0'` matches the
    string "0" that Entra ID carries — without either side having to lie about
    its type.

    The earlier version coerced numeric-looking *strings* to integers instead.
    That fixed the EVTX direction (PreAuthType "0" vs a rule saying 0) and broke
    the other one: Entra ID's ResultType is a string column, so a correctly
    string-typed rule stopped matching its own data while Sentinel would have
    matched it. One-sided leniency is worse than none, because it disagrees with
    the platform the query is destined for. ADR 0003 records the semantics.

    UInt64 Windows keyword masks come along for free: as text they no longer
    overflow SQLite's signed INTEGER.
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _regexp(pattern: str | None, value: Any) -> bool:
    """SQLite's REGEXP operator, which the engine does not ship.

    The Sigma `|re` modifier compiles to `field REGEXP '...'`, so without this a
    rule using a regex would raise rather than match. Sigma regexes are
    case-sensitive by default and unanchored, matching Hayabusa's behaviour.
    """
    if pattern is None or value is None:
        return False
    return re.search(pattern, str(value)) is not None


def matching_indices(query: str, fields: set[str], events: list[dict[str, Any]]) -> set[int]:
    """Indices of the events the rule matches."""
    if not events:
        return set()

    columns = sorted({key for event in events for key in event} | fields)
    conn = sqlite3.connect(":memory:")
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    try:
        # TEXT affinity on every column is what makes the comparison loose; see
        # normalise(). The index column stays affinity-free so it comes back as
        # the int it went in as.
        declared = ", ".join(
            [f'"{INDEX_COLUMN}"'] + [f'"{c}" TEXT' for c in columns]
        )
        conn.execute(f"CREATE TABLE {TABLE} ({declared})")
        placeholders = ", ".join("?" * (len(columns) + 1))
        conn.executemany(
            f"INSERT INTO {TABLE} VALUES ({placeholders})",
            [
                (index, *(normalise(event.get(c)) for c in columns))
                for index, event in enumerate(events)
            ],
        )
        cursor = conn.execute(query.replace("<TABLE_NAME>", TABLE))
        position = [d[0] for d in cursor.description].index(INDEX_COLUMN)
        return {row[position] for row in cursor.fetchall()}
    except sqlite3.Error as exc:
        raise EvaluationError(f"evaluating query failed: {exc}\n  query: {query}") from exc
    finally:
        conn.close()
