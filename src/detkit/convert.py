"""Compile the corpus to each target, and check the output is deployable.

Syntactic validity is not deployability. A Splunk search with no `source=` runs
against every index the reader can see, which is not a detection — so the
binding is checked, not assumed.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from detkit.paths import DETECTIONS, REPO

OUT = REPO / "out"
SPLUNK_SPL = OUT / "splunk.spl"
XDR_KQL = OUT / "xdr.kql"
ENTRA_KQL = OUT / "entra.kql"

WINDOWS = DETECTIONS / "windows"
ENTRA = DETECTIONS / "identity" / "entra"

SPLUNK_PIPELINES = ("splunk_windows", "pipelines/splunk_sysmon_source.yml")
# The repo pipeline must come first: it sets the target table, and the vendor
# azure_monitor pipeline aborts if it cannot resolve one. See the pipeline file.
ENTRA_PIPELINES = ("pipelines/azure_monitor_entra.yml", "azure_monitor")
# Every Entra query must open with one of these. The tables are Microsoft's, and
# the backend validates each field against the named table's published schema —
# a rule referencing a column that does not exist fails to compile. That check is
# what stands in for the EVTX proof on telemetry nobody publishes captures of.
ENTRA_TABLES = ("SigninLogs", "AuditLogs")


class ConversionError(Exception):
    """The corpus did not compile, or compiled to something undeployable."""


def _sigma(*args: str) -> None:
    executable = shutil.which("sigma", path=str(Path(sys.executable).parent)) or "sigma"
    proc = subprocess.run([executable, *args], cwd=REPO, check=False)
    if proc.returncode != 0:
        raise ConversionError(f"sigma {' '.join(args)} failed with {proc.returncode}")


def queries(text: str) -> list[list[str]]:
    """Split backend output into queries.

    Queries are separated by blank lines, and an SPL query can span several
    physical lines — the `regex` command renders as a `| regex ...` continuation.
    Treating every line as a query is what made the first version of this check
    report a correctly-bound rule as unbound.
    """
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.strip():
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks


def unbound(text: str) -> list[str]:
    """Queries with no source binding, by their first line."""
    return [
        block[0]
        for block in queries(text)
        if not any("source=" in line for line in block)
    ]


def untabled(text: str, tables: Sequence[str]) -> list[str]:
    """Kusto queries that do not open with one of the expected tables."""
    return [
        block[0]
        for block in queries(text)
        if block[0].strip() not in tables
    ]


def run() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # Splunk gets the Windows tier only. The splunk_windows pipeline has no
    # notion of Entra ID, so pointing it at the whole corpus would emit
    # index-wide searches for the cloud rules — the exact failure this gate
    # exists to catch, manufactured by us.
    _sigma("convert", "-t", "splunk",
           "-p", SPLUNK_PIPELINES[0], "-p", SPLUNK_PIPELINES[1],
           str(WINDOWS), "-o", str(SPLUNK_SPL))

    text = SPLUNK_SPL.read_text(encoding="utf-8")
    all_queries = queries(text)
    loose = unbound(text)
    if loose:
        print(f"{len(loose)} Splunk query/queries have no source binding:")
        for line in loose:
            print(f"  {line}")
        return 1
    print(f"Splunk: {len(all_queries)} queries, all source-bound")

    # Only the process_creation subset. Defender XDR has no table equivalent for
    # the Windows Security-log events the rest of the corpus targets, and
    # Sentinel's SecurityEvent schema does not surface fields like PreAuthType.
    _sigma("convert", "-t", "kusto", "-p", "microsoft_xdr",
           str(DETECTIONS / "windows" / "process_creation"), "-o", str(XDR_KQL))

    kql = XDR_KQL.read_text(encoding="utf-8")
    if "DeviceProcessEvents" not in kql:
        print("XDR output is not bound to a table")
        return 1
    print(f"Microsoft XDR: {len(queries(kql))} queries, table-bound")

    _sigma("convert", "-t", "kusto",
           "-p", ENTRA_PIPELINES[0], "-p", ENTRA_PIPELINES[1],
           str(ENTRA), "-o", str(ENTRA_KQL))

    entra = ENTRA_KQL.read_text(encoding="utf-8")
    entra_queries = queries(entra)
    if not entra_queries:
        print("Entra ID: no queries produced")
        return 1
    stray = untabled(entra, ENTRA_TABLES)
    if stray:
        print(f"{len(stray)} Entra query/queries are not bound to a known table:")
        for line in stray:
            print(f"  {line}")
        return 1
    print(f"Entra ID (Azure Monitor): {len(entra_queries)} queries, table-bound "
          f"and schema-checked")
    return 0
