"""Unit tests for the deployability check on compiled queries."""
from __future__ import annotations

from detkit.convert import queries, unbound

# An SPL query can span physical lines: the Sigma `|re` modifier renders as a
# `| regex ...` continuation. Treating every line as a query is what made the
# first version of this check report a correctly-bound rule as unbound.
MULTILINE = """\
source="WinEventLog:Security" EventCode=1102

source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="*\\\\powershell.exe"
| regex CommandLine="\\\\s-e[a-z]*\\\\s+[A-Za-z0-9+/=]{15,}"

source="WinEventLog:Security" EventCode=4720
"""


def test_multiline_query_counts_once() -> None:
    assert len(queries(MULTILINE)) == 3


def test_continuation_line_is_not_treated_as_unbound() -> None:
    """The regression this check itself caused."""
    assert unbound(MULTILINE) == []


def test_reports_a_genuinely_unbound_query() -> None:
    text = 'source="WinEventLog:Security" EventCode=1102\n\nEventCode=4688 Image="*\\\\x.exe"\n'
    loose = unbound(text)
    assert len(loose) == 1
    assert loose[0].startswith("EventCode=4688")


def test_binding_may_appear_on_a_later_line() -> None:
    text = 'index=main\n| search source="WinEventLog:Security" EventCode=1102\n'
    assert unbound(text) == []


def test_empty_output_has_no_queries() -> None:
    assert queries("") == []
    assert queries("\n\n  \n") == []
    assert unbound("") == []


def test_untabled_flags_a_query_that_does_not_open_with_a_known_table() -> None:
    """The Kusto equivalent of an unbound Splunk search."""
    from detkit.convert import untabled

    text = (
        "SigninLogs\n| where ResultType =~ \"0\"\n\n"
        "search *\n| where OperationName =~ \"x\"\n\n"
        "AuditLogs\n| where Result =~ \"success\"\n"
    )
    assert untabled(text, ("SigninLogs", "AuditLogs")) == ["search *"]
