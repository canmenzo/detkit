"""Unit tests for the metadata gate."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from detkit.attack import Vocabulary
from detkit.rules import Rule, load_rule
from detkit.validate import check_condition, has_technique_tag, validate_rule

VOCAB = Vocabulary(
    version="19.2",
    reviewed="19.2",
    techniques=frozenset({"T1059.001"}),
    tactics=frozenset({"execution"}),
)

COMPLETE = """\
title: Example
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: An example rule.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Can Ozmen
date: 2026-08-14
modified: 2026-08-14
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
falsepositives:
  - Nothing plausible.
level: high
"""


def _rule(tmp_path: Path, body: str, stem: str = "example") -> Rule:
    path = tmp_path / f"{stem}.yml"
    path.write_text(body, encoding="utf-8")
    return load_rule(path)


def test_complete_rule_with_fixture_passes(tmp_path: Path) -> None:
    rule = _rule(tmp_path, COMPLETE)
    assert validate_rule(rule, VOCAB, exempt={"example"}) == []


def test_missing_fixture_is_reported(tmp_path: Path) -> None:
    rule = _rule(tmp_path, COMPLETE)
    errors = validate_rule(rule, VOCAB, exempt=set())
    assert any("no test fixture" in e for e in errors)


def test_missing_required_fields_are_reported(tmp_path: Path) -> None:
    rule = _rule(tmp_path, COMPLETE.replace("author: Can Ozmen\n", ""))
    errors = validate_rule(rule, VOCAB, exempt={"example"})
    assert "missing required field: author" in errors


def test_empty_field_counts_as_missing(tmp_path: Path) -> None:
    rule = _rule(tmp_path, COMPLETE.replace("level: high", "level: ''"))
    errors = validate_rule(rule, VOCAB, exempt={"example"})
    assert "missing required field: level" in errors


def test_rule_without_technique_tag_is_reported(tmp_path: Path) -> None:
    rule = _rule(tmp_path, COMPLETE.replace("  - attack.t1059.001\n", ""))
    errors = validate_rule(rule, VOCAB, exempt={"example"})
    assert any("no ATT&CK technique tag" in e for e in errors)


def test_unknown_tag_is_reported(tmp_path: Path) -> None:
    rule = _rule(tmp_path, COMPLETE.replace("attack.t1059.001", "attack.t9999"))
    errors = validate_rule(rule, VOCAB, exempt={"example"})
    assert any("unknown ATT&CK technique" in e for e in errors)


def test_accepts_single_line_condition() -> None:
    assert check_condition({"condition": "selection and not filter"}) == []


@pytest.mark.parametrize("condition", ["selection and filter\n", "selection\nand filter"])
def test_rejects_multiline_condition(condition: str) -> None:
    """A folded scalar parses fine here but silently breaks Hayabusa's parser."""
    errors = check_condition({"condition": condition})
    assert len(errors) == 1
    assert "single-line scalar" in errors[0]


def test_multiline_condition_fails_the_gate(tmp_path: Path) -> None:
    body = COMPLETE.replace("  condition: selection\n", "  condition: >\n    selection\n")
    rule = _rule(tmp_path, body)
    errors = validate_rule(rule, VOCAB, exempt={"example"})
    assert any("single-line scalar" in e for e in errors)


@pytest.mark.parametrize(
    "tags,expected",
    [
        (["attack.t1059.001"], True),
        (["attack.T1027"], True),
        (["attack.execution"], False),
        ([], False),
        (None, False),
        ("attack.t1059.001", False),
    ],
)
def test_has_technique_tag(tags: Any, expected: bool) -> None:
    assert has_technique_tag(tags) is expected


CLOUD = COMPLETE.replace("product: windows", "product: azure\n  service: signinlogs")


def test_cloud_rule_needs_labelled_cases_not_an_evtx_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Telemetry with no public capture is measured instead, never neither."""
    from detkit import validate as validate_mod

    rule = _rule(tmp_path, CLOUD, stem="entra_x")
    monkeypatch.setattr(validate_mod, "has_case_set", lambda _stem: False)
    errors = validate_mod.check_evidence(rule, set())
    assert errors and "no labelled eval cases" in errors[0]

    monkeypatch.setattr(validate_mod, "has_case_set", lambda _stem: True)
    assert validate_mod.check_evidence(rule, set()) == []


def test_cloud_rule_may_not_claim_the_evtx_exemption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """conversion_only.txt exempts a rule from a gate that never applied to it."""
    from detkit import validate as validate_mod

    rule = _rule(tmp_path, CLOUD, stem="entra_x")
    monkeypatch.setattr(validate_mod, "has_case_set", lambda _stem: True)
    errors = validate_mod.check_evidence(rule, {"entra_x"})
    assert errors and "conversion_only.txt" in errors[0]
