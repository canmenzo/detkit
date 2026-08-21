"""Unit tests for the rule-authoring probe.

The EVTX path needs the network and a pinned sample, so it is exercised by hand
and by the detection tests. What is worth pinning here is the tier split: a rule
whose telemetry has no public capture must still be probeable, or the first thing
someone tries on a cloud rule fails.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from detkit import probe


def test_cloud_rule_probes_its_case_set(capsys: pytest.CaptureFixture[str]) -> None:
    assert probe.run("entra_signin_legacy_auth_success") == 0
    out = capsys.readouterr().out
    assert "labelled cases" in out
    assert "(TP)" in out and "(TN)" in out


def test_windows_rule_takes_the_evtx_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tier is decided by logsource.product, not by which files happen to exist."""
    monkeypatch.setattr(probe, "manifest", lambda stem: [])
    assert probe.run("security_win_service_installed") == 1


def test_unknown_rule_lists_the_corpus(capsys: pytest.CaptureFixture[str]) -> None:
    assert probe.run("no_such_rule") == 1
    assert "security_win_service_installed" in capsys.readouterr().out


def test_missing_case_set_is_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(probe, "EVALS", tmp_path)
    assert probe.run("entra_signin_legacy_auth_success") == 1
    assert "no labelled cases" in capsys.readouterr().out
