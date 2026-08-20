"""Unit tests for the report generators' transform logic.

These cover the arithmetic behind every number the repo publishes.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from detkit.coverage import scan
from detkit.dashboard import render
from detkit.navigator import build_layer

RULE = """\
title: {title}
tags:
{tags}
detection:
  selection:
    EventID: 1
  condition: selection
"""


def _write(root: Path, name: str, tags: list[str], title: str = "Example") -> None:
    root.mkdir(parents=True, exist_ok=True)
    body = RULE.format(title=title, tags="\n".join(f"  - {t}" for t in tags))
    (root / name).write_text(body, encoding="utf-8")


def test_build_layer_scores_and_pluralises() -> None:
    layer = build_layer(Counter({"T1059.001": 2, "T1027": 1}))
    assert layer["techniques"] == [
        {"techniqueID": "T1027", "score": 1, "comment": "1 detection", "enabled": True},
        {"techniqueID": "T1059.001", "score": 2, "comment": "2 detections", "enabled": True},
    ]
    assert layer["gradient"]["maxValue"] == 2
    assert layer["domain"] == "enterprise-attack"


def test_build_layer_handles_empty_corpus() -> None:
    layer = build_layer(Counter())
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1


def test_scan_counts_rules_pairs_and_techniques(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", ["attack.execution", "attack.t1059.001"])
    _write(tmp_path, "b.yml", ["attack.stealth", "attack.t1027", "attack.t1059.001"])
    _write(tmp_path, "untagged.yml", ["detection.threat-hunting"])

    result = scan(tmp_path)
    assert result.n_rules == 2  # the untagged rule is not counted
    assert result.counts == Counter({"T1059.001": 2, "T1027": 1})
    assert result.pairs == {
        ("execution", "T1059.001"),
        ("stealth", "T1027"),
        ("stealth", "T1059.001"),
    }


def test_scan_folds_retired_tactic_token(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", ["attack.defense-evasion", "attack.t1027"])
    assert scan(tmp_path).pairs == {("stealth", "T1027")}


def _card(stem: str, **overrides: object) -> dict[str, object]:
    card: dict[str, object] = {
        "stem": stem, "title": "Rule", "description": "d", "level": "high",
        "tactics": ["Execution"], "techniques": ["T1059.001"], "logsource": "security",
        "status": "tested", "samples": 1, "path": f"detections/{stem}.yml",
        "metrics": {},
    }
    card.update(overrides)
    return card


SCORED = {
    "tp": 4, "fp": 0, "fn": 0, "tn": 4,
    "precision": 1.0, "recall": 1.0, "fp_rate": 0.0,
}


def test_render_reports_counts_and_escapes_titles() -> None:
    rules = [
        _card("one", title="Rule <script>", samples=2, metrics=SCORED),
        _card("two", techniques=["T1027"], status="conversion-only", samples=0),
    ]
    html_out = render(rules, {"total_rules": 2399, "convert": {"rate": 1.0},
                              "techniques": ["T1105"]})

    assert "<b>2</b><span>authored detections</span>" in html_out
    assert "<b>2</b><span>ATT&amp;CK techniques authored</span>" in html_out
    assert "<b>1</b><span>fixture-tested on real EVTX</span>" in html_out
    assert "<b>2</b><span>pinned EVTX samples</span>" in html_out
    # Only the rule carrying metrics counts as scored, and its cases are summed.
    assert "<b>1</b><span>scored for precision/recall</span>" in html_out
    assert "<b>8</b><span>labelled eval events</span>" in html_out
    # The vendored tier is named separately, not folded into the headline stats.
    assert "<b>2,399</b> third-party rules" in html_out
    assert 'data-tactic="Execution">Execution <span>2</span>' in html_out


def test_render_without_vendored_report() -> None:
    html_out = render([_card("one", status="untested", samples=0)], {})
    assert "<b>0</b> third-party rules" in html_out
    assert "—" in html_out


def test_render_counts_only_vendored_only_techniques() -> None:
    """A technique the authored corpus already covers is not a vendored addition."""
    rules = [_card("one", techniques=["T1059.001"])]
    html_out = render(rules, {"total_rules": 10, "convert": {"rate": 1.0},
                              "techniques": ["T1059.001", "T1105"]})
    assert "adds <b>1</b> further" in html_out


def test_render_gives_every_headline_stat_a_provenance_tooltip() -> None:
    """A number nobody can interrogate is decoration. Each tile explains itself."""
    html_out = render([_card("one", metrics=SCORED)], {})
    tips = html_out.count('class="stat" tabindex="0" data-tip=')
    assert tips == 6
    # Tooltip HTML is attribute-escaped, so the parser hands the markup back intact.
    assert "data-tip=\"&lt;b class=&#x27;h&#x27;&gt;Rules written in this repo" in html_out


def test_render_wires_a_tooltip_to_every_metric_on_a_card() -> None:
    html_out = render([_card("one", metrics=SCORED)], {})
    # The ids are bound when a card renders, so the template carries the wiring.
    for key in ("fp", "recall", "precision", "events", "status", "level"):
        assert "data-tipid=\"${r.stem}:" + key + '"' in html_out
    # Built in JS from the rule's own counts, not from a static string.
    assert "TIPS[r.stem + ':fp'] = fpTip(r);" in html_out
