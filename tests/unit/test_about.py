"""Unit tests for the how-it-works page.

The page is generated so it cannot drift from the corpus. These cover the parts
that are derived rather than written: the threshold table, the gate list, and
the worked example.
"""
from __future__ import annotations

from typing import Any

from detkit.about import _gate_rows, _threshold_rows, _worked_example, render
from detkit.pipeline import DRIFT_PATHS, STEPS

RESULTS: dict[str, Any] = {
    "rule_clean": {
        "tp": 4, "fp": 0, "fn": 0, "tn": 4,
        "precision": 1.0, "recall": 1.0, "fp_rate": 0.0,
        "thresholds": {"min_precision": 0.9, "min_recall": 1.0, "max_fp_rate": 0.1},
    },
    "rule_noisy": {
        "tp": 3, "fp": 5, "fn": 0, "tn": 0,
        "precision": 0.38, "recall": 1.0, "fp_rate": 1.0,
        "thresholds": {"min_precision": 0.35, "min_recall": 1.0, "max_fp_rate": 1.0},
    },
}


def _data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "rules": [], "results": RESULTS,
        "justifications": {"rule_noisy": "the base rate carries this one"},
        "lenient": {"rule_noisy"}, "techniques": ["T1059.001"], "tactics": ["Execution"],
        "n_tested": 1, "n_samples": 2, "n_exempt": 0, "n_cases": 16,
        "vend_rules": 2399, "vend_rate": 1.0, "vend_tech": 290,
    }
    data.update(overrides)
    return data


def test_threshold_rows_flag_the_rule_that_alerts_on_everything() -> None:
    html_out = _threshold_rows(RESULTS, {})
    assert "<td class='num bad'>1.00</td>" in html_out
    assert "<td class='num'>0.00</td>" in html_out


def test_threshold_rows_publish_the_justification_for_a_lowered_bar() -> None:
    html_out = _threshold_rows(RESULTS, {"rule_noisy": "the base rate carries this one"})
    assert "the base rate carries this one" in html_out
    # A rule on the default bar has nothing to justify, so it gets no second row.
    assert html_out.count("Why the bar is where it is") == 1


def test_every_ci_gate_appears_including_the_drift_check() -> None:
    """A gate added to the pipeline cannot silently vanish from the page."""
    html_out = _gate_rows()
    for label, _ in STEPS:
        assert f"<code>{label}</code>" in html_out
    assert "artifact drift" in html_out
    for path in DRIFT_PATHS:
        assert path in html_out


def test_worked_example_prefers_a_rule_with_real_false_alarms() -> None:
    stem, _ = _worked_example(RESULTS)
    assert stem == "rule_noisy"  # rule_clean's arithmetic is all zeros


def test_render_shows_the_arithmetic_and_the_measured_state() -> None:
    html_out = render(_data())
    assert "3 &divide; (3 + 5) = 0.38" in html_out          # precision, worked through
    assert "of 2 rules currently run on a justified lenient threshold" in html_out
    assert "16 events hand-written and labelled" in html_out
    assert "2,399 rules, 100% convert rate" in html_out


def test_render_survives_an_unscored_corpus() -> None:
    """The page still renders before `detkit eval` has ever run."""
    html_out = render(_data(results={}, lenient=set(), justifications={}, n_cases=0))
    assert "Worked example" not in html_out
    assert "How it works" in html_out
