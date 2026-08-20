"""Tests for the test harness itself.

The detection suite's central claim is "every rule is verified". Nothing used to
assert that the suite actually ran: with the Hayabusa binary missing every case
skipped and pytest still exited 0, and if fixture discovery ever returned nothing
the parametrised suite collapsed to zero cases — also green.

These tests need no Hayabusa. They fail when the wiring is wrong.
"""
from __future__ import annotations

import yaml

from detkit.paths import DETECTIONS, FIXTURES
from detkit.rules import conversion_only, has_case_set, is_evtx_testable, load_corpus, rule_paths
from test_detections import CASES


def _rule_stems() -> set[str]:
    return {path.stem for path in rule_paths(DETECTIONS)}


def _declared_samples() -> dict[str, int]:
    counts = {}
    for manifest in FIXTURES.glob("*/sample_sources.yml"):
        doc = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        counts[manifest.parent.name] = len(doc.get("samples") or [])
    return counts


def test_rules_exist() -> None:
    assert _rule_stems(), "no detection rules found under detections/"


def test_collected_cases_match_declared_samples() -> None:
    """Discovery must produce exactly the cases the manifests declare."""
    declared = _declared_samples()
    expected = sum(n for stem, n in declared.items() if stem in _rule_stems())
    assert expected > 0, "fixture manifests declare zero samples"
    assert len(CASES) == expected, (
        f"collected {len(CASES)} test case(s) but manifests declare {expected} — "
        "fixture discovery is dropping cases"
    )


def _evtx_stems() -> set[str]:
    return {r.stem for r in load_corpus(DETECTIONS) if is_evtx_testable(r)}


def test_every_evtx_rule_is_tested_or_declared_exempt() -> None:
    """No Windows rule may be silently untested."""
    tested = {stem for stem, n in _declared_samples().items() if n > 0}
    untested = _evtx_stems() - tested - conversion_only()
    assert not untested, (
        f"rule(s) with no fixture and no conversion-only declaration: {sorted(untested)}"
    )


def test_every_non_evtx_rule_carries_labelled_cases() -> None:
    """Telemetry with no public capture is measured instead, never neither.

    A cloud rule cannot be replayed against a recording, so the scoring is not
    optional for it — it is the whole of its evidence, alongside the schema check
    that conversion performs. Without this test, adding a rule for a new log
    source would silently create the repo's first unverified detection.
    """
    unmeasured = {
        r.stem for r in load_corpus(DETECTIONS)
        if not is_evtx_testable(r) and not has_case_set(r.stem)
    }
    assert not unmeasured, f"non-EVTX rule(s) with no eval case set: {sorted(unmeasured)}"


def test_no_orphan_fixture_manifests() -> None:
    """A manifest whose rule was renamed or deleted silently stops running."""
    orphans = set(_declared_samples()) - _rule_stems()
    assert not orphans, f"fixture manifest(s) with no matching rule: {sorted(orphans)}"


def test_conversion_only_entries_reference_real_rules() -> None:
    stale = conversion_only() - _rule_stems()
    assert not stale, f"conversion_only.txt lists non-existent rule(s): {sorted(stale)}"
