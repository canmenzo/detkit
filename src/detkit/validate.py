"""The metadata gate.

Hard rules, any failure breaks CI:
  1. Every rule carries the full required Sigma frontmatter, including at least
     one ATT&CK technique tag (attack.tXXXX[.XXX]).
  2. Every Windows rule has a fixture manifest under tests/fixtures/<stem>/, or
     is declared conversion-only. A rule whose telemetry has no public capture
     (Entra ID, and any future cloud tier) carries a labelled eval case set
     instead — a different evidence tier, declared rather than implied.
  3. Every attack.* tag resolves against the live ATT&CK release.
"""
from __future__ import annotations

from detkit.attack import TECHNIQUE_TAG_RE, Vocabulary, check_tags, vocabulary
from detkit.paths import DETECTIONS, REPO
from detkit.rules import (
    Rule,
    conversion_only,
    has_case_set,
    is_evtx_testable,
    load_corpus,
    sample_count,
)

REQUIRED_FIELDS = (
    "title", "id", "status", "description", "references", "author",
    "date", "modified", "tags", "logsource", "detection",
    "falsepositives", "level",
)


def has_technique_tag(tags: object) -> bool:
    return isinstance(tags, list) and any(
        isinstance(tag, str) and TECHNIQUE_TAG_RE.match(tag.strip()) for tag in tags
    )


def has_fixture(stem: str, exempt: set[str]) -> bool:
    return stem in exempt or sample_count(stem) > 0


def check_condition(detection: object) -> list[str]:
    """A folded/block YAML scalar in `condition:` is silently fatal.

    `condition: >` yields a trailing newline. pySigma and the SQL backend accept
    it; Hayabusa fails to parse the rule and reports only "Rule parsing errors: 1"
    without naming it, so the rule stops running with no obvious signal. Keep
    conditions on one line.
    """
    if not isinstance(detection, dict):
        return []
    condition = detection.get("condition")
    conditions = condition if isinstance(condition, list) else [condition]
    return [
        f"condition is not a single-line scalar (avoid '>' and '|'): {c!r}"
        for c in conditions
        if isinstance(c, str) and (c != c.strip() or "\n" in c)
    ]


def validate_rule(rule: Rule, vocab: Vocabulary, exempt: set[str]) -> list[str]:
    errors: list[str] = []
    errors.extend(check_condition(rule.doc.get("detection")))

    for field in REQUIRED_FIELDS:
        if field not in rule.doc or rule.doc[field] in (None, "", []):
            errors.append(f"missing required field: {field}")

    tags = rule.doc.get("tags")
    if not has_technique_tag(tags):
        errors.append("no ATT&CK technique tag (need at least one attack.tXXXX)")
    errors.extend(check_tags(tags, vocab))

    errors.extend(check_evidence(rule, exempt))
    return errors


def check_evidence(rule: Rule, exempt: set[str]) -> list[str]:
    """Every rule must carry the evidence its telemetry can actually produce."""
    if not is_evtx_testable(rule):
        # No public capture of this telemetry exists, so the EVTX gate cannot
        # apply. What can apply is the scoring, and it is mandatory here rather
        # than optional: without it the rule would carry no measurement at all.
        problems = []
        if not has_case_set(rule.stem):
            problems.append(
                f"no labelled eval cases: {rule.stem} is not EVTX-testable "
                f"(logsource product is not windows), so evals/{rule.stem}/cases.yml "
                f"is required — an untested and unmeasured rule is not shippable"
            )
        if rule.stem in exempt:
            problems.append(
                f"'{rule.stem}' is listed in tests/conversion_only.txt, which "
                f"declares an exemption from the EVTX gate. That gate does not "
                f"apply to this rule in the first place; remove the entry"
            )
        return problems

    if not has_fixture(rule.stem, exempt):
        return [
            f"no test fixture: add tests/fixtures/{rule.stem}/sample_sources.yml "
            f"with >=1 pinned sample, or list '{rule.stem}' in tests/conversion_only.txt"
        ]
    return []


def run() -> int:
    rules = load_corpus(DETECTIONS)
    if not rules:
        print("no detection rules found under detections/")
        return 1

    vocab = vocabulary()
    exempt = conversion_only()
    print(
        f"ATT&CK {vocab.version} resolved (last reviewed against {vocab.reviewed}) — "
        f"{len(vocab.techniques)} techniques, {len(vocab.tactics)} tactics\n"
    )

    failed = 0
    for rule in rules:
        errors = validate_rule(rule, vocab, exempt)
        rel = rule.path.relative_to(REPO)
        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for error in errors:
                print(f"     - {error}")
        else:
            print(f"OK   {rel}")

    print(f"\n{len(rules)} rule(s), {failed} failing.")
    return 1 if failed else 0
