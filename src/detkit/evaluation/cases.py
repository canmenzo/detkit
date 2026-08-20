"""Loading and validating the golden dataset.

Each rule has evals/<stem>/cases.yml holding labelled events. A benign case must
be a genuine look-alike: same event type as the true positives, differing only
where the rule's logic is supposed to discriminate. A "benign" event of an
entirely different type proves nothing, so the loader rejects it.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from detkit.paths import EVALS

MALICIOUS = "malicious"
BENIGN = "benign"
LABELS = {MALICIOUS, BENIGN}


class CaseError(Exception):
    """A case file is malformed."""


@dataclass(frozen=True)
class Case:
    name: str
    label: str
    why: str
    event: dict[str, Any]

    @property
    def is_malicious(self) -> bool:
        return self.label == MALICIOUS


@dataclass(frozen=True)
class Thresholds:
    """The bar a rule must clear. Defaults are strict; leniency must be argued."""

    min_precision: float = 0.9
    min_recall: float = 1.0
    max_fp_rate: float = 0.1
    justification: str = ""

    @property
    def is_lenient(self) -> bool:
        return (
            self.min_precision < 0.9
            or self.min_recall < 1.0
            or self.max_fp_rate > 0.1
        )


@dataclass(frozen=True)
class CaseSet:
    stem: str
    path: Path
    description: str
    cases: tuple[Case, ...]
    thresholds: Thresholds = Thresholds()

    @property
    def malicious(self) -> tuple[Case, ...]:
        return tuple(c for c in self.cases if c.is_malicious)

    @property
    def benign(self) -> tuple[Case, ...]:
        return tuple(c for c in self.cases if not c.is_malicious)

    @property
    def events(self) -> list[dict[str, Any]]:
        return [c.event for c in self.cases]


# What identifies "the same kind of event", per telemetry domain. Windows numbers
# its events; Entra ID names the operation instead. Without a domain-appropriate
# key every cloud event would compare equal (all None), and the look-alike
# guarantee below would quietly stop guaranteeing anything.
KIND_FIELDS = ("EventID", "OperationName", "Category")


def _discriminator(event: dict[str, Any]) -> Any:
    """What makes two events "the same kind of event"."""
    for field in KIND_FIELDS:
        if field in event:
            return (field, event[field])
    return None


def load_case_set(path: Path) -> CaseSet:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CaseError(f"{path}: unparseable YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise CaseError(f"{path}: not a YAML mapping")

    raw_cases = doc.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise CaseError(f"{path}: no cases")

    cases = []
    seen: set[str] = set()
    for entry in raw_cases:
        if not isinstance(entry, dict):
            raise CaseError(f"{path}: case is not a mapping")
        name = entry.get("name")
        label = entry.get("label")
        why = entry.get("why")
        event = entry.get("event")
        if not name or not isinstance(name, str):
            raise CaseError(f"{path}: case without a name")
        if name in seen:
            raise CaseError(f"{path}: duplicate case name {name!r}")
        seen.add(name)
        if label not in LABELS:
            raise CaseError(f"{path}: case {name!r} has label {label!r}, expected one of {LABELS}")
        if not why or not isinstance(why, str):
            raise CaseError(
                f"{path}: case {name!r} needs a 'why' explaining the label. "
                f"An unexplained label is an assertion, not evidence."
            )
        if not isinstance(event, dict) or not event:
            raise CaseError(f"{path}: case {name!r} has no event")
        cases.append(Case(name=name, label=label, why=why, event=event))

    case_set = CaseSet(
        stem=path.parent.name,
        path=path,
        description=str(doc.get("description", "")).strip(),
        cases=tuple(cases),
        thresholds=_thresholds(path, doc.get("thresholds")),
    )
    _validate(case_set)
    return case_set


def _thresholds(path: Path, raw: object) -> Thresholds:
    if raw is None:
        return Thresholds()
    if not isinstance(raw, dict):
        raise CaseError(f"{path}: thresholds must be a mapping")
    unknown = set(raw) - {"min_precision", "min_recall", "max_fp_rate", "justification"}
    if unknown:
        raise CaseError(f"{path}: unknown threshold key(s): {sorted(unknown)}")
    try:
        thresholds = Thresholds(
            min_precision=float(raw.get("min_precision", 0.9)),
            min_recall=float(raw.get("min_recall", 1.0)),
            max_fp_rate=float(raw.get("max_fp_rate", 0.1)),
            justification=str(raw.get("justification", "")).strip(),
        )
    except (TypeError, ValueError) as exc:
        raise CaseError(f"{path}: thresholds must be numeric: {exc}") from exc

    # Lowering the bar is allowed. Lowering it silently is not.
    if thresholds.is_lenient and not thresholds.justification:
        raise CaseError(
            f"{path}: thresholds are below the default bar "
            f"(precision >= 0.9, recall == 1.0, FP rate <= 0.1) and need a "
            f"'justification'. A weakened threshold without a stated reason is "
            f"how a gate stops meaning anything."
        )
    return thresholds


def _validate(case_set: CaseSet) -> None:
    unidentifiable = [c.name for c in case_set.cases if _discriminator(c.event) is None]
    if unidentifiable:
        raise CaseError(
            f"{case_set.path}: case(s) {unidentifiable} carry none of "
            f"{list(KIND_FIELDS)}, so the benign look-alike check cannot tell what "
            f"kind of event they are. Include the field the telemetry identifies "
            f"the event with."
        )

    if not case_set.malicious:
        raise CaseError(f"{case_set.path}: no malicious cases — recall is undefined")
    if not case_set.benign:
        raise CaseError(
            f"{case_set.path}: no benign cases — precision would be 1.0 by construction, "
            f"which is exactly the gap this harness exists to close"
        )

    # A benign case must be a look-alike, not a different kind of event.
    malicious_kinds = {_discriminator(c.event) for c in case_set.malicious}
    for case in case_set.benign:
        if _discriminator(case.event) not in malicious_kinds:
            raise CaseError(
                f"{case_set.path}: benign case {case.name!r} is "
                f"{_discriminator(case.event)!r}, which no malicious case uses. "
                f"A benign event of a different type cannot exercise the rule's logic."
            )


def load_all() -> list[CaseSet]:
    if not EVALS.exists():
        return []
    return [load_case_set(p) for p in sorted(EVALS.glob("*/cases.yml"))]
