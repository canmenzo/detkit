"""Loading the Sigma corpus.

Unparseable YAML raises. The generators used to swallow it and continue, so a
malformed rule vanished from the coverage map, the Navigator layer and the
dashboard with no signal at all.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from detkit.attack import Tags, parse_tags
from detkit.paths import CONVERSION_ONLY, EVALS, FIXTURES


class RuleError(Exception):
    """A rule file could not be read as a Sigma rule."""


@dataclass(frozen=True)
class Rule:
    path: Path
    stem: str
    doc: dict[str, Any]
    tags: Tags

    @property
    def techniques(self) -> tuple[str, ...]:
        return self.tags.techniques

    @property
    def tactics(self) -> tuple[str, ...]:
        return self.tags.tactics


def load_rule(path: Path) -> Rule:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: unparseable YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise RuleError(f"{path}: not a YAML mapping")
    return Rule(path=path, stem=path.stem, doc=doc, tags=parse_tags(doc.get("tags")))


def rule_paths(root: Path) -> list[Path]:
    """Rule files under a corpus root, in the repo's established order."""
    return sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))


def load_corpus(root: Path) -> list[Rule]:
    return [load_rule(path) for path in rule_paths(root)]


# EVTX exists for Windows telemetry and nothing else. A cloud rule cannot be
# proven against a captured event log because no public capture of Entra ID
# sign-in data exists to capture — so those rules carry a different, declared
# evidence tier (see docs/adr/0005). Keeping the distinction in one predicate
# stops it being re-derived, differently, in each gate.
EVTX_TESTABLE_PRODUCTS = {"windows"}


def is_evtx_testable(rule: Rule) -> bool:
    logsource = rule.doc.get("logsource") or {}
    return logsource.get("product") in EVTX_TESTABLE_PRODUCTS


def has_case_set(stem: str) -> bool:
    """Whether a rule has a labelled eval case set."""
    return (EVALS / stem / "cases.yml").is_file()


def conversion_only() -> set[str]:
    """Rule stems explicitly exempt from EVTX testing."""
    if not CONVERSION_ONLY.exists():
        return set()
    stems = set()
    for line in CONVERSION_ONLY.read_text(encoding="utf-8").splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            stems.add(stripped)
    return stems


def sample_count(stem: str) -> int:
    """Number of pinned samples declared for a rule."""
    manifest = FIXTURES / stem / "sample_sources.yml"
    if not manifest.is_file():
        return 0
    try:
        doc = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RuleError(f"{manifest}: unparseable YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise RuleError(f"{manifest}: not a YAML mapping")
    samples = doc.get("samples") or []
    return len(samples) if isinstance(samples, list) else 0
