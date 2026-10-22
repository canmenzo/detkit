"""Unit tests for ATT&CK tag parsing and vocabulary checks."""
from __future__ import annotations

import pytest

from detkit.attack import (
    TACTIC_BY_NAME,
    TACTICS,
    AttackDriftError,
    Vocabulary,
    check_tags,
    norm_tactic,
    parse_tags,
    vocabulary,
)
from detkit.paths import ATTACK_VERSION_FILE

VOCAB = Vocabulary(
    version="20.0",
    reviewed="20.0",
    techniques=frozenset({"T1059.001", "T1027", "T1685", "T1685.005"}),
    tactics=frozenset({"execution", "stealth", "defense-impairment", "credential-access"}),
)


def test_parses_hyphenated_tactics() -> None:
    """Regression: a [a-z_]+ pattern silently dropped every multi-word tactic."""
    tags = parse_tags(["attack.credential-access", "attack.command-and-control"])
    assert tags.tactics == ("credential-access", "command-and-control")


def test_normalises_underscored_tactics() -> None:
    assert parse_tags(["attack.credential_access"]).tactics == ("credential-access",)


def test_folds_retired_defense_evasion_into_stealth() -> None:
    assert norm_tactic("defense-evasion") == "stealth"
    assert norm_tactic("defense_evasion") == "stealth"
    assert parse_tags(["attack.defense_evasion"]).tactics == ("stealth",)


def test_uppercases_technique_ids() -> None:
    tags = parse_tags(["attack.t1059.001", "attack.T1027"])
    assert tags.techniques == ("T1059.001", "T1027")


def test_ignores_non_attack_and_malformed_tags() -> None:
    tags = parse_tags(["cve.2021-44228", "attack.", 42, None, "detection.threat-hunting"])
    assert tags.techniques == ()
    # "detection.threat-hunting" is not an attack.* tag; "attack." matches no token
    assert tags.tactics == ()


def test_parse_tags_tolerates_non_list() -> None:
    assert parse_tags(None).techniques == ()
    assert parse_tags("attack.execution").tactics == ()


def test_check_tags_accepts_known_tags() -> None:
    assert check_tags(["attack.execution", "attack.t1059.001"], VOCAB) == []


def test_check_tags_rejects_retired_technique() -> None:
    errors = check_tags(["attack.t1562.001"], VOCAB)
    assert len(errors) == 1
    assert "unknown ATT&CK technique" in errors[0]


def test_check_tags_rejects_underscored_tactic() -> None:
    errors = check_tags(["attack.credential_access"], VOCAB)
    assert len(errors) == 1
    assert "hyphenated" in errors[0]


def test_tactic_table_is_consistent() -> None:
    assert len(TACTIC_BY_NAME) == len(TACTICS)
    assert "stealth" in TACTIC_BY_NAME
    assert "defense-impairment" in TACTIC_BY_NAME
    # The retired token must not be a column of its own.
    assert "defense-evasion" not in TACTIC_BY_NAME


def test_vocabulary_matches_the_repo_pin() -> None:
    vocab = vocabulary()
    assert vocab.version.split(".")[0] == vocab.reviewed.split(".")[0]
    assert "T1059.001" in vocab.techniques
    assert "credential-access" in vocab.tactics


def test_vocabulary_raises_on_major_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    pinned_major = int(ATTACK_VERSION_FILE.read_text(encoding="utf-8").split(".")[0])
    monkeypatch.setattr("sigma.data.mitre_attack.mitre_attack_version", f"{pinned_major + 1}.0")
    with pytest.raises(AttackDriftError, match="major version drift"):
        vocabulary()
