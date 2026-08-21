"""Inspect a rule against the evidence its telemetry can actually produce.

This is the loop every discriminator in this repo was written against: parse the
real sample, see which events the rule matches, and read the fields of the ones
it does not. Writing a rule against imagined telemetry is how you end up with a
rule that passes your own tests and misses the actual attack.

    detkit probe security_win_service_installed
    detkit probe security_win_service_installed --show ServiceFileName

Which evidence depends on the rule's tier (see ADR 0005). A Windows rule is
probed against its pinned public EVTX. A cloud rule has no public capture to
probe, so it is probed against its labelled case set instead — same compiled
query, same matcher, different events, and the verdict is scored against each
case's label rather than a manifest's `expect`.

    detkit probe entra_signin_legacy_auth_success
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from detkit.evaluation.cases import MALICIOUS, load_case_set
from detkit.evaluation.engine import compile_rule, matching_indices
from detkit.paths import DETECTIONS, EVALS
from detkit.rules import is_evtx_testable, load_rule, rule_paths
from detkit.samples import SampleError, event_id_counts, fetch, manifest, read_events

# Fields worth showing by default when a rule matches, across the log sources in
# this corpus.
INTERESTING = (
    "EventID", "Channel", "Computer",
    "Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine",
    "NewProcessName", "ParentProcessName",
    "ServiceName", "ServiceFileName", "TaskName",
    "TargetImage", "GrantedAccess", "SourceImage",
    "ScriptBlockText",
    "TargetUserName", "SubjectUserName", "TargetSid", "Properties",
    "TicketEncryptionType", "PreAuthType", "Status", "ServiceName",
    # Entra ID: sign-in and audit logs name the operation instead of numbering it.
    "OperationName", "Category", "Result", "ResultType", "ClientAppUsed",
    "AppDisplayName", "UserPrincipalName", "IPAddress", "InitiatedBy",
    "TargetResources", "IsInteractive",
)


def _summarise(event: dict[str, Any], fields: tuple[str, ...], width: int) -> list[str]:
    lines = []
    for field in fields:
        value = event.get(field)
        if value in (None, ""):
            continue
        text = str(value).replace("\r", " ").replace("\n", " ")
        if len(text) > width:
            text = text[: width - 1] + "…"
        lines.append(f"      {field}: {text}")
    return lines


def probe_cases(stem: str, rule_path: Path, show: tuple[str, ...], width: int) -> int:
    """Probe a rule with no public capture against its labelled case set.

    The EVTX path answers "does it fire on the real attack"; there is no real
    capture here, so this answers the question the cloud tier can answer: does
    the rule agree with the labels a human wrote, and which case disagrees.
    """
    path = EVALS / stem / "cases.yml"
    if not path.is_file():
        print(f"{stem}: no labelled cases (evals/{stem}/cases.yml)")
        return 1

    case_set = load_case_set(path)
    query, referenced = compile_rule(rule_path)
    fields = show or INTERESTING
    print(f"rule : {rule_path.name}")
    print("tier : labelled cases — no public capture of this telemetry exists "
          "(ADR 0005)")
    print(f"sql  : {query}\n")

    matched = matching_indices(query, referenced, case_set.events)
    disagreements = 0
    for index, case in enumerate(case_set.cases):
        fired = index in matched
        verdict = {
            (True, True): "TP", (False, False): "TN",
            (True, False): "FP", (False, True): "FN",
        }[(fired, case.label == MALICIOUS)]
        if verdict in ("FP", "FN"):
            disagreements += 1
        print(f"[{case.name}] label={case.label} got={'fire' if fired else 'silent'} "
              f"({verdict})")
        print(f"    why: {case.why.strip().splitlines()[0]}")
        if verdict in ("FP", "FN") or fired:
            print("\n".join(_summarise(case.event, fields, width)))
        print()

    print(f"{len(case_set.cases)} case(s), {disagreements} disagreeing with their label.")
    # Disagreement is not failure here: several rules carry declared false
    # positives with a written justification. `detkit eval` owns that gate.
    return 0


def run(stem: str, show: tuple[str, ...] = (), limit: int = 3, width: int = 160) -> int:
    rules = {path.stem: path for path in rule_paths(DETECTIONS)}
    if stem not in rules:
        print(f"no rule named {stem!r}. Known rules:")
        for name in sorted(rules):
            print(f"  {name}")
        return 1

    if not is_evtx_testable(load_rule(rules[stem])):
        return probe_cases(stem, rules[stem], show, width)

    samples = manifest(stem)
    if not samples:
        print(f"{stem}: no pinned samples (tests/fixtures/{stem}/sample_sources.yml)")
        return 1

    query, referenced = compile_rule(rules[stem])
    fields = show or INTERESTING
    print(f"rule : {rules[stem].name}")
    print(f"sql  : {query}\n")

    failures = 0
    for sample in samples:
        name = sample.get("name", "?")
        expect = sample.get("expect", "?")
        try:
            evtx = fetch(sample)
        except SampleError as exc:
            print(f"[{name}] could not fetch: {exc}")
            failures += 1
            continue

        events = read_events(evtx)
        matched = matching_indices(query, referenced, events)
        verdict = "fire" if matched else "silent"
        agrees = "ok" if verdict == expect else "MISMATCH"

        print(f"[{name}] expect={expect} got={verdict} ({agrees})")
        print(f"    {len(events)} events, EventIDs: "
              f"{dict(event_id_counts(events).most_common(8))}")

        if matched:
            for index in sorted(matched)[:limit]:
                print(f"    -- match #{index}")
                print("\n".join(_summarise(events[index], fields, width)))
        elif expect == "fire":
            # The interesting case: it should have matched and did not. Show what
            # the rule was looking at so the mismatch is diagnosable.
            failures += 1
            candidates = [e for e in events if any(e.get(f) for f in referenced)]
            print(f"    no match. {len(candidates)} event(s) carry a referenced field:")
            for event in candidates[:limit]:
                print("\n".join(_summarise(event, fields, width)))
        print()

    return 1 if failures else 0
