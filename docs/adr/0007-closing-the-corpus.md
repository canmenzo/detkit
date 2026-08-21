# ADR 0007 — Closing the corpus: what this project does not do next

**Status:** accepted
**Date:** 2026-08-20

## Context

The repository set out to demonstrate detection-engineering discipline —
version control, testing, CI, measured rule quality, coverage tracking — rather
than to become a detection product. It now does that: 20 authored rules across
two evidence tiers, 131 tests, 172 labelled events scoring every rule against
per-rule thresholds that gate CI, source-bound query conversion, generated
artifacts diffed on every commit, and seven decisions on record.

Work that remained on the list falls into two groups, and the difference between
them matters more than the size of either.

## Decision

**The corpus is closed at 20 rules.** The repository is complete and moves to
maintenance: keep CI green, bump the pinned ATT&CK release and Hayabusa version
when they move, fix anything the gates catch. No new detections are planned.

Two named items are declined, for different reasons.

### 1. More Entra ID rules — declined as redundant

MFA-fatigue denials, risky sign-in over a legacy client, cross-tenant access
grants, removal from a Conditional Access exclusion: each is a rule file plus a
case set, and every gate that would run on them already exists and already runs
on four rules of exactly that shape.

They would add volume, not capability. The thing worth demonstrating about cloud
telemetry is the *argument* — that a tier with no public captures needs a
declared, weaker, separately-enforced form of proof (ADR 0005) — and that
argument is made once, not four more times. A corpus that grows by repeating a
solved pattern is measuring its own line count.

### 2. Deployment into a live SIEM — declined as out of scope, not as worthless

The remaining item with genuine value: stand up Splunk in Docker, load the
compiled searches, replay the pinned EVTX through it, capture evidence the
searches fire. It would turn "deployable" into "deployed".

It is declined because of what it would and would not prove. The conversion gate
already asserts that every rule compiles to a source-bound search — a query that
names its index and source rather than scanning everything the user can read —
and Hayabusa already asserts that the detection logic fires on the real capture.
A container replaying the same EVTX would restate both in a heavier harness.
What a live SIEM would genuinely add is behaviour under production volume and
field mapping against a real forwarder — and neither exists here, so the exercise
would produce a screenshot rather than evidence.

Better to say that plainly than to ship a container that looks like a deployment.
It stays in "Honest limits" on the how-it-works page, where a reader can weigh it,
and it is the first thing this project would do if it were a product.

## Consequences

- The repository can be read as finished rather than abandoned. A portfolio
  project with an open TODO list reads as one someone lost interest in; the same
  project with its scope boundary argued reads as one that ended on purpose.
- The standing obligations survive closure: `site/about.html` is still updated in
  the same commit as any architecture change, and the generated numbers are still
  drift-checked. Maintenance is not an exemption from the gates.
- ATT&CK is the one moving part guaranteed to break this repository eventually.
  `.attack-version` pins v19.1 and CI fails on drift, so the failure will be loud
  and its fix mechanical.
- If detection work resumes here, ADR 0006's hunting/alerting split is the
  pattern to extend — it is where the corpus has the most room, and it needs no
  new infrastructure.
