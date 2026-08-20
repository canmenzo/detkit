# ADR 0003 — Evaluate rules over labelled JSON events with the pySigma SQLite backend

**Status:** accepted
**Date:** 2026-08-14

## Context

Detection quality was unmeasured. Tests asserted only "fires on an attack sample"
and "silent on a benign one", 14 of 15 rules had no benign counter-example, and
the single negative case used a different event channel — so it proved nothing
about the rule's discrimination.

Measuring precision, recall and FP rate needs many labelled events per rule,
including benign look-alikes that differ from the true positive only where the
rule's logic should bite. Hayabusa cannot supply that: it consumes EVTX only
(`-J` JSON input does not apply Sigma `process_creation`/`ps_script` matching —
see ADR 0002), and no public EVTX corpus contains curated benign look-alikes for
these behaviours. Authoring EVTX by hand is not practical.

Three options were considered for a second evaluator that consumes JSON:

1. **Zircolite** — runs Sigma against JSONL. Not on PyPI; it is distributed as a
   GitHub repository plus release binaries, so it cannot be locked in `uv.lock`
   and would reintroduce the "download a binary from a release page" problem that
   already makes the Hayabusa step the most fragile part of CI.
2. **A hand-written matcher** over pySigma's parsed rule objects. Full control,
   but ~300 lines of security-critical matching logic that we would own, test and
   keep in step with pySigma's modifier semantics.
3. **`pysigma-backend-sqlite`** — a maintained pySigma backend that renders a
   rule to SQL. Load labelled events into an in-memory SQLite table, run the SQL,
   count matching rows. This is what Zircolite does internally, without the tool.

## Decision

Option 3. Rules are converted with the SQLite backend and evaluated against
labelled JSON events loaded into an in-memory table.

Hayabusa is kept as an independent second engine over real EVTX. The two engines
must agree; disagreement fails the build. Two independent implementations of
Sigma semantics checking each other is worth more than either alone.

### Validation

The approach was proven before anything was built. All 15 authored rules convert
to SQL. Every existing fixture sample was dumped to JSON with `evtx_dump`,
flattened, loaded into SQLite, and evaluated — then compared against Hayabusa on
the same file:

**15 of 15 cases agree, on the exact hit count, not merely the verdict.**

### Consequences and the semantics this pinned down

Three behaviours had to be defined explicitly, and each is a real decision:

- **A field absent from the data must not match, not raise.** Every field a rule
  references is materialised as a NULL column. Note that SQL three-valued logic
  means a negated condition over an absent field is also false, which differs
  from Sigma, where an unsatisfiable filter under `not` is true. No current rule
  depends on that case; when one does, it needs an explicit test.
- **Numeric strings are coerced on load.** EVTX `EventData` values are strings in
  the XML, so `PreAuthType` arrives as `"0"` while the rule (and SigmaHQ's own
  `win_security_kerberos_asrep_roasting.yml`) says `PreAuthType: 0`. Hayabusa
  compares loosely and matches; SQLite does not. Without coercion the AS-REP rule
  silently stops matching — 14/15 agreement instead of 15/15.

  This makes the evaluator as lenient as Hayabusa, and **more lenient than a
  strictly-typed backend**. A KQL query comparing an integer literal against a
  string column would miss this detection in production. Precision measured here
  is precision under loose typing; it is not a claim about a strict SIEM.
- **UInt64 keyword masks overflow SQLite's INTEGER** and are stored as text.

## Alternatives not taken

Writing our own matcher (option 2) remains viable if the SQLite backend is
abandoned upstream. The cost of switching is bounded: the harness depends on
"rule in, matching row IDs out", not on SQL.

## Amendment, 2026-08-20 — comparison is text-based in both directions

The original implementation coerced numeric-looking strings in the event data to
integers, so that EVTX's string-typed `PreAuthType: "0"` matched a rule written
`PreAuthType: 0`. Adding Entra ID rules showed that this leniency only worked one
way: `SigninLogs.ResultType` is a string column, so the rule is correctly written
`ResultType: '0'` — and the coercion turned the event's `"0"` into an integer,
which no longer matched. The evaluator disagreed with the platform the query
compiles to, in the direction that hides a working rule.

Every value is now stored as text in columns declared `TEXT`, which makes SQLite
apply text affinity to the rule's literal before comparing. Both directions match,
the UInt64 keyword-mask special case disappears, and the leniency is symmetric and
stated rather than incidental. All 15 Windows rules produced identical metrics
before and after the change.

One consequence to know about: numeric comparison modifiers (`|gt`, `|lt`, `|gte`,
`|lte`) would compare as text under this scheme. No rule in the corpus uses one.
A rule that needs one needs a typed column, and that needs a decision here first.
