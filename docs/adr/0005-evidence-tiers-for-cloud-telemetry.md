# ADR 0005 — Evidence tiers: how a cloud rule is proven when no capture exists

**Status:** accepted
**Date:** 2026-08-20

## Context

The corpus was Windows-only, and every rule carried the same proof: replay a
pinned public EVTX capture of the real attack through Hayabusa and require a hit.
Adding Entra ID (Azure AD) rules breaks that, because the proof depends on
something that does not exist for cloud identity telemetry.

There is no public equivalent of `hayabusa-sample-evtx` for Entra ID. Sign-in and
audit logs are tenant data: they carry user principal names, IP addresses and
device identifiers for real people, so nobody publishes captures of an attack
against a real tenant. Searching for one is not a research gap to close, it is a
privacy property of the data.

That leaves three options.

1. **Don't write cloud rules.** Keeps one uniform proof, at the cost of a corpus
   that stops where most current attacks start. Identity is where the intrusions
   are; a detection portfolio that cannot say anything about it is dated.
2. **Write them and quietly let the fixture gate not apply.** This is what most
   repositories do. It also silently converts "every rule here is proven against
   real telemetry" into "every rule here that happens to be Windows is", with
   nothing on the page saying which is which.
3. **Declare a second evidence tier, and enforce what that tier can actually
   prove.**

## Decision

Option 3. A rule's evidence tier follows from its `logsource.product`, and each
tier is enforced separately.

**Windows tier** — a pinned public EVTX capture replayed through Hayabusa, plus
labelled-event scoring. Unchanged.

**Cloud tier** (Entra ID today, anything without public captures later):

- **Labelled-event scoring is mandatory, not optional.** For a Windows rule the
  case set is the second of two proofs; here it is the first of two, so
  `detkit validate` fails a non-EVTX rule that has no `evals/<stem>/cases.yml`.
  `tests/test_harness_integrity.py` asserts the same thing independently, because
  a gate with one implementation is a gate with one bug away from nothing.
- **Every field is checked against the platform's published schema at compile
  time.** `detkit convert` compiles the Entra rules through
  `pipelines/azure_monitor_entra.yml` + the vendor `azure_monitor` pipeline,
  which binds each rule to its real Log Analytics table (`SigninLogs`,
  `AuditLogs`) and then validates every referenced column against Microsoft's
  published schema for that table. A rule naming a column that does not exist
  does not compile. Conversion is also checked to have produced a table-bound
  query, the same way Splunk output is checked for a `source=`.

This is deliberately weaker than the Windows tier, and the difference is stated
everywhere the rules appear: the dashboard badges those rules `schema-verified`
rather than `tested`, the hover tooltip says what that does and does not prove,
and the how-it-works page carries the same distinction.

## Consequences

- The claim the repository makes stays true, and stays specific. "Proven against
  a real capture" continues to mean exactly that, for exactly the rules where it
  is true.
- What the cloud tier does *not* prove is written down: nothing here shows an
  Entra rule firing on a real tenant's data, only that its logic discriminates
  between labelled malicious and benign events, and that the query would run.
- The schema check turned out to be a real gate rather than a formality. It
  catches the most common cloud-rule error — inventing a column name from the
  Graph API shape rather than the Log Analytics one — at build time, which the
  EVTX tier catches only if a sample happens to exercise that field.
- It also exposed a bug in the evaluator. `ResultType` is a **string** column in
  `SigninLogs`, so the rule is correctly written `ResultType: '0'`; the evaluator
  coerced numeric-looking strings in the *data* to integers, so a correctly typed
  rule stopped matching its own labelled events while Sentinel would have matched
  them. One-sided leniency disagrees with the platform the query is destined for.
  The evaluator now stores every value as text against TEXT columns, so SQLite
  applies text affinity to the rule's literal and the comparison is loose in both
  directions. All 15 Windows rules produce byte-identical metrics under the new
  semantics; see ADR 0003.
- Adding a further cloud source (AWS CloudTrail, Okta) is now a pipeline plus a
  case-set requirement, not a new argument about what counts as proof.
