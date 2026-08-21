# ADR 0006 — Severity follows the payload: a hunting tier and an alerting tier

**Status:** accepted
**Date:** 2026-08-20

## Context

`posh_ps_susp_encoded_powershell_scriptblock` matches obfuscation primitives in
PowerShell script-block logging (EID 4104): `FromBase64String`, `-bxor`,
`[char[`, `-join`, `[Convert]::ToInt`. It was written on the assumption that
those primitives are rare in legitimate use.

The eval harness measured the assumption and it was wrong. The rule scores an
**FP rate of 0.67**: `-join` builds file paths and CSV rows, `[Convert]::ToInt`
parses config values, and `FromBase64String` decodes certificates. Two thirds of
ordinary administrative PowerShell fires it. Its four false alarms are in the
case set by name.

Three options, and the first two are what usually happens.

1. **Delete the rule.** Obfuscation genuinely is a signal; throwing it away
   because it is noisy loses information the noisy version still carries.
2. **Tighten it until it is quiet.** Every tightening drops real Invoke-
   Obfuscation output, because the primitives *are* the technique. The rule
   would score better and detect less.
3. **Split it by what is being obfuscated.**

## Decision

Option 3, and it is the project owner's call rather than the harness's:
*severity should depend on what is obfuscated, not on obfuscation being present.*

- `posh_ps_susp_encoded_powershell_scriptblock` stays at `informational` and is
  documented as a **hunting query**. Its job is to rank script blocks for a human
  to review. An FP rate of 0.67 is a failure for an alert and unremarkable for a
  hunt, which is why the threshold is declared per rule.
- `posh_ps_obfuscated_payload_execution` is the **alerting tier**, at `high`. It
  requires an obfuscation primitive *and* an execution or ingress sink in the same
  script block: `IEX`/`Invoke-Expression`, `DownloadString`/`DownloadFile`/
  `DownloadData`, `Net.WebClient`, `Invoke-WebRequest`, `Start-BitsTransfer`, or a
  reflective assembly load. Measured **FP rate 0.11, precision 0.83**.
- **The alerting rule's benign cases are the hunting rule's false alarms.** The
  pair is gated by its own measurements: if the alerting tier ever starts firing
  on `-join` assembling a file path, CI fails.

`Start-Process` was in the first draft of the sink list and was removed:
`$list = @('/S','/qn') -join ' '; Start-Process setup.exe $list` is an ordinary
packaging idiom and it reintroduced exactly the false positives the tier exists
to exclude. It is in the case set as a benign case so the removal cannot be
quietly undone.

## Consequences

- Both rules run on the same pinned Invoke-Obfuscation capture (66 script
  blocks). The hunting tier matches most of them; the alerting tier matches the
  one that also calls `iex`. That is the intended shape, verified with
  `detkit probe`, not an authored string.
- One benign case still fires on the alerting rule and is kept: a bootstrap
  script that base64-decodes its download URL and fetches it. At script-block
  level that *is* a stager, and separating them needs script reputation or
  destination context the log does not carry. It is declared in the threshold
  justification rather than deleted to make the number look better.
- The pattern generalises. Any rule whose signal is real but whose base rate is
  hostile can be split the same way instead of being deleted or over-tightened —
  the harness already supports per-rule thresholds and per-rule severity, so the
  cost is one case set.
- It also makes the corpus honest about what a detection *is*. A repository where
  every rule is an alert is a repository that has not measured its rules.
