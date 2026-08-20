# Detection-as-Code — Project Memory

## What this is
Automated tests for threat-detection rules. Every Sigma detection ships with EVTX
test fixtures proving it (a) fires on the malicious behavior and (b) stays silent
on benign activity. CI re-runs everything on every commit and auto-generates a
MITRE ATT&CK coverage map. Demonstrates detection *engineering discipline* —
version control, testing, CI/CD, coverage tracking.

Python lives in `src/detkit/` (installed package, `detkit` CLI) plus the pytest
layer. "Does this rule fire" testing is done by **Hayabusa** (Rust, runs Sigma
against EVTX), driven by pytest.

## Repo structure
- `detections/` — AUTHORED Sigma rules (the showcase); held to the fixture gate
- `vendored/` — pinned third-party SigmaHQ Windows corpus (~2,400, DRL 1.1); NOT
  gated — fed through convert + coverage only. `vendored_report.py` → `report.json`
- `tests/` — pytest; `unit/` covers detkit, `harness.py` drives Hayabusa,
  `fixtures/<rule_stem>/` holds the pinned sample manifests
- `pipelines/` — pySigma processing pipelines (field maps for Splunk + Sentinel/Kusto)
- `src/detkit/` — the tooling package. `attack` (tag parsing + vocabulary),
  `rules` (corpus loading), `validate`, `coverage`, `navigator`, `dashboard`,
  `about` (the How-it-works page), `webui` (shared page chrome + tooltips),
  `vendored`, `cli`
- `coverage/` — committed Navigator layer JSON + screenshot
- `docs/` — detection lifecycle + ADRs
- `.github/workflows/ci.yml` — lint → (convert, test, vendored) → coverage

## Conventions
- **Required metadata on every rule:** title, id (UUID), status, description,
  references, author, date, modified, tags (≥1 `attack.tXXXX`), logsource,
  detection, falsepositives, level.
- **The enforced rule:** every rule must have ≥1 ATT&CK tag AND ≥1 test fixture,
  or CI fails. `validate_metadata.py` enforces this.
- **Naming:** `<logsource>_<platform>_<short_description>.yml`, mirroring Sigma-HQ.

## ATT&CK is a moving target — this bit matters
pySigma resolves ATT&CK from MITRE's **live** STIX feed (cached in
`~/.cache/pysigma/`), so the tag vocabulary changes with no commit here.
`.attack-version` pins the release we validated against (**19.1**);
`validate_metadata.py` fails if pySigma resolves anything else, and checks every
`attack.*` tag against it. To bump: update the file, re-run the gate, fix what
the new release retired.

v19.1 specifics that bit us: tactic shortnames are **hyphenated**
(`attack.credential-access`); TA0005 Defense Evasion is now **`stealth`** and
**`defense-impairment`** (TA0112) split out of it; **T1562 no longer exists**
(→ T1685 Disable or Modify Tools, T1686 Disable or Modify System Firewall);
T1070.001 Clear Windows Event Logs → **T1685.005**.

## Tooling
pySigma + sigma-cli (convert/check), pySigma backends (splunk, kusto), Hayabusa
(EVTX testing), pytest, yamllint, ruff, mypy --strict. Dependencies are locked
in `uv.lock`; `uv sync --all-extras` reproduces CI exactly. Commands are `uv run
detkit <validate|vendored|navigator|coverage|dashboard>`. Hayabusa's version is
pinned in `.hayabusa-version` and read by CI — bump it there, nowhere else.

**Do not run `uv sync` against the repo's existing pip-managed `.venv`** without
meaning to; set `UV_PROJECT_ENVIRONMENT` to a scratch path to test the lock.

## Status
15 authored detections. **119 tests.** Every rule is scored against labelled
events (122 of them) for precision/recall/FP rate, with per-rule thresholds that
gate CI. `sigma check --fail-on-issues` passes at **0 issues**. All 15 rules
convert to source-bound Splunk searches; the process_creation subset also
converts to Microsoft XDR KQL. Coverage: 16 authored techniques (headline) plus
290 vendored-only, across 15 tactics.

**One command:** `uv sync --all-extras && uv run detkit ci` — installs the pinned
Hayabusa, runs every gate in CI's order, ~20s.

### Production-grade engagement (6 phases, agreed 2026-08-14)
All six phases are ✅ done: honest gates → Python foundation → eval harness →
rule quality + CI gating → reproducible setup → README/dashboard.

**Remaining follow-ups (none blocking):**
- Branch protection is not enabled (see below) — awaiting Can's call.
- `posh_ps_susp_encoded_powershell_scriptblock` was demoted to `informational`
  on my initiative; Can has not confirmed or vetoed.

**Rule-authoring loop:** `detkit probe <rule_stem>` fetches the pinned EVTX,
runs the rule's compiled SQL against it, and prints matches — or, when a rule
that should fire does not, the fields of events carrying the referenced fields.
Use it **before** finalising rule logic. It replaced a scratchpad script plus a
hand-downloaded evtx_dump; the `evtx` PyPI package is the same Rust parser and
locks like any other dependency, so don't reintroduce the binary.

## The site has two pages, and one of them is a standing obligation
`detkit dashboard` writes **both** `site/index.html` (the coverage dashboard) and
`site/about.html` (**"How it works"** — `src/detkit/about.py`). Both are
drift-checked in CI.

- **`site/about.html` must be updated in the same commit as any architecture
  change.** New gate, new generator, different engine, changed metric, new ADR,
  new limitation — it goes on that page. Can uses it to explain the project to
  other people and to prepare for interviews, so a page describing a system that
  no longer exists is worse than no page. Everything derivable from the corpus
  (rule counts, the threshold table with justifications, the CI step list from
  `pipeline.STEPS`, the ADR titles) is **generated**; the prose sections and
  `GATE_PROSE` / `ADR_SUMMARY` are the parts a human has to touch.
- **Every published number carries a hover tooltip** explaining its formula with
  that rule's own counts, where the data came from, and the CI gate it must
  clear. 600 ms delay, also on keyboard focus and tap. Shared chrome lives in
  `src/detkit/webui.py` (`PALETTE`, `TIP_CSS`, `TIP_JS`, `nav()`); tooltip content
  resolves from `data-tip` (literal HTML, escape it with `tip_attr`) or
  `data-tipid` (a key into the page's `TIPS` map — used for JS-rendered cards, so
  per-rule arithmetic never round-trips through attribute escaping).
- A new metric on a card needs a tooltip, or it should not ship. The point of the
  page is that no number is unexplained.
- **No accuracy metric anywhere, on purpose.** `(TP+TN)/total` is dominated by
  the authored malicious:benign ratio. Both the tooltip and the about page say so
  explicitly — don't "helpfully" add it.

## Phase 1 hardening — what changed and why
- **The suite could not fail.** No Hayabusa → all tests skipped → `pytest` exit 0.
  CI now sets `DETKIT_REQUIRE_HAYABUSA=1`: missing engine, bogus `HAYABUSA_BIN`,
  or *any* skip fails the run. `tests/test_harness_integrity.py` (no engine
  needed) asserts collected cases == declared samples, and catches orphan
  manifests / stale `conversion_only.txt` entries.
- **Defender quarantines Hayabusa's JSON output.** `count_hits` wrote `out.json`
  to a temp dir and never read it; the file contains the sample's attacker
  artifacts verbatim, so AV signature-matches it (4 detections in one session).
  Output now goes to `os.devnull` — nothing on disk. **Do not reintroduce a
  file-backed `-o`**; `json-timeline` requires the flag but `NUL`/`/dev/null`
  works and the summary still prints to stdout.
- **Generators failed silently.** All four swallowed `yaml.YAMLError`; they now
  exit non-zero. `vendored_report.py` and `generate_dashboard.py` matched tactic
  tags with `[a-z_]+`, silently dropping every hyphenated (multi-word) tactic —
  the report claimed 8 of 15.
- **Committed artifacts can no longer drift.** Generator output is a pure
  function of the corpus (no timestamps); CI regenerates and `git diff
  --exit-code`s `navigator_layer.json`, `vendored/report.json`, `site/index.html`.
  PNGs excluded — matplotlib is not byte-stable across versions.
- `sigma check` is down from 20 issues to 2 (both `SpecificInsteadOfGeneric
  Logsource`, deferred to Phase 4) and is **still advisory** — `--fail-on-issues`
  goes on when the count is zero, not before. README says so out loud.
- LICENSE added (MIT for authored content; `vendored/` stays DRL 1.1).

## Phase 2 — Python foundation
- `tools/*.py` and `requirements.txt` are **gone**. Logic moved to `src/detkit/`
  behind the `detkit` CLI; deps live in `pyproject.toml` + `uv.lock`.
- The shared `attack` module exists because the same regex and alias table were
  copy-pasted into four generators, drifted, and two copies used `[a-z_]+` for
  tactic tags — which cannot match a hyphen. Don't re-inline that logic.
- **ruff + mypy --strict are green over 18 files and gate CI.** Two carve-outs,
  both deliberate: `E501` is ignored in `dashboard.py` (wrapping its embedded
  HTML/JS template would change the generated bytes), and `no_implicit_reexport`
  is off for `sigma.*`/`matplotlib.*` (they re-export through `__init__`).
- Tests: 60 total = 15 detection + 5 harness-integrity + 40 unit. Unit tests
  cover the arithmetic behind every published number. `tests/harness.py` holds
  the Hayabusa plumbing so nothing imports `conftest` any more.
- The refactor was verified by regenerating every artifact: `navigator_layer.json`,
  `vendored/report.json` and `coverage.png` came out **byte-identical**; the only
  diff was one dashboard footer line naming the new command.

## Phase 3 — eval harness
- `evals/<stem>/cases.yml` holds labelled events; `detkit eval` scores every rule and
  writes `evals/results.json` (drift-checked in CI like the other artifacts).
- Engine = pySigma's **SQLite backend**, rules rendered to SQL and run over an
  in-memory table. ADR 0003 has the reasoning and the 15/15 cross-check against
  Hayabusa on real EVTX. **Zircolite was rejected: not on PyPI, so unlockable.**
- Three semantics are load-bearing and tested: absent fields materialise as NULL
  columns (must not raise); numeric strings are coerced on load (without it the
  AS-REP rule silently stops matching); UInt64 keyword masks are stored as text.
- The case loader **rejects** a benign case whose EventID no malicious case uses
  — the old fixture set's only negative was a different channel and proved
  nothing. It also rejects a missing `why`, and any set lacking either label.
- **Read FP rate, not precision.** Precision moves with the authored
  malicious:benign ratio; FP rate and recall do not.
- Findings: 4 bare-EventID rules sat at **FP rate 1.00**; the 4104 obfuscation
  rule is at 0.67 (it fires on `-join`); `proc_creation_win_encoded_powershell`
  has a **real recall gap** — `powershell -e` is a valid abbreviation the rule
  does not cover. All are recorded in the case sets, not hidden.

## Phase 4 — rule quality and gating
- **NEVER use a folded/block scalar (`>` or `|`) for a Sigma `condition:`.**
  Hayabusa fails to parse the rule and reports only "Rule parsing errors: 1"
  without naming it, so the rule silently stops running — while `sigma check` and
  the SQL backend both accept it. `detkit validate` now rejects this.
- 4697/4698 gained discriminators (interpreter/LOLBIN, user-writable path, and
  for 4697 a bare exe in the Windows root with a **branch-scoped** System32
  filter, because `%SystemRoot%\System32\svchost.exe -k` is ubiquitous).
  4697: 0.43 → 1.00 precision, FP rate 1.00 → 0.00. 4698: 0.43 → 0.75, 1.00 → 0.25.
- Write discriminators against the **real pinned EVTX**, not just synthetic
  cases — probe the sample first (scratchpad `spike_crosscheck.py` has the
  evtx_dump → flatten helpers).
- 1102 stays `high` with FP rate 1.0 accepted on a **base-rate** argument;
  4720 and the 4104 obfuscation rule are demoted to `informational`.
- Thresholds live in `evals/<stem>/cases.yml`, **not** in the Sigma rules, so the
  rules stay portable. Defaults are strict; anything lenient is rejected at load
  time without a `justification`.
- **No ratchet file** — `evals/results.json` is drift-checked, so any metric
  change already fails CI until committed deliberately. Don't add one.
- **GitHub cannot require PRs for only some paths.** Branch protection is
  per-branch. So "PRs for detections/** and evals/** only" is enforced by
  convention: PR template + eval gate + results published to the run summary.
  Protecting all of `main` is the only way to make it mandatory — Can's call.

## Phases 5 & 6 — reproducibility and presentation
- **`.hayabusa-version` pins the release AND each platform archive's SHA-256.**
  `detkit hayabusa` verifies before extracting and refuses an unverified binary.
  CI calls the same installer a human does. Never go back to `curl | unzip |
  find` — an empty `find` is what silently degraded the suite to "skipped".
- `detkit ci` is the single entry point and mirrors CI's order. On Windows the
  venv's Scripts dir is not on PATH under the console script, so the runner
  resolves each tool against `sys.executable`'s directory — don't "simplify" that
  back to bare names.
- **README numbers are generated.** `detkit readme` rewrites the block between
  `<!-- detkit:eval-table:start/end -->` from `evals/results.json`, and README.md
  is drift-checked in CI. Never hand-edit inside those markers.
- Coverage headline is **authored-only**; the vendored count is a separate,
  clearly-labelled line. Don't merge them back into one number.
- Pipelines: vendor `splunk_windows` + repo `pipelines/splunk_sysmon_source.yml`
  (binds generic categories to their Sysmon/PowerShell channels). `detkit convert`
  compiles and **fails if any Splunk query lacks a `source=`**. Note an SPL query
  can span lines — a Sigma `|re` renders as a `| regex ...` continuation — so the
  check splits on blank lines, not newlines. A line-based version of this check
  reported a correctly-bound rule as unbound. Kusto uses `microsoft_xdr` on the
  process_creation subset only — **Sentinel's SecurityEvent schema has no
  PreAuthType column**, so those rules cannot bind there without EventData
  parsing. That is a platform limit, documented in the README, not a TODO.

Note on logsource: Hayabusa maps `category: process_creation` to Sysmon EID 1, so
4688 Security-log samples won't match those. Rules tested on Security-log samples
are authored as `service: security` with native fields (EventID + NewProcessName /
CommandLine / TargetSid / Properties), mirroring Sigma-HQ's windows/builtin/security
tree. `category: ps_script` (4104) and `category: process_access` (Sysmon 10) map
fine. Use scratchpad probe.py / dump.py pattern to verify a new rule fires before
committing.
