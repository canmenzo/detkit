# Detection Engineering — Detection-as-Code

> Threat-detection rules that are **measured**, not just written. Every rule is
> scored for precision, recall and false-positive rate against labelled events,
> tested against real adversary telemetry, and blocked from merging if it drops
> below a threshold it declares for itself.

**[🔎 Live dashboard →](https://canmenzo.github.io/detection-engineering/)** — browsable, filterable view of every detection and its test status. Hover any metric for how it is calculated, or read **[How it works →](https://canmenzo.github.io/detection-engineering/about.html)** for the method behind every number.

![ATT&CK coverage](coverage/coverage.png)

## Why this exists

Most "detection work" lives in a SIEM console and disappears when you log out.
This repo treats detections like software: version-controlled rules, tests
against real adversary telemetry, CI/CD, and an auto-generated coverage map.

The part that is genuinely uncommon is the measurement. Writing a rule is easy;
showing that it catches the attack **and** stays quiet on the ordinary
administrative activity it resembles is the actual job. Every number in this
README is produced by the harness, not typed by hand — including the unflattering
ones.

## Two tiers: authored vs. vendored

The corpus is deliberately split so quality and breadth are never conflated:

- **`detections/`** — my own rules. Each is ATT&CK-mapped, scored against
  labelled events, and pinned to real adversary EVTX. CI fails if any rule lacks
  a fixture or drops below its declared thresholds. This is the showcase, and it
  is what the headline coverage number counts.
- **`vendored/`** — a pinned, clearly-attributed copy of the public
  [SigmaHQ](https://github.com/SigmaHQ/sigma) Windows corpus (~2,400 rules, DRL 1.1).
  **Not my work**, and not held to the fixture or eval gates. It runs through the
  same conversion pipeline at scale (100% convert to Splunk) and shades the
  coverage map. See [`vendored/README.md`](vendored/README.md).

In the coverage matrix, **green** cells are authored, **blue** are vendored-only.
The headline count is the green one; the vendored figure is stated separately
rather than added to it.

Two rules carry a *negative-only* EVTX fixture, and say so in their manifests. No
public Sysmon EID 1 capture exists of a firewall being disabled or of an encoded
PowerShell command line — every public one is Security 4688 or PowerShell 4104.
What does exist is real telemetry those rules must stay **silent** on, which is
worth pinning; their true-positive coverage comes from the eval harness.

## How it works

```
                      ┌──────────────────────┐
                      │  detections/*.yml    │   Sigma rules (authored here)
                      └───────────┬──────────┘
                                  │
        ┌────────────────┬────────┴────────┬──────────────────┐
        │                │                 │                  │
   ┌────▼─────┐    ┌─────▼──────┐    ┌─────▼──────┐    ┌──────▼───────┐
   │ discipline│    │  quality   │    │ real data  │    │  deployable  │
   ├───────────┤    ├────────────┤    ├────────────┤    ├──────────────┤
   │ yamllint  │    │ detkit eval│    │  Hayabusa  │    │ sigma convert│
   │sigma check│    │            │    │  + pytest  │    │              │
   │detkit     │    │ labelled   │    │  pinned    │    │ splunk_windows│
   │ validate  │    │ events →   │    │  public    │    │ + repo source │
   │           │    │ precision  │    │  EVTX      │    │   binding     │
   │ ATT&CK tag│    │ recall     │    │  (sha256-  │    │ microsoft_xdr │
   │ + fixture │    │ FP rate    │    │   pinned)  │    │               │
   │ required  │    │            │    │            │    │ every query   │
   │           │    │ per-rule   │    │ engine must│    │ must name its │
   │           │    │ thresholds │    │ agree with │    │ source, or CI │
   │           │    │ gate CI    │    │ the eval   │    │ fails         │
   └─────┬─────┘    └─────┬──────┘    └─────┬──────┘    └──────┬───────┘
         │                │                 │                  │
         └────────────────┴────────┬────────┴──────────────────┘
                                   │
                      ┌────────────▼─────────────┐
                      │ generated, drift-checked │
                      │ coverage.png · dashboard │
                      │ navigator layer · README │
                      │ numbers · results.json   │
                      └──────────────────────────┘

  Two independent engines evaluate every rule — Hayabusa over real EVTX, and a
  SQL evaluator over labelled events. They must agree; disagreement fails CI.
```

## Run it locally

Dependencies are locked with [uv](https://docs.astral.sh/uv/); `uv sync` builds the
exact environment CI uses, from `uv.lock`.

```bash
uv sync --all-extras          # exact locked environment, incl. dev tooling
uv run detkit ci              # everything, in CI's order
```

`detkit ci` installs the pinned Hayabusa release (verified against the SHA-256 in
`.hayabusa-version` — an unverified binary download is not a reproducible build),
then runs lint, type check, YAML lint, `sigma check`, the rule-discipline gate,
the full test suite, the detection-quality eval, every generator, and finally
checks that the committed artifacts still match what the generators produce. It
is the same sequence CI runs, just serial instead of parallel. Or open the repo
in the devcontainer, which does the setup for you.

Individual steps:

```bash
uv run detkit validate        # metadata + fixture + ATT&CK tag discipline (authored only)
uv run detkit eval            # precision / recall / FP rate per rule
uv run detkit vendored        # batch convert + coverage over the vendored SigmaHQ corpus
uv run detkit coverage        # writes coverage/coverage.png
uv run detkit navigator       # writes coverage/navigator_layer.json
uv run detkit dashboard       # writes site/index.html + site/about.html (the live dashboard)
uv run detkit hayabusa        # install the pinned Hayabusa release
uv run detkit probe <rule>    # run a rule against its pinned EVTX and show the hits

uv run pytest -v              # unit tests + detection tests (fetches samples, runs Hayabusa)
uv run ruff check .           # lint
uv run mypy                   # type check (strict)
```

Hayabusa is a single binary from [Yamato Security](https://github.com/Yamato-Security/hayabusa);
download a release and point `HAYABUSA_BIN` at it (keep it next to its bundled
`rules/config`). Tests download pinned public EVTX samples on first run and cache
them locally — see [`docs/adr/0002`](docs/adr/0002-fetch-pinned-samples.md).

Without Hayabusa the detection tests skip so you can still work on the tooling;
the harness-integrity tests always run. CI sets `DETKIT_REQUIRE_HAYABUSA=1`,
which turns any skip into a build failure — a detection suite that did not
execute must never report green.

## Detection quality

Every rule is scored against a golden dataset of labelled events — true
positives *and* benign look-alikes that differ only where the rule's logic is
supposed to discriminate. `detkit eval` reports precision, recall and
false-positive rate per rule; run it yourself and get the numbers below.

Read **FP rate** first. Precision depends on the malicious-to-benign ratio in the
case set, which is authored, not observed — so it is comparable between runs but
is not a claim about a real event stream. FP rate (the share of benign events
that alert) and recall do not move with that ratio.

Thresholds are declared per rule and CI fails when one is missed. Lowering a bar
is allowed; lowering it silently is not — the loader rejects a weakened threshold
that carries no written justification.

<!-- detkit:eval-table:start -->

15 rules, 125 labelled events. Generated by `detkit eval`; CI fails if this table drifts from the corpus.

| rule | level | precision | recall | FP rate | bar it must clear |
|---|---|---:|---:|---:|---|
| `proc_creation_win_impacket_wmiexec_output` | high | 1.00 | 1.00 | 0.00 | p≥0.90, r≥1.00, fp≤0.10 |
| `security_win_dcsync_replication` | critical | 1.00 | 1.00 | 0.00 | p≥0.90, r≥1.00, fp≤0.10 |
| `security_win_service_installed` | high | 1.00 | 1.00 | 0.00 | p≥0.90, r≥1.00, fp≤0.10 |
| `proc_creation_win_encoded_powershell` | high | 0.83 | 1.00 | 0.14 | p≥0.80, r≥1.00, fp≤0.20 |
| `proc_creation_win_firewall_disabled_netsh` | high | 0.75 | 1.00 | 0.14 | p≥0.70, r≥1.00, fp≤0.20 |
| `security_win_kerberoasting_rc4_request` | high | 0.75 | 1.00 | 0.17 | p≥0.70, r≥1.00, fp≤0.25 |
| `sysmon_proc_access_lsass_dump` | high | 0.80 | 1.00 | 0.20 | p≥0.75, r≥1.00, fp≤0.25 |
| `security_win_asrep_roasting` | high | 0.75 | 1.00 | 0.25 | p≥0.70, r≥1.00, fp≤0.30 |
| `security_win_scheduled_task_created` | high | 0.75 | 1.00 | 0.25 | p≥0.70, r≥1.00, fp≤0.30 |
| `proc_creation_win_certutil_download_decode` | high | 0.67 | 1.00 | 0.33 | p≥0.60, r≥1.00, fp≤0.40 |
| `posh_ps_defender_tamper` | high | 0.71 | 1.00 | 0.40 | p≥0.65, r≥1.00, fp≤0.45 |
| `security_win_user_added_to_privileged_group` | high | 0.60 | 1.00 | 0.50 | p≥0.55, r≥1.00, fp≤0.55 |
| `posh_ps_susp_encoded_powershell_scriptblock` | informational | 0.50 | 1.00 | 0.67 | p≥0.45, r≥1.00, fp≤0.70 |
| `security_win_eventlog_cleared` | high | 0.60 | 1.00 | **1.00** | p≥0.55, r≥1.00, fp≤1.00 |
| `security_win_local_user_created` | informational | 0.43 | 1.00 | **1.00** | p≥0.40, r≥1.00, fp≤1.00 |

<!-- detkit:eval-table:end -->

Three results worth calling out rather than burying:

- **`proc_creation_win_encoded_powershell` misses a true positive** (recall 0.80).
  `powershell.exe` accepts `-e` as an abbreviation of `-EncodedCommand`, and the
  rule only tests `-enc`, `-encodedcommand` and `-ec`. The evasion is in the case
  set as a known miss.
- **`posh_ps_susp_encoded_powershell_scriptblock` fires on two thirds of benign
  PowerShell** in its set. `-join` and `[Convert]::ToInt` are ordinary
  administrative code, so it is shipped as `informational` — a hunting query, not
  an alert.
- **Two rules still alert on 100% of benign events.** `security_win_eventlog_cleared`
  keeps that bar deliberately: a cleared log carries no evidence of *why* it was
  cleared, so no discriminator exists, and the justification is a base-rate
  argument (1102 does not happen on a healthy host). `security_win_local_user_created`
  cannot make that argument — account creation is routine — so it is demoted to an
  audit record. Both justifications are in their case files.

Two rules that *did* have signal available were fixed rather than excused:
`security_win_service_installed` went from 0.43 precision / 1.00 FP rate to
**1.00 / 0.00**, and `security_win_scheduled_task_created` to **0.75 / 0.25**, by
keying on what the service or task actually executes.

## Known gaps

Stated plainly, because a reviewer will find them anyway:

- **The benign events are authored, not captured.** They measure whether a rule's
  logic discriminates. They do not measure real-world base rates, so nothing here
  predicts alert volume on a live estate.
- **The evaluator coerces numeric strings**, matching Hayabusa's loose typing and
  therefore being more lenient than a strictly-typed backend. See
  [ADR 0003](docs/adr/0003-sql-evaluator-for-labelled-events.md).
- **Thresholds do not gate the build yet.** The eval runs on every PR and reports;
  per-rule bars and a regression ratchet are the next piece of work.
- **Sentinel coverage is partial, and that is a platform limit, not an oversight.**
  Splunk gets all 15 rules, source-bound. Microsoft XDR gets the
  `process_creation` subset — Defender XDR has no table equivalent for the
  Windows Security-log events the rest of the corpus targets. Sentinel's
  `SecurityEvent` table does not surface every field these rules use (`PreAuthType`
  is not a column), so those rules would need per-rule `EventData` parsing before
  they could run there. The Kusto pipeline refuses to emit a query it cannot bind
  to a table, which is the correct behaviour.

## The detection lifecycle

Hypothesis → Sigma rule → EVTX fixtures (TP + benign) → tested with Hayabusa →
converted to KQL/SPL → mapped to ATT&CK → shipped via PR.
Full walkthrough in [`docs/detection_lifecycle.md`](docs/detection_lifecycle.md).

## Why this design

Four choices here have real alternatives, so they are worth defending.

**Why Sigma rather than writing SPL/KQL directly.** A rule written once and
compiled to each platform stays reviewable as a single artifact, and the
compilation step is itself a test — a rule that cannot be expressed against a
target's schema is telling you something. That happened here: the Kusto pipeline
refused to bind `PreAuthType`, because Sentinel's `SecurityEvent` table does not
surface it. Writing KQL by hand would have hidden that until deployment.

**Why two evaluation engines.** Hayabusa runs rules against real attacker EVTX;
a SQL evaluator runs them against labelled events. Neither alone is enough —
public EVTX contains almost no curated *benign look-alikes*, and hand-written
events are not real telemetry. Running both and requiring agreement catches what
either would miss alone, and it already has: a YAML formatting choice that
Hayabusa silently refused to parse was accepted by both other tools, so the rule
would have stopped running with nothing to show for it. See
[ADR 0003](docs/adr/0003-sql-evaluator-for-labelled-events.md).

**Why fetched samples instead of vendored ones.** Committing real attack captures
means committing malware artifacts: endpoint AV quarantines them, and contributors
cannot clone the repo cleanly. Pinning them by commit + SHA-256 and fetching at
test time keeps the repo AV-safe and the samples immutable. See
[ADR 0002](docs/adr/0002-fetch-pinned-samples.md).

**Why no Terraform.** There is no cloud infrastructure to provision. A Terraform
module with nothing behind it is a prop, and reviewers notice props. What
"reproducible" actually means here is that a clean checkout produces an identical
verified run, so that is what was built: locked dependencies, a checksum-verified
Hayabusa, a devcontainer, and one command. See
[ADR 0004](docs/adr/0004-no-terraform.md).

## Coverage

The matrix at the top is rendered directly from the rule corpus by
[`detkit coverage`](src/detkit/coverage.py) — no external service needed. CI
regenerates every published artifact and fails if the committed copies differ,
so the dashboard cannot drift from the repo.

For an interactive view, [`coverage/navigator_layer.json`](coverage/navigator_layer.json)
can be loaded in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
("Open Existing Layer" → "Upload from local"). The layer pins `attack: 16`; if the
hosted Navigator has moved to a newer ATT&CK release it may refuse the file, which
is why the committed PNG above is the canonical, dependency-free view.
