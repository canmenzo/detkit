"""Render site/about.html — the explanation of how the whole thing works.

The dashboard publishes numbers; this page publishes the method behind them. It
exists so a reader who has never seen a Sigma rule can follow what is being
measured and why, and so the design decisions are stated in one place rather
than reconstructed from commit messages.

**Keep it current.** Anything that changes the architecture — a new gate, a new
generator, a different engine, a changed metric — has to be reflected here in
the same commit. A page explaining a system that no longer exists is worse than
no page. Everything that can be derived from the corpus (rule counts, per-rule
thresholds and their justifications, the CI step list) is generated rather than
typed, so the prose is the only part needing a human.
"""
from __future__ import annotations

import html
import json
from typing import Any

import yaml

from detkit.attack import TACTIC_BY_NAME
from detkit.paths import (
    ATTACK_VERSION_FILE,
    DETECTIONS,
    EVAL_RESULTS,
    HAYABUSA_VERSION_FILE,
    REPO,
    SITE,
    VENDORED_REPORT,
)
from detkit.pipeline import DRIFT_PATHS, STEPS
from detkit.rules import conversion_only, load_corpus, sample_count
from detkit.webui import PALETTE, nav

SITE_ABOUT = SITE / "about.html"
GH_BASE = "https://github.com/canmenzo/detection-engineering/blob/main/"

# What each gate in `detkit ci` is actually for. Keyed by the step label in
# pipeline.STEPS; a step added there without an entry here still renders, so the
# table cannot silently omit a gate.
GATE_PROSE: dict[str, str] = {
    "ruff": "Lint over every Python file in the repo, tooling and tests alike.",
    "mypy": "Strict type checking. No implicit <code>Any</code>, no untyped defs.",
    "yamllint": "Formatting discipline on the rule files themselves.",
    "sigma check": "pySigma's own rule linter, run with <code>--fail-on-issues</code>. It sat at "
                   "20 issues while it was advisory; it is only enforced now that the count is 0.",
    "rule discipline": "<code>detkit validate</code>: required metadata on every rule, at least one "
                       "ATT&amp;CK technique tag, and either a test fixture or a declared exemption. "
                       "It also pins the ATT&amp;CK release and rejects a folded scalar in a "
                       "<code>condition:</code> — Hayabusa cannot parse one and silently stops "
                       "running the rule.",
    "pytest": "Unit tests over the tooling, plus the EVTX detection tests. A skipped detection test "
              "fails the run: the suite used to pass by skipping everything.",
    "detection quality": "<code>detkit eval</code> scores every rule against its labelled events and "
                         "fails if any rule drops below the bar it declares.",
    "convert + binding": "Compiles the corpus to Splunk SPL and Microsoft XDR KQL, and fails if any "
                         "Splunk query lacks a <code>source=</code>. Syntactic validity is not "
                         "deployability.",
    "vendored corpus": "Batch-converts the pinned third-party SigmaHQ corpus and rebuilds its report.",
    "navigator layer": "Rebuilds the ATT&amp;CK Navigator layer JSON.",
    "coverage matrix": "Rebuilds the coverage heat map.",
    "dashboard": "Rebuilds this site.",
    "readme numbers": "Rewrites the measured table in the README from <code>evals/results.json</code>. "
                      "The README's numbers are the harness's numbers because the harness writes them.",
}

ADR_SUMMARY: dict[str, str] = {
    "0001": "Hayabusa is the EVTX test engine: one static binary that runs Sigma against real "
            "event logs, driven by pytest.",
    "0002": "Samples are not vendored. Each fixture pins public EVTX by repo, commit, path and "
            "SHA-256, and they are fetched and hash-verified at test time.",
    "0003": "Labelled events are evaluated through pySigma's SQLite backend rather than a second "
            "log platform. Zircolite was the obvious candidate and was rejected: it is not on "
            "PyPI, so it could not be locked. Hayabusa stays as an independent second engine and "
            "the two must agree.",
    "0004": "No Terraform. Terraform with no infrastructure behind it is a prop; reproducibility "
            "here means a clean checkout produces an identical verified run, which locked "
            "dependencies and a checksum-pinned engine already deliver.",
    "0005": "Cloud rules carry a declared, weaker evidence tier. Nobody publishes captures of Entra "
            "ID telemetry — it is real people's tenant data — so those rules cannot be replayed "
            "against a recording. Instead their labelled scoring is mandatory and every field is "
            "validated against Microsoft's published table schema at compile time. The dashboard "
            "badges them differently rather than letting the distinction blur.",
    "0006": "Obfuscation is split into two rules instead of one. Matching obfuscation primitives "
            "alone fires on two thirds of ordinary admin PowerShell (measured), so that rule is "
            "informational and used for hunting; a second rule requiring obfuscation plus an "
            "execution or download sink alerts at high, and its benign cases are the first rule's "
            "false alarms. Severity follows what is obfuscated, not that something is.",
    "0007": "The corpus is closed at its current size. More cloud rules would repeat a solved "
            "pattern rather than prove anything new, and a Splunk container replaying the same "
            "pinned EVTX would restate gates that already pass — what a live SIEM would really "
            "add is production volume, which this project does not have. Both are declined in "
            "writing rather than left on an open TODO list.",
}


def attack_version() -> str:
    if not ATTACK_VERSION_FILE.exists():
        return "the pinned release"
    return "v" + ATTACK_VERSION_FILE.read_text(encoding="utf-8").strip()


def hayabusa_version() -> str:
    if not HAYABUSA_VERSION_FILE.exists():
        return "pinned"
    doc = yaml.safe_load(HAYABUSA_VERSION_FILE.read_text(encoding="utf-8"))
    return f"v{doc['version']}" if isinstance(doc, dict) and "version" in doc else "pinned"


def _results() -> dict[str, Any]:
    if not EVAL_RESULTS.exists():
        return {}
    data = json.loads(EVAL_RESULTS.read_text(encoding="utf-8"))
    rules = data.get("rules")
    return rules if isinstance(rules, dict) else {}


def _vendored() -> dict[str, Any]:
    if not VENDORED_REPORT.exists():
        return {}
    data = json.loads(VENDORED_REPORT.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _adrs() -> list[tuple[str, str, str]]:
    """(number, title, summary) for each ADR, in file order."""
    root = REPO / "docs" / "adr"
    out = []
    for path in sorted(root.glob("*.md")):
        first = path.read_text(encoding="utf-8").splitlines()[0]
        title = first.lstrip("# ").strip()
        number = path.name.split("-", 1)[0]
        out.append((number, title, ADR_SUMMARY.get(number, "")))
    return out


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _worked_example(results: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """A rule whose arithmetic is worth showing: real false alarms, most cases."""
    scored = [(stem, m) for stem, m in results.items() if m.get("fp")]
    if not scored:
        scored = sorted(results.items())
    stem, metrics = max(
        scored,
        key=lambda item: (item[1]["tp"] + item[1]["fp"] + item[1]["fn"] + item[1]["tn"], item[0]),
    )
    return stem, metrics


def _threshold_rows(results: dict[str, Any], justifications: dict[str, str]) -> str:
    rows = []
    for stem in sorted(results):
        m = results[stem]
        t = m.get("thresholds", {})
        bar = (
            f"p&ge;{t.get('min_precision', 0.9):.2f} &middot; "
            f"r&ge;{t.get('min_recall', 1.0):.2f} &middot; "
            f"fp&le;{t.get('max_fp_rate', 0.1):.2f}"
        )
        fp_cls = "num bad" if (m["fp_rate"] or 0) >= 1.0 else "num"
        rows.append(
            f"<tr><td><code>{html.escape(stem)}</code></td>"
            f"<td class='num'>{_fmt(m['precision'])}</td>"
            f"<td class='num'>{_fmt(m['recall'])}</td>"
            f"<td class='{fp_cls}'>{_fmt(m['fp_rate'])}</td>"
            f"<td class='bar'>{bar}</td></tr>"
        )
        justification = justifications.get(stem, "")
        if justification:
            rows.append(
                f"<tr class='why'><td colspan='5'><b>Why the bar is where it is:</b> "
                f"{html.escape(justification)}</td></tr>"
            )
    return "\n".join(rows)


HUNT_STEM = "posh_ps_susp_encoded_powershell_scriptblock"
ALERT_STEM = "posh_ps_obfuscated_payload_execution"


def _tier_pair(results: dict[str, Any]) -> str:
    """The hunting/alerting pair, with both measured FP rates filled in.

    Written as a generated block rather than prose because the two numbers are
    the whole argument: quoting them by hand would let the page keep claiming an
    improvement the corpus no longer shows.
    """
    hunt, alert = results.get(HUNT_STEM), results.get(ALERT_STEM)
    if not hunt or not alert:
        return ""
    return f"""
  <h3>Some rules are hunting queries, not alerts</h3>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Attackers scramble their PowerShell so it does not read as an attack. The obvious rule is
    "alert when a script looks scrambled" — and measuring it showed that <b>two thirds of ordinary
    admin scripts look scrambled too</b>, because joining text together and converting numbers are
    everyday operations.</p>
    <p>Deleting the rule would be wrong: scrambling really is a signal. So it was demoted. It now
    ranks script blocks for a human to look through — a <b>hunting query</b> — while a second rule
    pages someone only when scrambling appears <i>together with</i> something that runs or downloads
    the result. Same signal, two products, two severities.</p>
  </div>
  <table>
    <tr><th>rule</th><th>asks</th><th>severity</th><th>FP rate</th></tr>
    <tr><td><code>{html.escape(HUNT_STEM)}</code></td>
        <td>which script blocks are worth a human's attention?</td>
        <td>informational</td><td class="num bad">{_fmt(hunt['fp_rate'])}</td></tr>
    <tr><td><code>{html.escape(ALERT_STEM)}</code></td>
        <td>which ones should wake someone up?</td>
        <td>high</td><td class="num">{_fmt(alert['fp_rate'])}</td></tr>
  </table>
  <p>The second rule's benign cases <b>are</b> the first rule's false alarms, so the pair is held
  together by its own gate: if the alerting tier ever starts firing on <code>-join</code> building
  a file path, CI fails. On the real Invoke-Obfuscation capture both rules see the same 66 script
  blocks; the hunting tier flags most of them, the alerting tier flags the one that also calls
  <code>iex</code>.</p>
  <p class="muted">A false-positive rate of {_fmt(hunt['fp_rate'])} is a failure for an alert and
  perfectly reasonable for a hunt, which is why the threshold is a property of the rule rather than
  a constant. Severity follows what is being obfuscated, not the fact that something is.</p>"""


def _gate_rows() -> str:
    rows = [
        f"<tr><td><code>{html.escape(label)}</code></td><td>{GATE_PROSE.get(label, '')}</td></tr>"
        for label, _ in STEPS
    ]
    paths = ", ".join(f"<code>{html.escape(p)}</code>" for p in DRIFT_PATHS)
    rows.append(
        "<tr><td><code>artifact drift</code></td><td>Every generated artifact is rebuilt and "
        f"diffed against what is committed ({paths}). Generator output is a pure function of the "
        "corpus — no timestamps — so a diff means someone changed the rules without regenerating, "
        "and the published numbers no longer describe the repo.</td></tr>"
    )
    return "\n".join(rows)


def collect() -> dict[str, Any]:
    from detkit.evaluation.cases import load_all  # local: keeps import cost off other commands

    rules = load_corpus(DETECTIONS)
    results = _results()
    case_sets = load_all()
    justifications = {cs.stem: cs.thresholds.justification for cs in case_sets}
    lenient = {cs.stem for cs in case_sets if cs.thresholds.is_lenient}
    techniques = sorted({t for r in rules for t in r.techniques})
    tactics = sorted({TACTIC_BY_NAME[t].label for r in rules for t in r.tactics
                      if t in TACTIC_BY_NAME})
    vend = _vendored()
    return {
        "rules": rules,
        "results": results,
        "justifications": justifications,
        "lenient": lenient,
        "techniques": techniques,
        "tactics": tactics,
        "n_tested": sum(1 for r in rules if sample_count(r.stem)),
        "n_samples": sum(sample_count(r.stem) for r in rules),
        "n_exempt": len(conversion_only()),
        "n_cases": sum(
            m["tp"] + m["fp"] + m["fn"] + m["tn"] for m in results.values()
        ),
        "vend_rules": vend.get("total_rules", 0),
        "vend_rate": (vend.get("convert", {}) or {}).get("rate"),
        "vend_tech": len(set(vend.get("techniques", [])) - set(techniques)),
    }



def render(data: dict[str, Any]) -> str:
    results = data["results"]
    n_rules = len(data["rules"])
    n_scored = len(results)
    vend_rate = data["vend_rate"]
    vend_rate_pct = f"{100 * vend_rate:.0f}%" if vend_rate is not None else "—"
    ex_stem, ex = _worked_example(results) if results else ("", {})
    ex_malicious = ex.get("tp", 0) + ex.get("fn", 0)
    ex_benign = ex.get("fp", 0) + ex.get("tn", 0)
    worked = ""
    if ex_stem:
        tp, fp, fn, tn = ex["tp"], ex["fp"], ex["fn"], ex["tn"]
        worked = (
            f'<h3>Worked example — <code>{html.escape(ex_stem)}</code></h3>'
            f"<p>{ex_malicious} malicious and {ex_benign} benign events are labelled for this "
            f"rule. It fired on {tp} of the malicious ones and {fp} of the benign ones.</p>"
            f'<span class="calc">'
            f"FP rate &nbsp;= {fp} &divide; ({fp} + {tn}) = {_fmt(ex['fp_rate'])}<br>"
            f"recall &nbsp;&nbsp;= {tp} &divide; ({tp} + {fn}) = {_fmt(ex['recall'])}<br>"
            f"precision = {tp} &divide; ({tp} + {fp}) = {_fmt(ex['precision'])}"
            f"</span>"
        )
    adrs = "\n".join(
        f"<li><b>{html.escape(title)}</b><br><span class='muted'>{summary}</span></li>"
        for _, title, summary in _adrs()
    )
    tier_pair = _tier_pair(results)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>How it works — Detection-as-Code</title>
<style>
{PALETTE}
  html {{ scroll-behavior:smooth; }}
  header {{ max-width:860px; margin:0 auto; padding:36px 24px 4px; }}
  h1 {{ margin:0 0 8px; font-size:28px; }}
  .lede {{ color:var(--muted); font-size:15.5px; }}
  main {{ max-width:860px; margin:0 auto; padding:0 24px 80px; }}
  /* The nav is sticky, so an anchored section has to clear it or the heading
     lands underneath the bar. */
  section {{ margin:44px 0 0; scroll-margin-top:76px; }}
  h2 {{ font-size:20px; margin:0 0 4px; scroll-margin-top:76px; }}
  h2 .n {{ color:var(--muted); font-weight:400; font-size:15px; margin-right:8px; }}
  h3 {{ font-size:15px; margin:22px 0 6px; }}
  p {{ margin:10px 0; }}
  .muted {{ color:var(--muted); }}
  .toc {{ display:flex; flex-wrap:wrap; gap:8px; margin:22px 0 0; }}
  .toc a {{ font-size:13px; text-decoration:none; color:var(--muted); background:var(--card);
            border:1px solid var(--line); border-radius:20px; padding:5px 11px; }}
  .toc a:hover {{ color:var(--fg); border-color:var(--accent); }}
  .plain {{ border-left:3px solid #1f6feb; background:#12233d33; border-radius:0 8px 8px 0;
            padding:12px 16px; margin:16px 0; }}
  .plain .tagp {{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.09em;
                  color:var(--accent); margin-bottom:6px; font-weight:600; }}
  .plain p {{ margin:8px 0; color:#dbe3ea; }}
  .plain p:first-of-type {{ margin-top:0; }}
  .plain p:last-child {{ margin-bottom:0; }}
  .analogy {{ font-style:italic; color:var(--muted); border-left:3px solid var(--warn);
              padding-left:13px; margin:14px 0; font-size:14px; }}
  .box {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:14px 16px; margin:16px 0; }}
  .box.why {{ border-left:3px solid var(--accent); }}
  .box.limit {{ border-left:3px solid var(--warn); }}
  .box h4 {{ margin:0 0 6px; font-size:13px; text-transform:uppercase; letter-spacing:.06em;
             color:var(--muted); }}
  .grid {{ display:grid; grid-template-columns:170px 1fr; gap:10px 18px; margin:14px 0; }}
  .grid dt {{ font-weight:600; }}
  .grid dd {{ margin:0; color:#c9d1d9; }}
  .stages {{ display:flex; flex-wrap:wrap; gap:10px; margin:18px 0; }}
  .stage {{ flex:1 1 210px; background:var(--card); border:1px solid var(--line);
            border-radius:10px; padding:12px 14px; position:relative; }}
  .stage b {{ display:block; font-size:14px; margin-bottom:4px; }}
  .stage code {{ font-size:11.5px; color:var(--accent); }}
  .stage p {{ margin:6px 0 0; font-size:12.5px; color:var(--muted); }}
  .stage .num {{ position:absolute; top:10px; right:12px; font-size:11px; color:var(--muted); }}
  table {{ width:100%; border-collapse:collapse; margin:14px 0; font-size:13px; }}
  th {{ text-align:left; color:var(--muted); font-weight:600; padding:6px 8px;
        border-bottom:1px solid var(--line); font-size:12px; text-transform:uppercase;
        letter-spacing:.05em; }}
  td {{ padding:7px 8px; border-bottom:1px solid #21262d; vertical-align:top; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.num.bad {{ color:var(--bad); font-weight:600; }}
  td.bar {{ color:var(--muted); font-size:12px; white-space:nowrap; }}
  td.was {{ color:var(--muted); }}
  td.now {{ color:var(--ok); }}
  tr.why td {{ color:var(--muted); font-size:12.5px; border-bottom:1px solid var(--line);
               padding-top:0; }}
  code {{ background:#1c2129; border-radius:4px; padding:1px 5px; font-size:12.5px; }}
  .calc {{ display:block; background:var(--card); border:1px solid var(--line);
           border-radius:8px; padding:12px 14px; margin:12px 0; color:var(--accent);
           font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:13px; }}
  .calc span {{ color:var(--muted); }}
  ul.spaced li {{ margin:8px 0; }}
  ol.spaced li {{ margin:10px 0; }}
  ol.spaced li b {{ color:var(--fg); }}
  .qa dt {{ font-weight:600; margin:16px 0 4px; }}
  .qa dd {{ margin:0; color:#c9d1d9; }}
  footer {{ max-width:860px; margin:0 auto; padding:24px; color:var(--muted);
            font-size:12.5px; border-top:1px solid var(--line); }}
</style>
</head>
<body>
{nav("about")}
<header>
  <h1>How it works</h1>
  <p class="lede">This repository treats threat-detection rules like software: written in
  version control, reviewed, tested against real attacker telemetry, scored for quality, and
  blocked from merging when they fall below a bar they declare for themselves. This page is the
  method behind every number on the <a href="index.html">coverage dashboard</a> — what is
  measured, how it is measured, and what it deliberately does not claim.</p>
  <p class="lede">It is written on two levels at once. The blue blocks explain each idea in
  ordinary language with no security background assumed; the text around them is the precise
  version. Read either one, or both.</p>
  <div class="toc">
    <a href="#problem">The problem</a>
    <a href="#vocabulary">Vocabulary</a>
    <a href="#story">Where this started</a>
    <a href="#pipeline">The pipeline</a>
    <a href="#layers">Two test layers</a>
    <a href="#metrics">The metrics</a>
    <a href="#thresholds">Thresholds</a>
    <a href="#gates">CI gates</a>
    <a href="#decisions">Design decisions</a>
    <a href="#limits">Honest limits</a>
    <a href="#repo">Repo map</a>
    <a href="#faq">FAQ</a>
  </div>
</header>
<main>

<section id="problem">
  <h2><span class="n">01</span>The problem this solves</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Windows computers write down almost everything that happens on them, in files called
    event logs. When an attacker breaks in, they leave traces there. A <b>detection rule</b> is a
    written recipe that says: if you ever see this pattern in the logs, shout.</p>
    <p>Anyone can write such a recipe. What almost nobody does is prove theirs works — that it
    catches the attack <i>and</i> stays quiet during ordinary Tuesday-afternoon admin work. This
    repository is a set of rules plus the machinery that produces that proof, automatically, every
    time anything changes.</p>
  </div>
  <p>In most organisations detection rules live inside a SIEM's web console: edited in a text box,
  deployed by whoever was on shift, with no history, no tests and no measurement. Nobody can answer
  the two questions that matter — <b>does this rule still fire on the attack it was written
  for</b>, and <b>how much noise does it cost the analyst reading the queue</b>.</p>
  <p>Detection-as-Code is the answer software engineering already found: put the logic in git, make
  every change reviewable, and gate it on automated tests. This repo is a working implementation of
  that idea over {n_rules} rules I wrote myself, plus the tooling that keeps them honest.</p>
  <div class="box why">
    <h4>The claim being made</h4>
    <p style="margin:0">Not "I can write a Sigma rule." Anyone can. The claim is: every rule here is
    mapped to adversary behaviour, proven to fire on a real attack capture, measured for false
    positives against benign look-alikes, and continuously re-checked — and where a rule is
    <i>bad</i>, the number saying so is published rather than hidden.</p>
  </div>
</section>

<section id="vocabulary">
  <h2><span class="n">02</span>Vocabulary</h2>
  <p>Nothing below this point needs any term that is not defined here.</p>
  <dl class="grid">
    <dt>Detection rule</dt>
    <dd>A written condition over log data that raises an alert when it matches. "Shout if a program
    starts with a scrambled command line" is a detection rule.</dd>
    <dt>Sigma</dt>
    <dd>A vendor-neutral YAML format for writing those rules. You write the logic once and compile
    it to whichever platform you run — Splunk, Sentinel, Elastic. Like writing a recipe in a
    universal language and having it auto-translated into any kitchen's local terms.</dd>
    <dt>EVTX</dt>
    <dd>The binary file format of Windows event logs. Public repositories publish EVTX <i>captured
    while real attacker tooling ran</i>, which is what makes it possible to test a rule against
    genuine telemetry rather than something I invented.</dd>
    <dt>Event ID</dt>
    <dd>Windows numbers every kind of event. 4688 = a program started. 1102 = the security log was
    cleared. 4697 = a service was installed. Attackers trigger these too, which is why they are
    worth watching — and why matching on the number <i>alone</i> is not a detection.</dd>
    <dt>MITRE ATT&amp;CK</dt>
    <dd>The industry catalogue of adversary behaviour — tactics (the goal, e.g. Credential Access)
    and techniques (the method, e.g. T1003.001 LSASS Memory). Tagging rules with technique IDs is
    what turns a pile of rules into a coverage map. This repo validates tags against release
    <b>{attack_version()}</b>.</dd>
    <dt>False positive</dt>
    <dd>The rule shouted and nothing bad had happened. This is <i>the</i> problem in security
    operations: a rule with too many false positives gets ignored, and an ignored rule might as
    well not exist.</dd>
    <dt>Hayabusa</dt>
    <dd>A fast Sigma engine that runs rules directly against EVTX files. Here it is the test
    harness: pytest hands it a rule and a captured attack and asserts on whether it hit. Pinned at
    <b>{hayabusa_version()}</b>.</dd>
    <dt>pySigma</dt>
    <dd>The Python library that parses Sigma and compiles it to backends. It does the conversion to
    Splunk and KQL, and — through its SQLite backend — the scoring of rules against labelled
    events.</dd>
    <dt>CI</dt>
    <dd>Continuous integration: a robot on GitHub's machines that re-runs every check on every
    change. If anything breaks it goes red. It is what stops "it worked on my laptop".</dd>
  </dl>
  <p>Four counts describe every rule's performance, and everything else is derived from them:
  <b>TP</b> (malicious event, rule fired), <b>FP</b> (benign event, rule fired anyway),
  <b>FN</b> (malicious event, rule stayed silent — a miss), <b>TN</b> (benign event, rule
  correctly silent).</p>
</section>

<section id="story">
  <h2><span class="n">03</span>Where this started</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>This repo did not begin in the state described on this page. It began as a normal portfolio
    project that looked fine from the outside, and was then audited on purpose, without mercy. Six
    things were wrong, and every one of them is the kind of thing that quietly makes a security
    project a decoration rather than a control.</p>
    <p>All six are fixed. They are written down here rather than deleted from the history, because
    the interesting part of the project is not that it is tidy now — it is what it took to find out
    that it wasn't.</p>
  </div>
  <ol class="spaced">
    <li><b>The tests could pass while testing nothing.</b> The suite needed an external engine. When
    that engine was missing the tests did not fail — they skipped, and the run reported success. The
    repository's single biggest claim was guarded by nothing at all.
    <div class="analogy">A smoke alarm that reports "all clear" when its battery has been
    removed.</div></li>
    <li><b>Nobody was measuring whether the rules were any good.</b> There were 16 test cases. 15
    asked "here is an attack, does it fire?". One asked "here is something harmless, does it stay
    quiet?" — and that one used a different kind of log entirely, so it proved nothing. There was
    zero evidence about false positives. For detection work that is a chef who never tastes the
    food.</li>
    <li><b>Four of the fifteen rules were not detections.</b> They alerted whenever a given event ID
    appeared, with no further logic. That is not detecting anything; it is forwarding an event and
    making a human decide.</li>
    <li><b>The quality checker was switched off.</b> Sigma's own linter was running, reporting 20
    problems (two serious), and the build was configured to ignore all of them and pass.</li>
    <li><b>The supporting code had no safety net.</b> ~800 lines of Python with no tests, no type
    checking, no dependency locking — in a repository whose entire pitch is treating security
    content like professional software.</li>
    <li><b>The compiled output would not have run anywhere.</b> Rules were auto-translated to Splunk
    and checked for grammar, but not for whether the result was usable: wrong field names, and no
    statement of which logs to search. Grammatically valid nonsense.</li>
  </ol>
  <h3>What changed</h3>
  <table>
    <tr><th>&nbsp;</th><th>at the audit</th><th>now</th></tr>
    <tr><td>Test suite</td><td class="was">15 tests, all silently skippable</td>
        <td class="now">119 tests; a skipped detection test fails the build</td></tr>
    <tr><td>Rule quality</td><td class="was">unmeasured</td>
        <td class="now">{data['n_cases']} labelled events, every rule scored, thresholds enforced</td></tr>
    <tr><td>Rules alerting on<br>100% of benign traffic</td><td class="was">4, unnoticed</td>
        <td class="now">2, both with a written justification</td></tr>
    <tr><td>Sigma linter</td><td class="was">20 problems, ignored</td>
        <td class="now">0 problems, and it blocks the build</td></tr>
    <tr><td>Python tooling</td><td class="was">no tests, no types, unlocked deps</td>
        <td class="now">packaged CLI, strict typing, locked and reproducible</td></tr>
    <tr><td>Compiled queries</td><td class="was">would not have run</td>
        <td class="now">all {n_rules} bound to a real source, checked in CI</td></tr>
    <tr><td>Published numbers</td><td class="was">typed by hand</td>
        <td class="now">generated; the build fails if they go stale</td></tr>
  </table>
  <div class="box why">
    <h4>Things measurement found that reading could not</h4>
    <p>Two examples, both invisible until there were numbers.</p>
    <p><b>A real evasion.</b> PowerShell accepts <code>-e</code> as an abbreviation of
    <code>-EncodedCommand</code>. The rule looked for the longer spellings only, so
    <code>powershell -e &lt;blob&gt;</code> walked straight past it. Fixing it moved recall from
    0.80 to 1.00 and cost one false positive out of seven benign cases — and the harness
    <i>blocked the change</i> until that trade was written down.</p>
    <p style="margin-bottom:0"><b>A rule that had silently stopped running.</b> Writing a rule's
    condition across multiple YAML lines is accepted by two of the three engines involved and
    rejected by the third, which reports only "1 parsing error" without naming the rule. The rule
    stops running and nothing says so. There is now a check for exactly that.</p>
  </div>
</section>

<section id="pipeline">
  <h2><span class="n">04</span>The pipeline</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Six stages take a rule from an idea to the published map. Each one can stop the whole thing,
    and one command runs all of them the same way the robot does — so "it works on my machine" and
    "the build is green" mean the same sentence.</p>
  </div>
  <div class="stages">
    <div class="stage"><span class="num">01</span><b>Author</b><code>detections/*.yml</code>
      <p>A Sigma rule with required metadata and ATT&amp;CK tags. <code>detkit probe</code> runs the
      draft against real samples before it is finalised.</p></div>
    <div class="stage"><span class="num">02</span><b>Gate</b><code>detkit validate</code>
      <p>Metadata, tag vocabulary pinned to an ATT&amp;CK release, and a fixture or a declared
      exemption. Structural problems die here.</p></div>
    <div class="stage"><span class="num">03</span><b>Prove it fires</b><code>pytest</code>
      <p>Hayabusa runs the rule against pinned public EVTX. Real channel, real field names, real
      attacker artefacts.</p></div>
    <div class="stage"><span class="num">04</span><b>Score it</b><code>detkit eval</code>
      <p>The rule is compiled to SQL and run over hand-labelled malicious and benign events.
      Precision, recall and FP rate fall out of the result.</p></div>
    <div class="stage"><span class="num">05</span><b>Compile</b><code>detkit convert</code>
      <p>Splunk SPL and Microsoft XDR KQL, with every query checked for a bound
      <code>source=</code>.</p></div>
    <div class="stage"><span class="num">06</span><b>Publish</b><code>detkit dashboard</code>
      <p>Coverage map, Navigator layer, this site and the README table — all regenerated and
      diffed, so published numbers cannot go stale.</p></div>
  </div>
  <div class="box why">
    <h4>Why the order matters</h4>
    <p style="margin:0">Each stage assumes the previous one held. There is no point measuring the
    false-positive rate of a rule that does not parse, and no point publishing a coverage map built
    from rules that failed their tests. <code>detkit ci</code> stops at the first failure for the
    same reason.</p>
  </div>
</section>

<section id="layers">
  <h2><span class="n">05</span>Two test layers, two different questions</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>There are two completely separate ways a rule is checked here, because there are two
    different ways a rule can be wrong.</p>
    <p>The first replays a <b>real recorded attack</b> and demands the rule fire. That catches a
    rule written against logs the author imagined rather than the ones Windows actually produces —
    the classic beginner mistake, and one that never shows up in your own tests.</p>
    <p>The second feeds the rule <b>hand-written examples, some attacks and some deliberately
    similar harmless activity</b>, and counts what it does. A real attack recording cannot do this:
    it has no harmless counterpart inside it to stay quiet on.</p>
  </div>
  <table>
    <tr><th>&nbsp;</th><th>EVTX fixture tests</th><th>Labelled-event scoring</th></tr>
    <tr><td><b>Question</b></td>
        <td>Does the rule fire on a real recording of this attack?</td>
        <td>Does the rule tell malicious apart from benign?</td></tr>
    <tr><td><b>Engine</b></td><td>Hayabusa {hayabusa_version()}, over real EVTX</td>
        <td>pySigma SQLite backend, over JSON events</td></tr>
    <tr><td><b>Data</b></td>
        <td>{data['n_samples']} public captures pinned by URL and SHA-256</td>
        <td>{data['n_cases']} events hand-written and labelled, each with a stated reason</td></tr>
    <tr><td><b>Catches</b></td>
        <td>Wrong channel, wrong field name, a rule that cannot run at all</td>
        <td>Logic too broad, logic too narrow, a rule that alerts on everything</td></tr>
    <tr><td><b>Misses</b></td>
        <td>A rule that fires on the sample <i>and</i> on everything else</td>
        <td>A rule matching a field Windows never actually emits</td></tr>
    <tr><td><b>Coverage</b></td>
        <td>{data['n_tested']} of {n_rules} rules ({data['n_exempt']} declared exempt)</td>
        <td>{n_scored} of {n_rules} rules</td></tr>
  </table>
  <p>The two engines are also a cross-check on each other. Two independent implementations of Sigma
  semantics agreeing on the same rule is worth more than trusting either alone; where they
  disagreed during development, the disagreement was the bug.</p>

  <h3>The cloud rules carry a third, weaker tier — and say so</h3>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>The Entra ID (Microsoft cloud identity) rules cannot get the first test. Nobody publishes
    recordings of cloud sign-in logs, because those logs are real people's names, addresses and
    devices — it is not a gap somebody forgot to fill, it is what privacy means for that data.</p>
    <p>So those rules get the scoring, which is compulsory for them rather than optional, plus a
    check that every field they mention actually exists in Microsoft's published table layout. A
    rule that invents a column name cannot be built. What that still does not prove is that the
    rule fires in a real tenant, and the dashboard labels them <b>schema-verified</b> instead of
    <b>tested</b> so the difference is visible at a glance rather than buried here.</p>
  </div>
  <p>Concretely: <code>detkit validate</code> fails a non-EVTX rule with no case set, and
  <code>detkit convert</code> compiles each Entra rule to its real Log Analytics table
  (<code>SigninLogs</code>, <code>AuditLogs</code>) through the repo's own Azure Monitor pipeline,
  where the backend rejects any column Microsoft does not publish. ADR 0005 has the argument and
  the two rejected alternatives — not writing cloud rules at all, and writing them while quietly
  letting the fixture gate not apply.</p>
</section>

<section id="metrics">
  <h2><span class="n">06</span>The metrics, and what each one hides</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Three numbers describe a rule, and they answer different questions:</p>
    <p><b>Recall</b> — of the real attacks, how many did it catch? Missing one is the expensive
    failure.<br>
    <b>FP rate</b> — of the harmless activity, how often did it shout anyway?<br>
    <b>Precision</b> — of everything it shouted about, how much was real?</p>
    <p>The trap is that precision can be improved without touching the rule, just by writing more
    attack examples and fewer harmless ones. Recall and FP rate cannot be gamed that way, so they
    lead and precision trails.</p>
  </div>
  <p>Every rule card on the dashboard carries four figures. Hovering any of them shows this same
  arithmetic with that rule's own counts filled in.</p>

  <h3>False-positive rate — the number to read first</h3>
  <span class="calc">FP &divide; (FP + TN) <span>— of the benign events, the share that alerted</span></span>
  <p>Stable against the shape of the dataset: adding or removing malicious cases cannot change it.
  That is what makes it the honest headline. A rule at 1.00 fires on every benign look-alike it was
  given, which usually means it is matching an event ID and nothing else.</p>

  <h3>Recall — did it catch what it was written for</h3>
  <span class="calc">TP &divide; (TP + FN) <span>— of the malicious events, the share that alerted</span></span>
  <p>Also stable, for the mirror reason: it only looks at malicious events. A miss is the expensive
  failure mode, because an alert that never fires is indistinguishable from a quiet network. Almost
  every rule here declares a recall floor of 1.00 — missing a true positive is not negotiable, and
  the trade is paid in false positives instead.</p>

  <h3>Precision — how much of the alert queue is real</h3>
  <span class="calc">TP &divide; (TP + FP) <span>— of everything that alerted, the share that was real</span></span>
  <p>This is what an analyst actually feels on shift, and it is the one figure here that must be
  read with suspicion. Precision depends on the ratio of malicious to benign events, and in a case
  set that ratio is <i>authored</i>, not observed. Real estates run millions of benign events for
  every malicious one, so a rule scoring 0.80 here would score far lower in production. It is
  published because it is informative, and ranked third because it is flattering.</p>

  <h3>Why there is no accuracy figure</h3>
  <span class="calc">(TP + TN) &divide; total <span>— not published anywhere in this repo</span></span>
  <p>Accuracy is dominated by whichever malicious-to-benign ratio was authored. Write nine benign
  cases and one malicious one, and a rule that never fires at all scores 0.90. It would measure the
  dataset rather than the rule, which is precisely the failure this harness was built to avoid.</p>

  {worked}

  <div class="box why">
    <h4>How the labelled events are built</h4>
    <p>Each rule has an <code>evals/&lt;rule&gt;/cases.yml</code> holding events written by hand.
    Every case carries a <code>why</code> justifying its label, and the loader refuses a case
    without one — an unexplained label is an assertion, not evidence.</p>
    <p style="margin-bottom:0">Benign cases must be genuine look-alikes: the same event type as the
    malicious ones, differing only where the rule is supposed to discriminate. A benign case whose
    event ID no malicious case uses is rejected, because it cannot exercise the rule's logic, and a
    set with no benign cases at all is refused outright — precision would be 1.00 by construction.
    An earlier version of this repo had exactly that problem: 15 of 16 fixtures were "expect fire",
    and the single negative was a different log channel, so it proved nothing.</p>
  </div>
</section>

<section id="thresholds">
  <h2><span class="n">07</span>Every rule declares its own bar</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Rules are not equally hard. Detecting a specific hacking tool should be near perfect;
    detecting "someone added an antivirus exclusion" cannot be, because a system administrator does
    exactly the same thing for legitimate reasons and the log entry looks identical.</p>
    <p>So each rule states, in its own file, the score it has to reach — and the build fails if it
    drops below it. Setting an easier bar is allowed. Setting one <i>silently</i> is not: without a
    written reason, the file is rejected. Every one of those reasons is printed below.</p>
  </div>
  <p>The defaults are strict — precision &ge; 0.90, recall = 1.00, FP rate &le; 0.10. Anything more
  lenient is <b>rejected at load time unless it carries a written justification</b>. {len(data['lenient'])}
  of {n_scored} rules currently run on a justified lenient threshold.</p>
  <table>
    <tr><th>rule</th><th>precision</th><th>recall</th><th>FP rate</th><th>declared bar</th></tr>
    {_threshold_rows(results, data['justifications'])}
  </table>
  <p class="muted">Thresholds live in the case files, not in the Sigma rules, so the rules stay
  portable — a threshold is a property of this harness, not of the detection.</p>
{tier_pair}
</section>

<section id="gates">
  <h2><span class="n">08</span>What CI actually checks</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Every one of the checks below runs on every change, on GitHub's machines, and any single one
    of them can stop the change from landing. The last row is the unusual one: the robot rebuilds
    every published chart, table and page from scratch and compares them to what is committed. If
    they differ, someone changed a rule without refreshing the numbers, and the build fails.</p>
  </div>
  <p>One command runs all of it: <code>uv sync --all-extras &amp;&amp; uv run detkit ci</code>, about
  twenty seconds from a clean checkout. The workflow runs the same steps split across parallel jobs.</p>
  <table>
    <tr><th>gate</th><th>what it enforces</th></tr>
    {_gate_rows()}
  </table>
  <div class="box why">
    <h4>The gate that mattered most</h4>
    <p style="margin:0">The suite originally passed while testing nothing: with no Hayabusa binary
    present every detection test skipped, and pytest exits 0 on a fully skipped run. CI now installs
    a checksum-verified pinned binary and treats <i>any</i> skip as a failure. A test suite that
    cannot fail is worse than no test suite, because it manufactures confidence.</p>
  </div>
</section>

<section id="decisions">
  <h2><span class="n">09</span>Design decisions on record</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Every significant choice is written down with the options that were considered and the reason
    one won — including the ones that were rejected. Knowing when <i>not</i> to add something is
    half of engineering, and it is invisible unless you record it.</p>
  </div>
  <ul class="spaced">{adrs}</ul>
  <h3>Other choices worth stating</h3>
  <ul class="spaced">
    <li><b>The third-party corpus is demoted, not deleted.</b> A pinned copy of the public SigmaHQ
    Windows corpus ({data['vend_rules']:,} rules, {vend_rate_pct} convert rate) is run through the
    same conversion pipeline and contributes {data['vend_tech']} further techniques to the map — but
    it is reported separately and held to none of the fixture or eval gates. Folding it into the
    headline would turn {n_rules} authored rules into a four-figure number that means nothing.
    The headline is deliberately the smaller, true number.</li>
    <li><b>Published artifacts are diffed, not trusted.</b> Every generated file is rebuilt in CI and
    compared to what is committed. There is no ratchet file and no manual metric anywhere: if a rule
    changes and the numbers move, the build fails until the new numbers are committed deliberately.</li>
    <li><b>Bad results stay published.</b> Rules that score badly are either fixed with
    discriminators, reclassified with a written argument, or left visible with their real numbers.
    Deleting an inconvenient measurement is the one move that would make this whole repo
    worthless.</li>
  </ul>
</section>

<section id="limits">
  <h2><span class="n">10</span>Honest limits</h2>
  <div class="plain"><span class="tagp">In plain English</span>
    <p>Everything below is a genuine weakness, written here on purpose. A limitation somebody else
    discovers reads very differently from one you documented yourself.</p>
  </div>
  <div class="box limit">
    <h4>What this does not prove</h4>
    <ul class="spaced" style="margin-bottom:0">
      <li><b>The labelled events are synthetic.</b> They are written to be realistic look-alikes,
      but they are mine. They establish that a rule's logic discriminates; they cannot establish
      what its volume would be on a real estate.</li>
      <li><b>Case sets are small.</b> {data['n_cases']} events across {n_scored} rules. Enough to
      catch a rule that matches an event ID and nothing else — not enough for a confidence
      interval.</li>
      <li><b>Some rules are irreducibly noisy, and stay.</b> Clearing the event log is one event
      with no distinguishing fields; its case set scores an FP rate of 1.00 and it is still shipped
      at <code>high</code>, on a base-rate argument — the behaviour is rare enough in practice that
      the alert is worth the noise. Others were demoted to <code>informational</code> instead, so
      they remain available for hunting without paging anyone. Both calls are argued in the case
      files rather than hidden by deleting the rule.</li>
      <li><b>Sentinel's <code>SecurityEvent</code> schema has no <code>PreAuthType</code>
      column</b>, so the Kerberos rules cannot bind there without EventData parsing. KQL conversion
      therefore targets Microsoft XDR on the process-creation subset. That is a platform limit,
      documented rather than pretended away.</li>
      <li><b>The cloud rules are not proven against a real tenant.</b> Entra ID telemetry has no
      public captures, so those four rules carry the schema-verified tier described above: measured
      logic and a validated query, but no replay. That is a real difference from the Windows rules
      and it is labelled as one everywhere it appears.</li>
      <li><b>Deployment is a static site.</b> Nothing here provisions a SIEM. The rules compile to
      deployable, source-bound queries; actually running them in an estate is out of scope, and
      Terraform with nothing behind it would be set dressing.</li>
    </ul>
  </div>
</section>

<section id="repo">
  <h2><span class="n">11</span>Repo map</h2>
  <dl class="grid">
    <dt><code>detections/</code></dt><dd>The {n_rules} authored Sigma rules, split by telemetry:
      <code>windows/</code> and <code>identity/entra/</code>. Everything is gated on these, though
      not every rule can be gated the same way — see the evidence tiers above.</dd>
    <dt><code>evals/</code></dt><dd>Labelled events and declared thresholds, one directory per rule,
      plus the generated <code>results.json</code>.</dd>
    <dt><code>tests/</code></dt><dd>pytest: unit tests over the tooling, the Hayabusa harness, and
      the per-rule fixture manifests pinning public EVTX by hash.</dd>
    <dt><code>src/detkit/</code></dt><dd>The tooling package behind the <code>detkit</code> command —
      validation, evaluation, conversion, coverage, and the generators for this site.</dd>
    <dt><code>pipelines/</code></dt><dd>pySigma processing pipelines: the field maps that bind
      generic Sigma categories to a platform's real channels and column names.</dd>
    <dt><code>vendored/</code></dt><dd>The pinned third-party SigmaHQ corpus and its report. Not
      authored here, not gated.</dd>
    <dt><code>coverage/</code></dt><dd>The ATT&amp;CK Navigator layer and the rendered heat map.</dd>
    <dt><code>docs/</code></dt><dd>The detection lifecycle and the ADRs.</dd>
  </dl>
  <p>Run it yourself: <code>uv sync --all-extras</code> then <code>uv run detkit ci</code>. The
  pinned test engine is downloaded and checksum-verified on first run; nothing else is needed.</p>
</section>

<section id="faq">
  <h2><span class="n">12</span>Questions this invites</h2>
  <dl class="qa">
    <dt>Why measure detections at all — isn't a rule either right or wrong?</dt>
    <dd>No. Every detection is a trade between missing the attack and drowning the analyst, and the
    trade is different for every behaviour. Without measurement that trade is made by whoever wrote
    the rule, silently, and re-made every time someone edits it. Numbers make it a decision.</dd>

    <dt>Why is FP rate the headline instead of precision?</dt>
    <dd>Because precision moves with the malicious-to-benign ratio of the dataset, and in a
    hand-authored case set I choose that ratio. FP rate looks only at benign events, so I cannot
    flatter it by writing more attacks. When a metric can be improved by editing the test data
    rather than the rule, it should not lead.</dd>

    <dt>You have rules with an FP rate of 1.00. Why ship them?</dt>
    <dd>Because the alternative is worse. Clearing the security event log produces one event with
    nothing in it to discriminate on — any rule for it fires on every instance, benign or not. What
    matters is the base rate: it almost never happens legitimately, so the alert is cheap in
    practice even though it is undiscriminating in the lab. That argument is written into the case
    file, and rules where the argument does not hold were demoted to informational instead.</dd>

    <dt>Why two engines rather than one?</dt>
    <dd>They answer different questions and check each other. Hayabusa proves a rule works against
    real Windows telemetry — right channel, right field names. The SQL evaluator scores the logic
    over labelled events, which real captures cannot do, because a capture has no benign
    counterfactual in it. Where two independent implementations of Sigma disagree about the same
    rule, something is wrong and I want the build to say so.</dd>

    <dt>What stops the published numbers going stale?</dt>
    <dd>CI regenerates every artifact and diffs it against what is committed. Generator output is a
    pure function of the corpus, so a diff means the repo changed and the published numbers no
    longer describe it. That includes this page.</dd>

    <dt>What was actually hard?</dt>
    <dd>Making failure possible. The first version of this repo passed its build while testing
    nothing, reported coverage it did not have, and had exactly one negative test case — which was
    for a different log channel and could never have failed. Most of the engineering since has been
    removing ways for the build to be green without being true.</dd>

    <dt>Only {n_rules} rules? SigmaHQ has thousands.</dt>
    <dd>A pinned copy of SigmaHQ's Windows corpus is in this repository too, and it is reported
    separately on purpose. The authored rules are the ones held to every gate: a pinned capture or
    a mandatory case set, a declared threshold with a written justification, a bound query, an
    ATT&amp;CK tag that resolves. {n_rules} rules that each carry that evidence say more about how
    someone works than a thousand copied ones. The corpus is deliberately the smaller, true
    number.</dd>

    <dt>Is this finished, or abandoned?</dt>
    <dd>Finished, and the boundary is argued rather than implied — ADR 0007 names the two things
    that were on the list and declines both: more cloud rules of a shape already proven four times
    over, and a Splunk container replaying the same pinned captures the existing gates already
    check. What a live SIEM would genuinely add is behaviour under production volume, which is not
    available here, so shipping one would produce a screenshot rather than evidence. The gates keep
    running; the corpus is closed.</dd>
  </dl>
</section>

</main>
<footer>
  Generated by <code>detkit dashboard</code> from the corpus, the case files and the CI definition —
  do not edit <code>site/about.html</code> by hand; edit <code>src/detkit/about.py</code>.
  <a href="{GH_BASE}README.md">Source on GitHub →</a>
</footer>
</body>
</html>
"""


def run() -> int:
    SITE.mkdir(parents=True, exist_ok=True)
    SITE_ABOUT.write_text(render(collect()), encoding="utf-8")
    print(f"Wrote {SITE_ABOUT.relative_to(REPO)} — how-it-works page.")
    return 0
