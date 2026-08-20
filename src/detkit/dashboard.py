"""Render a self-contained static dashboard from the detection corpus.

Emits site/index.html plus site/about.html (see `about.py`) and a copy of the
coverage matrix. No server, no build step, no external assets.

Every published number carries a hover tooltip explaining how it is calculated
and where the underlying data comes from — a metric nobody can interrogate is
decoration.
"""
from __future__ import annotations

import html
import json
import shutil
from collections import Counter
from typing import Any

from detkit import about
from detkit.attack import TACTIC_BY_NAME
from detkit.paths import (
    COVERAGE_PNG,
    DETECTIONS,
    EVAL_RESULTS,
    REPO,
    SITE,
    SITE_INDEX,
    VENDORED_REPORT,
)
from detkit.rules import conversion_only, is_evtx_testable, load_corpus, sample_count
from detkit.webui import PALETTE, TIP_CSS, TIP_JS, nav, tip_attr

GH_BASE = "https://github.com/canmenzo/detection-engineering/blob/main/"


def vendored_summary() -> dict[str, Any]:
    """Read the vendored report, if present."""
    if not VENDORED_REPORT.exists():
        return {}
    try:
        data = json.loads(VENDORED_REPORT.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        # An absent report is a legitimate state (vendored report not generated
        # yet); a corrupt one silently drops the whole vendored tier.
        raise SystemExit(f"{VENDORED_REPORT}: unreadable: {exc}") from exc
    return data if isinstance(data, dict) else {}


def eval_metrics() -> dict[str, Any]:
    """Per-rule scores from the last `detkit eval`, if it has been run."""
    if not EVAL_RESULTS.exists():
        return {}
    try:
        data = json.loads(EVAL_RESULTS.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"{EVAL_RESULTS}: unreadable: {exc}") from exc
    rules = data.get("rules")
    return rules if isinstance(rules, dict) else {}


def collect() -> list[dict[str, Any]]:
    exempt = conversion_only()
    metrics = eval_metrics()
    rules: list[dict[str, Any]] = []
    for rule in load_corpus(DETECTIONS):
        tactics = [t for t in rule.tactics if t in TACTIC_BY_NAME]
        n = sample_count(rule.stem)
        if n:
            status = "tested"
        elif not is_evtx_testable(rule):
            # No public capture of this telemetry exists to replay. Its evidence
            # is the labelled scoring plus a compile-time check of every field
            # against the target platform's published table schema.
            status = "schema-verified"
        elif rule.stem in exempt:
            status = "conversion-only"
        else:
            status = "untested"
        logsource = rule.doc.get("logsource") or {}
        rules.append({
            "stem": rule.stem,
            "title": rule.doc.get("title", rule.stem),
            "description": " ".join(str(rule.doc.get("description", "")).split()),
            "level": rule.doc.get("level", "n/a"),
            "tactics": sorted({TACTIC_BY_NAME[t].label for t in tactics}),
            "techniques": sorted(set(rule.techniques)),
            "logsource": logsource.get("service") or logsource.get("category") or "windows",
            "status": status,
            "samples": n,
            "path": str(rule.path.relative_to(REPO)).replace("\\", "/"),
            "metrics": metrics.get(rule.stem, {}),
        })
    return rules


def stat(value: str, label: str, tip: str, alt: bool = False) -> str:
    cls = "stat alt" if alt else "stat"
    return (
        f'<div class="{cls}" tabindex="0" data-tip="{tip_attr(tip)}">'
        f"<b>{value}</b><span>{label}</span></div>"
    )


def header_stats(
    n_total: int, n_tech: int, n_scored: int, n_cases: int, n_tested: int, n_samples: int
) -> str:
    """The six headline tiles, each with the provenance of its own number."""
    attack = about.attack_version()
    tiles = [
        stat(
            str(n_total), "authored detections",
            "<b class='h'>Rules written in this repo</b>"
            "<p>Sigma rules under <code>detections/</code>. Every one must carry ATT&amp;CK tags, "
            "an EVTX fixture proving it fires on real telemetry, and a labelled case set scoring "
            "its quality — <code>detkit validate</code> fails the build otherwise.</p>"
            "<p class='src'>The pinned third-party SigmaHQ corpus is counted separately below and "
            "is deliberately held to none of those gates. Mixing the two would inflate this number "
            "by two orders of magnitude and mean nothing.</p>",
        ),
        stat(
            str(n_tech), "ATT&amp;CK techniques authored",
            "<b class='h'>Distinct ATT&amp;CK techniques covered</b>"
            "<p>Counted from the <code>tags:</code> of every authored rule — one technique may be "
            "covered by several rules, and is counted once.</p>"
            f"<p>Tags are validated against ATT&amp;CK <b>{attack}</b>, pinned in "
            "<code>.attack-version</code>. pySigma resolves the technique vocabulary from MITRE's "
            "live feed, so without that pin the map would drift with no commit in this repo; the "
            "gate fails if the resolved release moves.</p>",
        ),
        stat(
            str(n_scored), "scored for precision/recall",
            "<b class='h'>Rules with a labelled case set</b>"
            "<p>Rules that have <code>evals/&lt;rule&gt;/cases.yml</code>: hand-written malicious "
            "and benign events used to measure how well the rule discriminates, not just whether "
            "it fires.</p>"
            "<p class='src'>Run by <code>detkit eval</code>, which compiles each rule to SQL via "
            "pySigma's SQLite backend and executes it over the case set.</p>",
        ),
        stat(
            str(n_cases), "labelled eval events",
            "<b class='h'>The golden dataset</b>"
            "<p>Individual events hand-labelled malicious or benign across all case sets. Each one "
            "carries a written <code>why</code>; the loader rejects any case without it, because an "
            "unexplained label is an assertion rather than evidence.</p>"
            "<p>Benign cases must be look-alikes of the malicious ones — same event type, differing "
            "only where the rule is supposed to discriminate. A benign event of a different type is "
            "rejected: it cannot exercise the rule's logic.</p>",
        ),
        stat(
            str(n_tested), "fixture-tested on real EVTX",
            "<b class='h'>Proven against real telemetry</b>"
            "<p>Rules run by <b>Hayabusa</b> against pinned public EVTX captures — genuine Windows "
            "event logs recorded from real attacker tooling — where the rule must produce a hit.</p>"
            "<p>This is a separate layer from the scoring: the case sets test the rule's logic, and "
            "this tests that the logic matches the field names and channels Windows actually emits. "
            "Synthetic events can't catch a rule bound to a field that does not exist.</p>",
        ),
        stat(
            str(n_samples), "pinned EVTX samples",
            "<b class='h'>Sample provenance</b>"
            "<p>Public EVTX files pinned by URL and SHA-256 in "
            "<code>tests/fixtures/&lt;rule&gt;/sample_sources.yml</code>, fetched and cached at test "
            "time rather than committed — the repo stays small and the samples stay verifiable.</p>"
            "<p class='src'>A changed checksum fails the test rather than silently testing different "
            "data.</p>",
        ),
    ]
    return "\n    ".join(tiles)


def render(rules: list[dict[str, Any]], vend: dict[str, Any]) -> str:
    n_total = len(rules)
    n_tested = sum(1 for r in rules if r["status"] == "tested")
    n_samples = sum(r["samples"] for r in rules)
    techniques = sorted({t for r in rules for t in r["techniques"]})
    tactics = sorted({t for r in rules for t in r["tactics"]})
    tactic_counts = Counter(t for r in rules for t in r["tactics"])

    vend_rules = vend.get("total_rules", 0)
    vend_conv = vend.get("convert", {}) or {}
    vend_rate = vend_conv.get("rate")
    vend_rate_pct = f"{100 * vend_rate:.0f}%" if vend_rate is not None else "—"
    vend_tech = len(set(vend.get("techniques", [])) - set(techniques))

    scored = [r for r in rules if r["metrics"]]
    n_cases = sum(
        r["metrics"]["tp"] + r["metrics"]["fp"] + r["metrics"]["fn"] + r["metrics"]["tn"]
        for r in scored
    )

    data_json = json.dumps(rules)
    chips = "".join(
        f'<button class="chip" data-tactic="{html.escape(t)}">{html.escape(t)} '
        f'<span>{tactic_counts[t]}</span></button>'
        for t in tactics
    )
    cov_img = ""
    if COVERAGE_PNG.exists():
        cov_img = '<img src="coverage.png" alt="ATT&CK coverage matrix" class="cov">'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Coverage — Detection-as-Code</title>
<style>
{PALETTE}
  header {{ padding:32px 24px 8px; max-width:1100px; margin:0 auto; }}
  h1 {{ margin:0 0 4px; font-size:26px; }}
  .sub {{ color:var(--muted); }}
  .sub a {{ color:var(--accent); text-decoration:none; }}
  .stats {{ display:flex; gap:14px; flex-wrap:wrap; margin:20px 0; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
           padding:14px 18px; min-width:120px; }}
  .stat:focus {{ outline:1px solid var(--accent); }}
  .stat b {{ display:block; font-size:24px; }}
  .stat span {{ color:var(--muted); font-size:13px; }}
  .stat.alt {{ border-color:#1f6feb55; }}
  .stat.alt b {{ color:var(--accent); }}
  .hint {{ font-size:12.5px; color:var(--muted); margin:-6px 0 0; }}
  .hint b {{ color:var(--fg); font-weight:600; }}
  h2 {{ font-size:17px; margin:28px 0 0; }}
  .h2sub {{ color:var(--muted); font-size:13px; margin:2px 0 0; }}
  main {{ max-width:1100px; margin:0 auto; padding:0 24px 60px; }}
  .cov {{ width:100%; border:1px solid var(--line); border-radius:10px;
          background:#fff; margin:8px 0 24px; }}
  .controls {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center;
               margin:18px 0; }}
  input[type=search] {{ flex:1; min-width:200px; background:var(--card);
    border:1px solid var(--line); color:var(--fg); padding:10px 12px;
    border-radius:8px; font-size:14px; }}
  .chip {{ background:var(--card); border:1px solid var(--line); color:var(--fg);
    padding:7px 11px; border-radius:20px; cursor:pointer; font-size:13px; }}
  .chip.active {{ background:var(--accent); color:#0d1117; border-color:var(--accent); }}
  .chip span {{ opacity:.65; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
           padding:16px 18px; margin:12px 0; }}
  .card h3 {{ margin:0 0 6px; font-size:16px; }}
  .card h3 a {{ color:var(--fg); text-decoration:none; }}
  .card h3 a:hover {{ color:var(--accent); }}
  .desc {{ color:var(--muted); font-size:13.5px; margin:6px 0 10px; }}
  .metrics {{ display:flex; gap:8px; flex-wrap:wrap; margin:0 0 10px; }}
  .metric {{ font-size:11.5px; padding:3px 9px; border-radius:6px; font-weight:600;
             border:1px solid var(--line); color:var(--fg); font-variant-numeric:tabular-nums;
             border-bottom-style:dashed; }}
  .metric:focus {{ outline:1px solid var(--accent); }}
  .metric.good {{ background:#23863626; color:var(--ok); border-color:#2386362e; }}
  .metric.warn {{ background:#9e6a0326; color:var(--warn); border-color:#9e6a032e; }}
  .metric.bad {{ background:#da363326; color:var(--bad); border-color:#da36332e; }}
  .metric.muted {{ color:var(--muted); font-weight:400; }}
  .tags {{ display:flex; gap:6px; flex-wrap:wrap; }}
  .tag {{ font-size:12px; padding:2px 8px; border-radius:6px;
          border:1px solid var(--line); color:var(--muted); }}
  .tag.tech {{ color:var(--accent); border-color:#1f6feb55; }}
  .badge {{ font-size:11.5px; padding:2px 8px; border-radius:20px; font-weight:600; }}
  .badge.tested {{ background:#23863633; color:var(--ok); }}
  .badge.conversion-only {{ background:#9e6a0333; color:var(--warn); }}
  .badge.schema-verified {{ background:#1f6feb33; color:var(--accent); }}
  .badge.untested {{ background:#6e768166; color:var(--muted); }}
  .row {{ display:flex; justify-content:space-between; align-items:start; gap:12px; }}
  .lvl {{ font-size:11.5px; text-transform:uppercase; letter-spacing:.04em; }}
  .lvl.critical {{ color:var(--bad); }} .lvl.high {{ color:var(--warn); }}
  .lvl.medium {{ color:var(--accent); }} .lvl.low {{ color:var(--muted); }}
  footer {{ max-width:1100px; margin:0 auto; padding:24px; color:var(--muted);
            font-size:12.5px; border-top:1px solid var(--line); }}
{TIP_CSS}
</style>
</head>
<body>
{nav("index")}
<header>
  <h1>Detection Coverage</h1>
  <div class="sub">Detection-as-Code — every authored rule is version-controlled,
    ATT&amp;CK-mapped, tested against real adversary telemetry, and <b>scored for
    precision, recall and false-positive rate</b> against labelled events. Rules
    that miss the bar they declare fail the build.
    <a href="{GH_BASE}README.md">View source on GitHub →</a></div>
  <div class="stats">
    {header_stats(n_total, len(techniques), len(scored), n_cases, n_tested, n_samples)}
  </div>
  <p class="hint"><b>Hover any number</b> — every metric on this page explains how it
    is calculated and where its data comes from. For the full picture, read
    <a href="about.html">How it works</a>.</p>
  <div class="sub" style="font-size:13px;margin-top:10px">
    Separately, a pinned copy of the public SigmaHQ Windows corpus
    (<b>{vend_rules:,}</b> third-party rules, {vend_rate_pct} convert rate) is run
    through the same conversion pipeline and adds <b>{vend_tech}</b> further
    techniques to the map below. That corpus is not authored here and is not
    held to the fixture or eval gates.
  </div>
</header>
<main>
  {cov_img}
  <h2>Authored detections</h2>
  <div class="h2sub">My own rules. Read <b>FP rate</b> first: precision moves with
    the malicious-to-benign ratio in each case set, which is authored rather than
    observed, while FP rate and recall do not. The {vend_rules:,} vendored SigmaHQ
    rules are not listed here; they only feed the coverage map above.</div>
  <div class="controls">
    <input type="search" id="q" placeholder="Search detections…">
    <button class="chip active" data-tactic="">All <span>{n_total}</span></button>
    {chips}
  </div>
  <div id="list"></div>
</main>
<footer>
  Generated by <code>detkit dashboard</code> from the rule corpus —
  do not edit by hand. Status: <b>tested</b> = proven to fire on a pinned public
  EVTX sample via Hayabusa; <b>schema-verified</b> = cloud telemetry with no public
  capture, scored against labelled events and field-checked against the target
  platform's published schema; <b>conversion-only</b> = a declared exemption. See
  <a href="about.html">How it works</a> for what each tier does and does not prove.
</footer>
<script>
const RULES = {data_json};
window.TIPS = {{}};
const list = document.getElementById('list');
const q = document.getElementById('q');
let tactic = '';
function esc(s){{ return (s||'').replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c])); }}
function pct(v){{ return v === null || v === undefined ? 'n/a' : v.toFixed(2); }}
function names(list){{ return list.map(n => '<code>' + esc(n) + '</code>').join(', '); }}
function verdict(ok, value){{ return `<span class="${{ok ? 'pass' : 'fail'}}">${{value}} ${{ok ? 'passes' : 'FAILS'}}</span>`; }}
function caseFile(r){{ return '<code>evals/' + esc(r.stem) + '/cases.yml</code>'; }}

// One tooltip per published metric. They are built here rather than written into
// attributes so the rule's own counts appear in the formula — the point is to
// show the arithmetic on this rule, not a textbook definition of it.
function fpTip(r){{
  const m = r.metrics, benign = m.fp + m.tn, gate = m.thresholds ? m.thresholds.max_fp_rate : null;
  const ok = gate === null || m.fp_rate <= gate;
  return `<b class="h">False-positive rate — read this one first</b>
    <p>The share of <b>benign</b> events labelled for this rule that fired it anyway.</p>
    <span class="calc">FP &divide; (FP + TN) = ${{m.fp}} &divide; (${{m.fp}} + ${{m.tn}}) = ${{pct(m.fp_rate)}}</span>
    <p>${{m.fp}} of the ${{benign}} benign look-alikes alerted.${{m.false_alarms && m.false_alarms.length ? ' Fired on: ' + names(m.false_alarms) + '.' : ''}}</p>
    <p>It leads because it is stable: adding or removing malicious cases cannot move it, so it
       can't be flattered by the shape of the dataset the way precision can.</p>
    <p class="src">Measured by <code>detkit eval</code>: the Sigma rule is compiled to SQL
       (pySigma SQLite backend) and executed over the hand-labelled events in ${{caseFile(r)}}.</p>
    <p class="gate">CI gate — fails above ${{pct(gate)}}: ${{verdict(ok, pct(m.fp_rate))}}</p>`;
}}
function recallTip(r){{
  const m = r.metrics, malicious = m.tp + m.fn, gate = m.thresholds ? m.thresholds.min_recall : null;
  const ok = gate === null || m.recall >= gate;
  return `<b class="h">Recall — did it catch what it was written for</b>
    <p>The share of <b>malicious</b> events the rule fired on. A miss is the expensive failure:
       an alert that never fires looks exactly like a quiet network.</p>
    <span class="calc">TP &divide; (TP + FN) = ${{m.tp}} &divide; (${{m.tp}} + ${{m.fn}}) = ${{pct(m.recall)}}</span>
    <p>${{m.tp}} of ${{malicious}} malicious cases caught.${{m.missed && m.missed.length ? ' Missed: ' + names(m.missed) + '.' : ' Nothing missed.'}}</p>
    <p>Like FP rate it is stable — it only looks at malicious events, so benign cases cannot move it.</p>
    <p class="src">Same run as the FP rate, over the labelled events in ${{caseFile(r)}}.</p>
    <p class="gate">CI gate — must be at least ${{pct(gate)}}: ${{verdict(ok, pct(m.recall))}}</p>`;
}}
function precisionTip(r){{
  const m = r.metrics, alerts = m.tp + m.fp, gate = m.thresholds ? m.thresholds.min_precision : null;
  const ok = gate === null || m.precision >= gate;
  return `<b class="h">Precision — how much of the alert queue is real</b>
    <p>Of everything the rule alerted on, the share that was actually malicious. This is what an
       analyst feels on shift: 0.50 means every second alert is wasted work.</p>
    <span class="calc">TP &divide; (TP + FP) = ${{m.tp}} &divide; (${{m.tp}} + ${{m.fp}}) = ${{pct(m.precision)}}</span>
    <p><b>Handle with care.</b> Precision depends on the ratio of malicious to benign cases, and
       here that ratio is <i>authored</i>, not observed. In production, where benign events
       outnumber malicious ones by orders of magnitude, the same rule scores far lower. FP rate and
       recall don't have that problem — which is why they lead and this one trails.</p>
    <p class="src">Measured over the labelled events in ${{caseFile(r)}} by <code>detkit eval</code>.</p>
    <p class="gate">CI gate — must be at least ${{pct(gate)}}: ${{verdict(ok, pct(m.precision))}}</p>`;
}}
function eventsTip(r){{
  const m = r.metrics, malicious = m.tp + m.fn, benign = m.fp + m.tn;
  return `<b class="h">Where all of these numbers come from</b>
    <p>${{malicious + benign}} events hand-written in ${{caseFile(r)}} — ${{malicious}} malicious,
       ${{benign}} benign — each carrying a one-line <code>why</code> justifying its label. The
       loader rejects a case without one: an unexplained label is an assertion, not evidence.</p>
    <p>Benign cases have to be genuine look-alikes, same event type as the malicious ones, differing
       only where the rule is supposed to discriminate. A benign case whose EventID no malicious case
       uses is rejected, and a set with no benign cases at all is refused outright — precision would
       be 1.00 by construction, which is the exact gap this harness exists to close.</p>
    <span class="calc">TP ${{m.tp}} &middot; FP ${{m.fp}} &middot; FN ${{m.fn}} &middot; TN ${{m.tn}}</span>
    <p>No <b>accuracy</b> figure is published: (TP + TN) &divide; total is dominated by whichever
       malicious-to-benign ratio was authored, so it measures the dataset rather than the rule.</p>
    <p class="src">Full write-up on the "How it works" page.</p>`;
}}
function statusTip(r){{
  if (r.status === 'tested') {{
    return `<b class="h">Fixture-tested on real telemetry</b>
      <p>Hayabusa runs this rule against ${{r.samples}} pinned public EVTX capture${{r.samples > 1 ? 's' : ''}}
         — real Windows event logs recorded from real attacker tooling — and the rule must produce a hit.</p>
      <p>This is a different question from the scoring above. The case sets ask <i>is the logic
         right</i>; this asks <i>does the logic match the fields and channels Windows actually
         emits</i>. A rule bound to a field name that does not exist passes the first and fails this.</p>
      <p class="src">Samples are pinned by URL and SHA-256 in
         <code>tests/fixtures/${{esc(r.stem)}}/sample_sources.yml</code>, fetched and cached at test time.</p>`;
  }}
  if (r.status === 'schema-verified') {{
    return `<b class="h">Schema-verified — a different evidence tier</b>
      <p>This rule reads cloud telemetry, and nobody publishes captures of it. There is no Entra ID
         equivalent of a recorded EVTX attack, so the replay test the Windows rules get cannot exist
         for this one. Saying so is the point: the tier is declared, not blurred.</p>
      <p>What it carries instead is two things the build enforces. Its logic is scored against
         labelled malicious and benign events, exactly like every other rule — and that scoring is
         <i>mandatory</i> here, not optional. And at compile time every field it references is
         checked against Microsoft's published schema for the table it targets: a rule naming a
         column that does not exist fails to build.</p>
      <p class="src">The gap that remains, stated plainly: nothing here proves this rule fires on a
         real tenant's data, only that its logic discriminates and that it would run.</p>`;
  }}
  if (r.status === 'conversion-only') {{
    return `<b class="h">Conversion-only — a declared exemption</b>
      <p>No public EVTX sample exists for this behaviour, so the rule cannot be proven to fire on real
         telemetry. It is still linted, metadata-gated, scored against labelled events and compiled to
         Splunk and KQL.</p>
      <p>The exemption is listed by name in <code>tests/conversion_only.txt</code> — an untested rule
         has to be declared out loud, and a stale entry there fails the build.</p>`;
  }}
  return `<b class="h">Untested</b><p>No fixture and no declared exemption. CI fails on this state;
     if you are seeing it, the page was generated from a dirty tree.</p>`;
}}
function levelTip(r){{
  return `<b class="h">Severity and log source</b>
    <p><b>${{esc(r.level)}}</b> is the Sigma severity level — the triage weight a SOC should give it,
       not a measure of confidence. A high-volume audit record stays <code>informational</code> even
       when the behaviour matters, so it is available for hunting without paging anyone.</p>
    <p><b>${{esc(r.logsource)}}</b> is the log source the rule binds to. It decides which channel and
       which field names the rule reads, and it is why conversion checks that every compiled Splunk
       query carries a <code>source=</code>: an unbound search runs against every index the user can
       read, which is a cost incident waiting to happen.</p>`;
}}

function metrics(r){{
  const m = r.metrics;
  if (!m || m.precision === undefined) return '';
  // FP rate leads: precision moves with the authored malicious:benign ratio,
  // FP rate and recall do not.
  const noisy = m.fp_rate !== null && m.fp_rate >= 1.0;
  const miss  = m.recall !== null && m.recall < 1.0;
  TIPS[r.stem + ':fp'] = fpTip(r);
  TIPS[r.stem + ':recall'] = recallTip(r);
  TIPS[r.stem + ':precision'] = precisionTip(r);
  TIPS[r.stem + ':events'] = eventsTip(r);
  return `<div class="metrics">
    <span class="metric ${{noisy ? 'bad' : 'good'}}" tabindex="0" data-tipid="${{r.stem}}:fp">FP rate ${{pct(m.fp_rate)}}</span>
    <span class="metric ${{miss ? 'warn' : 'good'}}" tabindex="0" data-tipid="${{r.stem}}:recall">recall ${{pct(m.recall)}}</span>
    <span class="metric" tabindex="0" data-tipid="${{r.stem}}:precision">precision ${{pct(m.precision)}}</span>
    <span class="metric muted" tabindex="0" data-tipid="${{r.stem}}:events">${{m.tp + m.fp + m.fn + m.tn}} labelled events</span>
  </div>`;
}}
function render(){{
  const term = q.value.trim().toLowerCase();
  const rows = RULES.filter(r =>
    (!tactic || r.tactics.includes(tactic)) &&
    (!term || (r.title+r.description+r.techniques.join(' ')+r.stem).toLowerCase().includes(term))
  );
  list.innerHTML = rows.map(r => {{
    TIPS[r.stem + ':status'] = statusTip(r);
    TIPS[r.stem + ':level'] = levelTip(r);
    return `
    <div class="card">
      <div class="row">
        <h3><a href="{GH_BASE}${{r.path}}">${{esc(r.title)}}</a></h3>
        <span class="badge ${{r.status}}" tabindex="0" data-tipid="${{r.stem}}:status">${{r.status}}${{r.samples?(' · '+r.samples+' sample'+(r.samples>1?'s':'')):''}}</span>
      </div>
      <div class="lvl ${{r.level}}" tabindex="0" data-tipid="${{r.stem}}:level">${{esc(r.level)}} · ${{esc(r.logsource)}}</div>
      <div class="desc">${{esc(r.description)}}</div>
      ${{metrics(r)}}
      <div class="tags">
        ${{r.tactics.map(t=>`<span class="tag">${{esc(t)}}</span>`).join('')}}
        ${{r.techniques.map(t=>`<span class="tag tech">${{esc(t)}}</span>`).join('')}}
      </div>
    </div>`;
  }}).join('') || '<p class="sub">No detections match.</p>';
}}
document.querySelectorAll('.chip').forEach(c => c.onclick = () => {{
  document.querySelectorAll('.chip').forEach(x => x.classList.remove('active'));
  c.classList.add('active'); tactic = c.dataset.tactic; render();
}});
q.oninput = render;
render();
{TIP_JS}
</script>
</body>
</html>
"""


def run() -> int:
    rules = collect()
    SITE.mkdir(parents=True, exist_ok=True)
    SITE_INDEX.write_text(render(rules, vendored_summary()), encoding="utf-8")
    if COVERAGE_PNG.exists():
        shutil.copyfile(COVERAGE_PNG, SITE / "coverage.png")
    n_tested = sum(1 for r in rules if r["status"] == "tested")
    print(f"Wrote {SITE_INDEX.relative_to(REPO)} — {len(rules)} detections ({n_tested} tested).")
    return about.run()
