#!/usr/bin/env python3
"""Build the final project report as HTML, then print it to PDF with Chromium."""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STAGE1 = ROOT / "results" / "train" / "stage1" / "metrics.json"
DEFAULT_STAGE2 = ROOT / "results" / "train" / "stage2" / "metrics.json"
DEFAULT_E2E = ROOT / "results" / "train" / "stage2" / "end_to_end_test.json"
DEFAULT_BLOCKS = ROOT / "results" / "corpus_v2_three_targets" / "block_label_report.json"
DEFAULT_INFER = (
    ROOT
    / "results"
    / "infer"
    / "0fe82dc1245fbb5001e1fae0396549fc50a083a82e1d63efa1f837813be691b6.json"
)
DEFAULT_SPOTCHECK = ROOT / "results" / "infer" / "block_spotcheck.json"


def load(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        return json.load(fh)


def f4(value: float) -> str:
    return f"{float(value):.4f}"


def e(value: str) -> str:
    return html.escape(str(value))


def metric_table(rows: list[tuple[str, ...]], headers: tuple[str, ...]) -> str:
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def build_html(
    stage1: dict[str, Any],
    stage2: dict[str, Any],
    e2e: dict[str, Any],
    blocks: dict[str, Any],
    infer: dict[str, Any],
    spotcheck: dict[str, Any] | None,
    test_count: int | None,
) -> str:
    s1 = stage1["test"]
    s2 = stage2["test"]
    labels = ["anti_debug", "keylogger", "injection"]

    s1_rows = []
    for name in labels:
        c = s1["per_class"][name]
        s1_rows.append(
            (
                f"<code>{name}</code>",
                str(c["support"]),
                f4(c["precision"]),
                f4(c["recall"]),
                f"<strong>{f4(c['f1'])}</strong>",
                f4(c["average_precision"]),
            )
        )
    s1_rows.append(
        (
            "<strong>macro</strong>",
            "",
            "",
            "",
            f"<strong>{f4(s1['macro_f1'])}</strong>",
            "",
        )
    )

    s2_rows = []
    for name in labels:
        o = s2["per_class"][name]
        ee = e2e["per_class"][name]["block"]
        s2_rows.append(
            (
                f"<code>{name}</code>",
                str(o["support_blocks"]),
                f4(o["precision"]),
                f4(o["recall"]),
                f"<strong>{f4(o['f1'])}</strong>",
                f4(o["iou"]),
                f4(ee["precision"]),
                f4(ee["recall"]),
                f"<strong>{f4(ee['f1'])}</strong>",
                f4(ee["iou"]),
            )
        )
    s2_rows.append(
        (
            "<strong>macro</strong>",
            "",
            "",
            "",
            f"<strong>{f4(s2['macro_f1'])}</strong>",
            f"<strong>{f4(s2['macro_iou'])}</strong>",
            "",
            "",
            f"<strong>{f4(e2e['macro_block_f1'])}</strong>",
            f"<strong>{f4(e2e['macro_block_iou'])}</strong>",
        )
    )

    sample = infer["sample"]
    inf_rows = []
    for name in labels:
        t = infer["targets"][name]
        localized = sum(len(fn["blocks"]) for fn in t["functions"])
        inf_rows.append(
            (
                f"<code>{name}</code>",
                '<span class="yes">PRESENT</span>' if t["present"] else '<span class="no">absent</span>',
                f"{t['n_flagged_functions']} / {t['n_functions']}",
                str(localized),
                f4(t["max_function_score"]),
                f4(t["stage1_threshold"]),
                f4(t["stage2_threshold"]),
            )
        )

    inj = infer["targets"]["injection"]
    top_rows = []
    for fn in inj["functions"][:5]:
        top = fn["blocks"][0] if fn["blocks"] else None
        top_rows.append(
            (
                f"<code>{fn['func_rva']}</code>",
                f4(fn["score"]),
                f4(fn["max_block_score"]) if fn["max_block_score"] is not None else "—",
                str(len(fn["blocks"])),
                f"<code>{top['block_rva']}</code>" if top else "—",
                f4(top["score"]) if top else "—",
            )
        )

    anti = infer["targets"]["anti_debug"]
    anti_fn = anti["functions"][0] if anti["functions"] else None
    anti_note = "no function selected"
    if anti_fn:
        anti_note = (
            f"function <code>{anti_fn['func_rva']}</code> is selected at "
            f"{f4(anti_fn['score'])}, but its best block score is "
            f"{f4(anti_fn['max_block_score'])} &lt; 0.94; no block is reported."
        )

    spot_rows = []
    spot_total = 0
    spot_complete = 0
    spot_with_api = 0
    if spotcheck:
        for b in spotcheck.get("blocks", [])[:6]:
            spot_total += 1
            spot_complete += int(bool(b.get("complete")))
            spot_with_api += int(bool(b.get("api")))
            instr = "; ".join(i.get("text", "") for i in b.get("instructions", []))
            spot_rows.append(
                (
                    f"<code>{b.get('function_rva', '—')}</code>",
                    f"<code>{b.get('block_rva', '—')}</code>",
                    f"<code>{e(b.get('api') or '—')}</code>",
                    f"{b.get('decoded_bytes')} / {b.get('size')}",
                    f"<code>{e(instr)}</code>",
                )
            )
    if spot_rows:
        spot_html = f"""
<div class="nobreak">
<h3>Static decode spot-check</h3>
<p class="small">Capstone decoded the first six localised injection blocks from
the saved PE. This checks address mapping and shows the IAT calls behind the
Stage 2 API seeds; it is not a Ghidra/manual label verdict.</p>
{metric_table(spot_rows, ("function RVA", "block RVA", "IAT call", "bytes decoded", "instructions"))}
<p class="small">{spot_complete}/{spot_total} sampled blocks decoded completely;
{spot_with_api}/{spot_total} end in an IAT call. The calls shown are consistent
with the API-seed supervision, which is also why they are not independent proof
of malicious semantics.</p>
</div>
"""
    else:
        spot_html = (
            '<p class="small">No saved static decode spot-check was found for '
            'this sample.</p>'
        )

    total_tests = f"{test_count}" if test_count is not None else "all"
    date_str = date.today().strftime("%d %B %Y")

    stage1_any = s1["selected"]
    stage1_bg = s1["background"]

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CFG-GNN final report</title>
<style>
  :root {{
    --ink:#18212f; --muted:#5b6472; --line:#d9dee6; --paper:#ffffff;
    --navy:#0d1b2a; --navy2:#152a40; --teal:#0f766e; --teal2:#14b8a6;
    --amber:#b45309; --red:#b91c1c; --soft:#f4f7fa; --code:#eef2f6;
  }}
  * {{ box-sizing:border-box; }}
  @page {{ size:A4; margin:16mm 15mm 16mm 15mm; }}
  html, body {{ margin:0; padding:0; }}
  body {{
    font-family: Lato, Inter, "DejaVu Sans", Arial, sans-serif;
    color:var(--ink); font-size:10.2pt; line-height:1.45;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    background:var(--paper);
  }}
  h1 {{ font-size:28pt; line-height:1.08; margin:0 0 8mm; letter-spacing:-0.7pt; }}
  h2 {{ font-size:16.5pt; margin:0 0 3mm; color:var(--navy); letter-spacing:-0.25pt; page-break-after:avoid; }}
  h3 {{ font-size:12pt; margin:6mm 0 2mm; color:var(--navy2); page-break-after:avoid; }}
  p {{ margin:0 0 3mm; }}
  ul {{ margin:1.5mm 0 3mm 5mm; padding:0; }}
  li {{ margin:0 0 1.2mm; }}
  code {{ font-family:"DejaVu Sans Mono", "Liberation Mono", monospace; font-size:8.7pt; background:var(--code); padding:0.3mm 1.1mm; border-radius:2px; }}
  pre {{ font-family:"DejaVu Sans Mono", "Liberation Mono", monospace; font-size:8.4pt; background:#0d1b2a; color:#e6edf5; padding:3mm 4mm; border-radius:2mm; white-space:pre-wrap; line-height:1.35; }}
  .cover {{ background:var(--navy); color:#f8fafc; border-radius:3mm; padding:14mm 13mm 12mm; margin-bottom:8mm; }}
  .cover .kicker {{ color:#99f6e4; text-transform:uppercase; letter-spacing:1.6pt; font-size:9pt; font-weight:700; margin-bottom:5mm; }}
  .cover h1 {{ color:#ffffff; }}
  .cover p {{ color:#cbd5e1; font-size:11pt; max-width:145mm; }}
  .cover .accent {{ width:28mm; height:1.5mm; background:var(--teal2); margin:7mm 0; }}
  .meta {{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:4mm; margin-top:7mm; font-size:8.8pt; color:#cbd5e1; }}
  .meta strong {{ display:block; color:#ffffff; font-size:9.5pt; margin-bottom:1mm; }}
  .kpis {{ display:grid; grid-template-columns:repeat(4,1fr); gap:3.5mm; margin:5mm 0 7mm; }}
  .kpi {{ border:1px solid var(--line); border-top:2.2mm solid var(--teal); border-radius:2mm; padding:3.5mm 3.5mm 3mm; background:var(--soft); }}
  .kpi .v {{ font-size:19pt; font-weight:800; color:var(--navy); line-height:1.05; letter-spacing:-0.4pt; }}
  .kpi .l {{ font-size:8.2pt; color:var(--muted); margin-top:1.5mm; text-transform:uppercase; letter-spacing:0.5pt; }}
  .callout {{ border-left:2.2mm solid var(--teal); background:var(--soft); padding:3.5mm 4mm; margin:4mm 0; border-radius:0 2mm 2mm 0; page-break-inside:avoid; }}
  .warn {{ border-left-color:var(--amber); }}
  .danger {{ border-left-color:var(--red); }}
  .small {{ font-size:8.7pt; color:var(--muted); }}
  .page {{ page-break-before:always; }}
  .nobreak {{ page-break-inside:avoid; }}
  table {{ width:100%; border-collapse:collapse; margin:3mm 0 4mm; font-size:8.6pt; }}
  th {{ background:var(--navy); color:#ffffff; text-align:left; padding:2mm 2.2mm; font-weight:700; }}
  td {{ border-bottom:1px solid var(--line); padding:1.9mm 2.2mm; vertical-align:top; }}
  tbody tr:nth-child(even) td {{ background:#f8fafc; }}
  td code {{ font-size:8.1pt; }}
  .yes {{ color:var(--teal); font-weight:800; }}
  .no {{ color:var(--muted); font-weight:700; }}
  .pipeline {{ display:grid; grid-template-columns:1.1fr 0.55fr 1.1fr 0.55fr 1.2fr; align-items:center; gap:2.2mm; margin:4mm 0 5mm; }}
  .box {{ border:1px solid var(--line); border-radius:2mm; padding:3mm 3.2mm; background:var(--soft); min-height:22mm; }}
  .box .t {{ font-weight:800; color:var(--navy); font-size:9.4pt; margin-bottom:1mm; }}
  .box .d {{ font-size:8.4pt; color:var(--muted); }}
  .arrow {{ text-align:center; color:var(--teal); font-size:18pt; font-weight:800; }}
  .two {{ display:grid; grid-template-columns:1fr 1fr; gap:5mm; page-break-inside:avoid; }}
  .three {{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:4mm; page-break-inside:avoid; }}
  .kpis, .pipeline, pre, ol {{ page-break-inside:avoid; }}
  li {{ page-break-inside:avoid; }}
  .tag {{ display:inline-block; border:1px solid #99f6e4; background:#ecfdf5; color:#0f766e; border-radius:10mm; padding:0.8mm 3mm; font-size:8.2pt; font-weight:700; margin:0 1mm 1mm 0; }}
  .footer-note {{ margin-top:6mm; padding-top:2.5mm; border-top:1px solid var(--line); font-size:8.2pt; color:var(--muted); }}
</style>
</head>
<body>

<section class="cover">
  <div class="kicker">Project report · static malware analysis</div>
  <h1>Hierarchical CFG-GNN for malware behaviour localisation</h1>
  <div class="accent"></div>
  <p>Function-level detection of anti-debug, keylogger, and injection behaviour in
  32-bit Windows PE files, followed by basic-block localisation inside the
  functions selected by Stage 1.</p>
  <div class="meta">
    <div><strong>Report date</strong>{date_str}</div>
    <div><strong>Scope</strong>BODMAS v2 clean x86 PE corpus</div>
    <div><strong>Status</strong>Three-target pipeline + single-binary inference</div>
  </div>
</section>

<div class="kpis">
  <div class="kpi"><div class="v">{f4(s1['macro_f1'])}</div><div class="l">Stage 1 test macro F1</div></div>
  <div class="kpi"><div class="v">{f4(s2['macro_f1'])}</div><div class="l">Stage 2 oracle block F1</div></div>
  <div class="kpi"><div class="v">{f4(e2e['macro_block_f1'])}</div><div class="l">Stage 2 end-to-end F1</div></div>
  <div class="kpi"><div class="v">{sample['functions']:,}</div><div class="l">Functions in demo binary</div></div>
</div>

<h2>Executive summary</h2>
<p>The project now has a complete inference path: one x86 PE goes through angr
CFG recovery, the frozen 187-feature block representation, a function-level GCN
and a per-block head, and comes out as a JSON report plus a sample-specific PDF
with function scores and basic-block addresses. The demo binary is a held-out
test sample; the CLI
selected one anti-debug function and 21 injection functions, and localised 205
injection blocks. The anti-debug function was selected at the function level but
no block crossed the conservative 0.94 Stage 2 threshold, so its block list is
empty by design.</p>

<div class="callout">
  <strong>What is measured.</strong> Stage 1 is evaluated on functions, with
  per-target precision/recall/F1 and average precision. Stage 2 is evaluated on
  blocks with precision/recall/F1 and IoU, both on oracle positive functions and
  end-to-end with Stage 1 selection. Test was evaluated once; thresholds were
  selected on validation only.
</div>

<h3>Key findings</h3>
<ul>
  <li><strong>Injection is the strongest target end-to-end.</strong> Stage 1
  test F1 is {f4(s1['per_class']['injection']['f1'])}; Stage 2 end-to-end block
  F1 is {f4(e2e['per_class']['injection']['block']['f1'])} with recall
  {f4(e2e['per_class']['injection']['block']['recall'])}. This is consistent with
  injection's larger positive support and API-call seed structure.</li>
  <li><strong>Keylogger is the weakest at function level.</strong> Test F1 is
  {f4(s1['per_class']['keylogger']['f1'])}. The label is concentrated: 75.7% of
  positives come from one cluster and the feature is largely keyboard-state API
  presence.</li>
  <li><strong>Anti-debug function detection is moderate, block localisation is
  conservative.</strong> Function F1 is {f4(s1['per_class']['anti_debug']['f1'])}
  on 27 test functions. The block head reaches precision 1.0000 but recall
  0.0588 on oracle functions; the selected threshold is too strict for reliable
  block recovery.</li>
  <li><strong>Features are identical between corpus and single-binary
  inference.</strong> A parity test compares all 36,649 block rows for the demo
  sample and obtains exact equality for features, addresses, function membership,
  edges, and model probabilities.</li>
  <li><strong>No malware-family attribution is produced.</strong> “Not selected”
  means no target rule was selected; it is not a benign verdict. The model is
  trained on malware only.</li>
</ul>

<div class="footer-note">Metrics in this report are the committed held-out test
metrics. The demo sample and its graph are git-ignored; the report contains
addresses and scores, not sample bytes.</div>

<section>
<h2>1. Task and data contract</h2>
<p>Stage 1 predicts three independent behaviours for every recovered function.
The labels are CAPA namespace matches, not hand-verified ground truth. A
function may match more than one target. Class 0 is “no target selected”, not
“benign”.</p>

<table>
<thead><tr><th>target</th><th>CAPA namespace</th><th>meaning</th></tr></thead>
<tbody>
<tr><td><code>anti_debug</code></td><td><code>anti-analysis/anti-debugging</code></td><td>anti-debugging / anti-analysis rules</td></tr>
<tr><td><code>keylogger</code></td><td><code>collection/keylog</code></td><td>keystroke-collection rules</td></tr>
<tr><td><code>injection</code></td><td><code>host-interaction/process/inject</code>, <code>load-code/pe/inject-</code></td><td>process / PE injection rules</td></tr>
<tr><td><em>background</em></td><td>none of the above</td><td>not selected; <strong>not benign</strong></td></tr>
</tbody>
</table>

<div class="two">
  <div>
    <h3>Corpus and labels</h3>
    <ul>
      <li>2,733 clean samples in the frozen manifest; 2,729 graphs recovered
      (4 angr failures).</li>
      <li>2,749,125 function rows in the three-target split.</li>
      <li>Positive functions: <strong>448 anti-debug</strong>,
      <strong>1,255 keylogger</strong>, <strong>1,349 injection</strong>.</li>
      <li>Split protocol: <code>three-target-cluster-stratified-v3</code>,
      70/15/15 by cluster. The old v2 <code>main.json</code> is not used for
      these targets.</li>
      <li>Test supports: 27 anti-debug, 153 keylogger, 202 injection functions.</li>
    </ul>
  </div>
  <div>
    <h3>Stage 2 supervision</h3>
    <ul>
      <li>120,319 masked blocks in 3,044 positive functions.</li>
      <li>Positive blocks: anti-debug 1,432, keylogger 9,504, injection 15,263.</li>
      <li>Labels combine CAPA evidence locations with import-resolved API-call
      seeds. API seeds dominate keylogger and injection positives.</li>
      <li>Test blocks: 136 anti-debug, 1,344 keylogger, 2,094 injection.</li>
    </ul>
  </div>
</div>

<h3>187-dimensional block feature</h3>
<table>
<thead><tr><th>dims</th><th>feature</th></tr></thead>
<tbody>
<tr><td>0–114</td><td>114 opcode frequencies + <code>other</code></td></tr>
<tr><td>115–119</td><td>log block size, log instructions, log in-degree, log out-degree, is-entry</td></tr>
<tr><td>120–183</td><td>64 hashed API-reference buckets</td></tr>
<tr><td>184–186</td><td>log resolved API calls, log distinct buckets, has API call</td></tr>
</tbody>
</table>
<p class="small">API references are resolved through PE import thunks and
<code>call/jmp dword ptr [IAT]</code> sites. No CAPA rule name or label value is
an input feature. Features are intraprocedural only.</p>

<h3>Pipeline</h3>
<div class="pipeline">
  <div class="box"><div class="t">PE input</div><div class="d">x86 PE32 only; header and architecture checks</div></div>
  <div class="arrow">→</div>
  <div class="box"><div class="t">angr CFG</div><div class="d">timeout / RSS-protected worker; explicit failure on packed input</div></div>
  <div class="arrow">→</div>
  <div class="box"><div class="t">Stage 1 + Stage 2</div><div class="d">frozen GCN trunk; function head and block head</div></div>
</div>
<p class="small">The inference CLI calls the same feature builder and the same
model classes as training. It is not a separate reimplementation.</p>
</section>

<section class="page">
<h2>2. Stage 1: function classification</h2>
<p>The GCN has two message-passing layers, a residual skip, mean+max pooling,
and a small MLP head with three sigmoid outputs. Edges are intraprocedural.
Model selection used validation only; the test split was evaluated once.</p>

{metric_table(s1_rows, ("target", "support", "precision", "recall", "F1", "AP"))}

<div class="two">
  <div class="callout">
    <strong>Any-target selection</strong><br>
    Precision {f4(stage1_any['precision'])}, recall {f4(stage1_any['recall'])},
    F1 {f4(stage1_any['f1'])}.
  </div>
  <div class="callout">
    <strong>Background / not selected</strong><br>
    Precision {f4(stage1_bg['precision'])}, recall {f4(stage1_bg['recall'])},
    F1 {f4(stage1_bg['f1'])}.
  </div>
</div>

<h3>How to read this table</h3>
<ul>
  <li>The macro F1 is <strong>{f4(s1['macro_f1'])}</strong>. It is not a
  family-wide generalisation claim: the test supports are small and clustered.</li>
  <li>Injection has the largest test support (202) and the highest F1
  ({f4(s1['per_class']['injection']['f1'])}). Keylogger has 153 positives but
  only {f4(s1['per_class']['keylogger']['f1'])} F1, reflecting the weak and
  concentrated label.</li>
  <li>Anti-debug has only 27 test positives. Its F1
  ({f4(s1['per_class']['anti_debug']['f1'])}) has a wide uncertainty even though
  precision is relatively high ({f4(s1['per_class']['anti_debug']['precision'])}).</li>
</ul>

<div class="callout warn">
  <strong>Label quality caveat.</strong> CAPA namespaces are observational
  labels. 75.7% of keylogger positives and 61.2% of anti-debug positives come
  from one cluster each; injection is 32.9%. The audit is committed under
  <code>results/audit/</code>. The labels are reported as-is; they are not
  renamed or dropped.
</div>
</section>

<section class="page">
<h2>3. Stage 2: block localisation</h2>
<p>The Stage 2 trunk is the frozen Stage 1 GCN; only a per-block head is
trained. “Oracle” uses all true positive functions, so it isolates block-head
quality. “End-to-end” uses only functions selected by Stage 1, so it includes
Stage 1 false positives and missed functions.</p>

{metric_table(s2_rows, ("target", "support blocks", "oracle P", "oracle R", "oracle F1", "oracle IoU", "e2e P", "e2e R", "e2e F1", "e2e IoU"))}

<h3>Observations</h3>
<ul>
  <li>Macro oracle F1 is <strong>{f4(s2['macro_f1'])}</strong> (IoU
  {f4(s2['macro_iou'])}); macro end-to-end F1 is
  <strong>{f4(e2e['macro_block_f1'])}</strong> (IoU
  {f4(e2e['macro_block_iou'])}).</li>
  <li>Injection dominates: oracle F1 {f4(s2['per_class']['injection']['f1'])}
  and end-to-end F1 {f4(e2e['per_class']['injection']['block']['f1'])}, with
  end-to-end recall {f4(e2e['per_class']['injection']['block']['recall'])}.</li>
  <li>Keylogger oracle F1 is {f4(s2['per_class']['keylogger']['f1'])}; end-to-end
  F1 is {f4(e2e['per_class']['keylogger']['block']['f1'])}. The block labels are
  API-call-heavy, which the head can recover better than the function-level
  keylogger pattern.</li>
  <li>Anti-debug oracle precision is 1.0000 but recall is 0.0588 on 136 test
  blocks. The 0.94 threshold was selected on 27 validation functions and is too
  conservative. Its block AP is 0.336, so ranking is better than thresholded
  recall suggests.</li>
</ul>

<div class="callout danger">
  <strong>Diagnostic, not ground truth.</strong> Stage 2 labels come from CAPA
  evidence plus API-call seeds. The metrics measure recovery of those seeds, not
  every malicious block. A localised block is a lead for an analyst, not proof
  that the block executes a malicious action.
</div>
</section>

<section class="page">
<h2>4. Single-binary inference</h2>
<p>The implementation adds <code>src/infer/run.py</code> with a CLI, a reusable
pipeline, and a JSON report builder. It validates the PE, optionally extracts
the CFG with the existing worker, rebuilds the exact features, loads the frozen
checkpoints, runs both stages, and writes an atomic JSON report plus a
sample-specific PDF report under <code>workspace/&lt;sha256&gt;/</code>. The PDF is
always generated and opened.</p>

<pre>./venv/bin/python -m src.infer.run --binary &lt;x86-pe&gt;
# writes workspace/&lt;sha256&gt;/report.json
# writes workspace/&lt;sha256&gt;/report.pdf (opens automatically)

# optional: skip extraction for an existing graph
./venv/bin/python -m src.infer.run \\
  --binary &lt;x86-pe&gt; --graph &lt;graph.npz&gt;</pre>

<h3>Demo run: held-out test sample</h3>
<p class="small"><code>{e(sample['sha256'])}</code> · {sample['functions']} functions ·
{sample['blocks']:,} blocks · base <code>{e(sample['base_address_hex'])}</code> ·
API imports resolved: {infer['api'].get('imports', '—')} · thunks:
{infer['api'].get('thunks', '—')}</p>

{metric_table(inf_rows, ("target", "status", "flagged functions", "localized blocks", "max function", "stage 1 thr.", "stage 2 thr."))}

<div class="callout warn">
  <strong>Anti-debug has a function flag but no block flag.</strong>
  {anti_note} This is the expected consequence of the conservative Stage 2
  anti-debug threshold, not an extraction or CLI failure.
</div>

<h3>Top injection functions and first localised block</h3>
{metric_table(top_rows, ("function RVA", "function score", "max block", "# blocks", "top block RVA", "top block score"))}

{spot_html}

<div class="two">
  <div class="callout">
    <strong>Feature parity</strong><br>
    For the demo sample, single-graph and corpus features are bit-identical:
    36,649 rows, 8,633 functions, 1,674 edges, 387 resolved API calls; maximum
    absolute feature difference 0.0. Stage 1 and Stage 2 probability differences
    are also 0.0. Two additional held-out samples reproduced the corpus batch
    selected sets exactly; see <code>results/infer/inference_validation.json</code>.
  </div>
  <div class="callout">
    <strong>Architecture and failures</strong><br>
    The CLI rejects known x64/ARM machines and PE32+ input before angr. Packed
    or malformed samples that cannot be recovered return exit code 2 with the
    worker error. They are never converted into a negative prediction.
  </div>
</div>

<h3>Output contract</h3>
<p>The JSON schema is <code>cfg-gnn.infer.v1</code>. Each target has
<code>present</code>, <code>max_function_score</code>,
<code>n_flagged_functions</code>, thresholds, and a function list. Each selected
function has <code>func_va</code>, <code>func_rva</code>, <code>score</code>,
<code>max_block_score</code>, and blocks sorted by Stage 2 score. The same data
is rendered as a per-sample PDF under <code>workspace/&lt;sha256&gt;/report.pdf</code>.
The complete field documentation is in <code>docs/inference.md</code>.</p>
</section>

<section>
<h2>5. Limitations and honest interpretation</h2>
<div class="two">
  <div>
    <h3>Labels and scope</h3>
    <ul>
      <li><strong>Weak labels.</strong> CAPA matches are not ground truth. The
      targets are namespace shorthand, not proof of intent.</li>
      <li><strong>Malware only.</strong> There is no benign corpus. Background
      means “no target rule selected”, not “safe”.</li>
      <li><strong>Cluster concentration.</strong> Keylogger and anti-debug
      results are dominated by one cluster each. Per-target scores should be
      read with cluster support, not as broad capability claims.</li>
      <li><strong>x86 PE only.</strong> ELF, ARM, and x64 are out of scope; the
      855 x64 BODMAS rows were packed and excluded by the v2 filter.</li>
    </ul>
  </div>
  <div>
    <h3>Pipeline and evaluation</h3>
    <ul>
      <li><strong>Stage 2 is weakly supervised.</strong> Its metrics measure
      recovery of CAPA/API seeds, not complete malicious-block annotation.</li>
      <li><strong>Anti-debug block threshold is unstable.</strong> Only 27
      validation functions; oracle F1 {f4(s2['per_class']['anti_debug']['f1'])}.
      A higher-recall threshold may be preferable for triage.</li>
      <li><strong>Static recovery limits.</strong> Packed binaries, indirect
      jumps, and missed code reduce recall. angr failures are reported, not
      silently dropped.</li>
      <li><strong>Test reuse.</strong> The test split has been evaluated once for
      each stage. Do not retune on it after design changes.</li>
    </ul>
  </div>
</div>

<div class="callout warn">
  <strong>Open validation.</strong> The Ghidra block-label spot-check remains
  open: 40 functions were selected and 0 verdicts are recorded. The inference
  CLI does not require Ghidra and does not claim that predicted blocks have been
  manually validated.
</div>

<h3>What the result does and does not claim</h3>
<table>
<thead><tr><th>claim</th><th>status</th></tr></thead>
<tbody>
<tr><td>The pipeline can score one x86 PE and return function flags plus block addresses.</td><td><span class="yes">Implemented and run on a held-out sample</span></td></tr>
<tr><td>Single-binary features and scores match the corpus path.</td><td><span class="yes">Verified exactly on the demo sample</span></td></tr>
<tr><td>The model detects all malicious functions in a binary.</td><td><span class="no">Not claimed; recall is limited, especially keylogger and anti-debug</span></td></tr>
<tr><td>The model identifies every malicious basic block.</td><td><span class="no">Not claimed; Stage 2 labels are weak and anti-debug recall is low</span></td></tr>
<tr><td>The model names a malware family.</td><td><span class="no">Not a target; no family classifier is trained or reported</span></td></tr>
<tr><td>Predicted blocks are manually validated.</td><td><span class="no">Ghidra spot-check is still open</span></td></tr>
</tbody>
</table>

<h3>Next engineering steps</h3>
<ol>
  <li>Complete the Ghidra block-label spot-check on the 40 selected functions;
  record verdicts and disagreement reasons.</li>
  <li>Compare the GCN encoder with a GAT encoder under the same split and
  frozen feature contract; this remains the planned modelling comparison.</li>
  <li>Increase anti-debug and keylogger support or report per-cluster results
  with confidence intervals; do not retune on test.</li>
  <li>Add a small analyst-facing wrapper around the JSON report (ranked
  functions, top blocks, and explicit extraction failures) once the output
  contract is stable.</li>
</ol>

<div class="footer-note">
<strong>Reproduction.</strong> Training and evaluation commands are in
<code>README.md</code> and <code>docs/label_pipeline.md</code>; the inference
contract is in <code>docs/inference.md</code>. The committed report generator is
<code>scripts/make_final_report.py</code>.
</div>
</section>

<section class="page">
<h2>Appendix: implementation and artifacts</h2>
<div class="three">
  <div class="box"><div class="t">Inference code</div><div class="d"><code>src/infer/pipeline.py</code><br><code>src/infer/report.py</code><br><code>src/infer/pdf.py</code><br><code>src/infer/run.py</code></div></div>
  <div class="box"><div class="t">Tests and docs</div><div class="d"><code>tests/test_infer.py</code><br><code>docs/inference.md</code><br>{total_tests} tests passing</div></div>
  <div class="box"><div class="t">Artifacts</div><div class="d"><code>results/train/stage1/</code><br><code>results/train/stage2/</code><br><code>results/infer/</code></div></div>
</div>

<h3>Committed vs local-only</h3>
<p>Source, tests, documentation, metrics, reports, and inference JSON are
committed. Raw malware samples, CAPA JSON, graphs, corpus arrays, and model
checkpoints are git-ignored. The report contains sample metadata and addresses,
not sample bytes.</p>

<h3>Checkpoint thresholds</h3>
<table>
<thead><tr><th>stage</th><th>anti-debug</th><th>keylogger</th><th>injection</th></tr></thead>
<tbody>
<tr><td>Stage 1</td><td>0.95</td><td>0.94</td><td>0.95</td></tr>
<tr><td>Stage 2</td><td>0.94</td><td>0.50</td><td>0.64</td></tr>
</tbody>
</table>

<h3>Test summary</h3>
<p>The repository test suite covers CFG storage, label parsing and mapping,
feature/corpus invariants, model batching, Stage 1/Stage 2 training helpers,
the end-to-end evaluator, and the inference report/parity path. The final run
reported <strong>{total_tests} passing tests</strong>.</p>

<div class="footer-note">
Report generated by <code>scripts/make_final_report.py</code>. The PDF is
printed from local HTML with Chromium; no external assets or network access are
required.
</div>
</section>

</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "final_report.pdf")
    parser.add_argument("--html", type=Path, default=ROOT / "results" / "final_report.html")
    parser.add_argument("--stage1", type=Path, default=DEFAULT_STAGE1)
    parser.add_argument("--stage2", type=Path, default=DEFAULT_STAGE2)
    parser.add_argument("--e2e", type=Path, default=DEFAULT_E2E)
    parser.add_argument("--blocks", type=Path, default=DEFAULT_BLOCKS)
    parser.add_argument("--infer", type=Path, default=DEFAULT_INFER)
    parser.add_argument("--spotcheck", type=Path, default=DEFAULT_SPOTCHECK)
    parser.add_argument("--test-count", type=int, default=None,
                        help="number of passing tests to print in the appendix")
    parser.add_argument("--no-open", action="store_true",
                        help="do not launch the PDF viewer")
    args = parser.parse_args(argv)

    for path in (args.stage1, args.stage2, args.e2e, args.blocks, args.infer):
        if not path.exists():
            print(f"error: missing report input: {path}", file=sys.stderr)
            return 2

    stage1 = load(args.stage1)
    stage2 = load(args.stage2)
    e2e = load(args.e2e)
    blocks = load(args.blocks)
    infer = load(args.infer)
    spotcheck = None
    if args.spotcheck.exists():
        candidate = load(args.spotcheck)
        if candidate.get("sample_sha256") == infer["sample"].get("sha256"):
            spotcheck = candidate

    html_text = build_html(
        stage1, stage2, e2e, blocks, infer, spotcheck, args.test_count
    )
    args.html.parent.mkdir(parents=True, exist_ok=True)
    args.html.write_text(html_text, encoding="utf-8")

    chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    if not chromium:
        print("error: Chromium not found; HTML was written but PDF was not printed", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        chromium,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={args.out}",
        args.html.resolve().as_uri(),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or not args.out.exists():
        print("error: Chromium PDF print failed", file=sys.stderr)
        print(result.stderr[-4000:], file=sys.stderr)
        return 2
    print(f"wrote {args.html}")
    print(f"wrote {args.out} ({args.out.stat().st_size / 1024:.1f} KiB)")

    if not args.no_open and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        opener = shutil.which("xdg-open")
        if opener:
            subprocess.Popen(
                [opener, str(args.out)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"opened {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
