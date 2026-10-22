#!/usr/bin/env python3
"""Per-sample PDF rendering for inference results.

The report is rendered as local HTML and printed with Chromium.  No network or
external report library is required.  The PDF is deliberately sample-specific:
it contains the target cards, selected functions, localized blocks, thresholds,
and warnings from one `cfg-gnn.infer.v1` JSON report.
"""

from __future__ import annotations

import html
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


def _e(value: Any) -> str:
    return html.escape(str(value))


def _f4(value: Any) -> str:
    if value is None:
        return "—"
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "—"


def _hex(value: Any) -> str:
    try:
        return f"0x{int(value):x}"
    except (TypeError, ValueError):
        return "—"


def _format_generated(value: Any) -> str:
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return str(value)


def _target_class(present: bool) -> str:
    return "present" if present else "absent"


def _target_card(name: str, target: dict[str, Any], stage2_enabled: bool) -> str:
    localized = sum(len(fn.get("blocks", [])) for fn in target.get("functions", []))
    localization = (
        f"{localized} localized blocks"
        if stage2_enabled
        else "block localization disabled"
    )
    state = "PRESENT" if target.get("present") else "absent"
    return f"""
<div class="card {_target_class(bool(target.get('present')))}">
  <div class="card-name">{_e(name)}</div>
  <div class="card-state">{state}</div>
  <div class="card-value">{_f4(target.get('max_function_score'))}</div>
  <div class="card-meta">{target.get('n_flagged_functions', 0)} / {target.get('n_functions', 0)} functions<br>
  {localization}</div>
</div>
"""


def _function_table(target: dict[str, Any], stage2_enabled: bool) -> str:
    funcs = [fn for fn in target.get("functions", []) if fn.get("selected")]
    if not funcs:
        return (
            '<p class="empty">No function crossed the Stage 1 threshold for this '
            "target.</p>"
        )
    rows = []
    for fn in funcs:
        max_block = _f4(fn.get("max_block_score")) if stage2_enabled else "—"
        n_blocks = len(fn.get("blocks", [])) if stage2_enabled else "—"
        rows.append(
            "<tr>"
            f"<td><code>{_hex(fn.get('func_va'))}</code></td>"
            f"<td><code>{_e(fn.get('func_rva'))}</code></td>"
            f"<td>{_f4(fn.get('score'))}</td>"
            f"<td>{max_block}</td>"
            f"<td>{n_blocks}</td>"
            "</tr>"
        )
    return f"""
<table>
<thead><tr><th>function VA</th><th>function RVA</th><th>function score</th>
<th>max block score</th><th>blocks above threshold</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
"""


def _block_section(name: str, target: dict[str, Any], stage2_enabled: bool) -> str:
    funcs = [fn for fn in target.get("functions", []) if fn.get("selected")]
    if not funcs:
        return ""
    if not stage2_enabled:
        return (
            '<p class="empty">Stage 2 was disabled for this run; no block '
            "localization was produced.</p>"
        )
    parts = [
        f'<h3 class="blocks-title">Block localization — {_e(name)}</h3>',
    ]
    for fn in funcs:
        blocks = fn.get("blocks", [])
        parts.append(
            f'<div class="function-block">'
            f'<h4><code>{_e(fn.get("func_rva"))}</code> '
            f'<span class="muted">score {_f4(fn.get("score"))}</span></h4>'
        )
        if not blocks:
            parts.append(
                '<p class="empty">No block crossed the Stage 2 threshold. '
                f'Best block score: <strong>{_f4(fn.get("max_block_score"))}</strong> '
                f'(threshold {_f4(target.get("stage2_threshold"))}).</p>'
            )
        else:
            rows = []
            for block in blocks:
                rows.append(
                    "<tr>"
                    f"<td><code>{_e(block.get('block_rva'))}</code></td>"
                    f"<td><code>{_hex(block.get('block_va'))}</code></td>"
                    f"<td>{block.get('size', '—')}</td>"
                    f"<td>{_f4(block.get('score'))}</td>"
                    "</tr>"
                )
            parts.append(
                "<table><thead><tr><th>block RVA</th><th>block VA</th>"
                "<th>size</th><th>score</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table>"
            )
        parts.append("</div>")
    return "".join(parts)


def build_sample_html(report: dict[str, Any]) -> str:
    """Render one inference JSON report as a self-contained HTML document."""
    sample = report.get("sample", {})
    targets = report.get("targets", {})
    warnings = report.get("warnings", [])
    models = report.get("models", {})
    extraction = report.get("extraction", {})
    api = report.get("api", {})
    labels = models.get("labels", list(targets))
    stage2_enabled = bool(models.get("stage2_enabled", True))

    cards = "".join(
        _target_card(name, targets.get(name, {}), stage2_enabled) for name in labels
    )
    target_sections = []
    for name in labels:
        target = targets.get(name, {})
        state = "PRESENT" if target.get("present") else "absent"
        target_sections.append(
            f"""
<section class="target">
<h2>{_e(name)} <span class="state {_target_class(bool(target.get('present')))}">{state}</span></h2>
<p class="target-meta">Stage 1 threshold {_f4(target.get('stage1_threshold'))} ·
Stage 2 threshold {_f4(target.get('stage2_threshold'))} ·
flagged {target.get('n_flagged_functions', 0)} / {target.get('n_functions', 0)} functions</p>
{_function_table(target, stage2_enabled)}
{_block_section(name, target, stage2_enabled)}
</section>
"""
        )

    warning_html = (
        "<ul>" + "".join(f"<li>{_e(w)}</li>" for w in warnings) + "</ul>"
        if warnings
        else '<p class="empty">No warnings.</p>'
    )
    extraction_kind = (
        "pre-extracted graph" if extraction.get("used_pre_extracted_graph") else "angr extraction"
    )
    summary = extraction.get("summary") or {}
    elapsed = extraction.get("elapsed_seconds")
    peak = extraction.get("peak_mb")
    extraction_bits = [extraction_kind]
    if elapsed is not None:
        extraction_bits.append(f"{float(elapsed):.1f}s")
    if peak is not None:
        extraction_bits.append(f"peak {float(peak):.0f} MiB")
    if summary.get("function_count") is not None:
        extraction_bits.append(f"{summary.get('function_count')} functions")
    if summary.get("block_count") is not None:
        extraction_bits.append(f"{summary.get('block_count')} blocks")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CFG-GNN inference — {_e(sample.get('sha256', ''))[:16]}</title>
<style>
  :root {{
    --ink:#18212f; --muted:#64748b; --line:#d9dee6; --paper:#ffffff;
    --navy:#0d1b2a; --navy2:#152a40; --teal:#0f766e; --teal2:#14b8a6;
    --amber:#b45309; --red:#b91c1c; --soft:#f4f7fa; --code:#eef2f6;
  }}
  * {{ box-sizing:border-box; }}
  @page {{ size:A4; margin:14mm 13mm 15mm 13mm; }}
  html, body {{ margin:0; padding:0; }}
  body {{
    font-family:Lato, Inter, "DejaVu Sans", Arial, sans-serif;
    color:var(--ink); font-size:9.8pt; line-height:1.4;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    background:var(--paper);
  }}
  h1 {{ font-size:24pt; line-height:1.08; margin:0 0 4mm; letter-spacing:-0.5pt; }}
  h2 {{ font-size:15pt; margin:7mm 0 2mm; color:var(--navy); page-break-after:avoid; }}
  h3 {{ font-size:11.5pt; margin:6mm 0 2mm; color:var(--navy2); page-break-after:avoid; }}
  h4 {{ font-size:10pt; margin:4mm 0 1.5mm; color:var(--navy2); page-break-after:avoid; }}
  p {{ margin:0 0 2.5mm; }}
  code {{ font-family:"DejaVu Sans Mono", "Liberation Mono", monospace; font-size:8.2pt; background:var(--code); padding:0.2mm 1mm; border-radius:2px; }}
  .header {{ background:var(--navy); color:#f8fafc; border-radius:2.5mm; padding:9mm 9mm 8mm; margin-bottom:5mm; }}
  .header .kicker {{ color:#99f6e4; text-transform:uppercase; letter-spacing:1.4pt; font-size:8.2pt; font-weight:700; margin-bottom:3mm; }}
  .header h1 {{ color:#ffffff; }}
  .header p {{ color:#cbd5e1; margin-bottom:0; }}
  .meta {{ display:grid; grid-template-columns:1.5fr 1fr 1fr; gap:3mm; margin:5mm 0 0; font-size:8.2pt; color:#cbd5e1; }}
  .meta strong {{ display:block; color:#ffffff; font-size:8.8pt; margin-bottom:0.8mm; }}
  .cards {{ display:grid; grid-template-columns:repeat(3,1fr); gap:3mm; margin:4mm 0 5mm; page-break-inside:avoid; }}
  .card {{ border:1px solid var(--line); border-top:2mm solid var(--line); border-radius:2mm; padding:3mm; background:var(--soft); }}
  .card.present {{ border-top-color:var(--teal); }}
  .card.absent {{ border-top-color:#94a3b8; }}
  .card-name {{ font-size:8pt; color:var(--muted); text-transform:uppercase; letter-spacing:0.5pt; }}
  .card-state {{ font-weight:800; font-size:9.5pt; margin:0.8mm 0; }}
  .card.present .card-state {{ color:var(--teal); }}
  .card.absent .card-state {{ color:var(--muted); }}
  .card-value {{ font-size:17pt; font-weight:800; color:var(--navy); line-height:1.05; }}
  .card-meta {{ font-size:7.8pt; color:var(--muted); margin-top:1.5mm; }}
  .state {{ font-size:8pt; border-radius:8mm; padding:0.7mm 2.5mm; vertical-align:middle; }}
  .state.present {{ color:#065f46; background:#d1fae5; }}
  .state.absent {{ color:#475569; background:#e2e8f0; }}
  .target {{ page-break-inside:auto; }}
  .target-meta {{ color:var(--muted); font-size:8.4pt; }}
  table {{ width:100%; border-collapse:collapse; margin:2.5mm 0 3mm; font-size:8.2pt; page-break-inside:auto; }}
  th {{ background:var(--navy); color:#ffffff; text-align:left; padding:1.8mm 2mm; font-weight:700; }}
  td {{ border-bottom:1px solid var(--line); padding:1.6mm 2mm; vertical-align:top; }}
  tbody tr:nth-child(even) td {{ background:#f8fafc; }}
  tr {{ page-break-inside:avoid; }}
  .blocks-title {{ margin-top:5mm; padding-top:3mm; border-top:1px solid var(--line); }}
  .function-block {{ page-break-inside:auto; }}
  .muted {{ color:var(--muted); font-weight:400; }}
  .empty {{ color:var(--muted); font-size:8.7pt; }}
  .warn {{ border-left:2mm solid var(--amber); background:#fffbeb; padding:3mm 4mm; border-radius:0 2mm 2mm 0; page-break-inside:avoid; }}
  .foot {{ margin-top:7mm; padding-top:2.5mm; border-top:1px solid var(--line); color:var(--muted); font-size:7.8pt; }}
</style>
</head>
<body>
<div class="header">
  <div class="kicker">CFG-GNN · single-binary inference</div>
  <h1>Behaviour and block localisation report</h1>
  <p>Function-level anti-debug, keylogger, and injection scores with
  basic-block localisation for one x86 PE.</p>
  <div class="meta">
    <div><strong>Sample SHA-256</strong><code>{_e(sample.get('sha256', '—'))}</code></div>
    <div><strong>Architecture</strong>{_e(sample.get('arch', '—'))}</div>
    <div><strong>Generated</strong>{_e(_format_generated(report.get('generated_at', '—')))}</div>
  </div>
</div>

<p class="small"><strong>File:</strong> <code>{_e(sample.get('path', '—'))}</code><br>
<strong>Size:</strong> {sample.get('size_bytes', '—')} bytes ·
<strong>Base:</strong> <code>{_e(sample.get('base_address_hex', '—'))}</code> ·
<strong>Functions:</strong> {sample.get('functions', '—')} ·
<strong>Blocks:</strong> {sample.get('blocks', '—')} ·
<strong>Edges:</strong> {sample.get('edges', '—')}</p>

<div class="cards">
{cards}
</div>

<div class="warn">
<strong>Interpretation.</strong> “Absent” means no function crossed the target
threshold; it is not a benign verdict. The model is trained on malware only and
does not attribute a malware family. Blocks are model-ranked candidates, not
manual ground truth.
</div>

<h2>Run metadata</h2>
<table>
<tbody>
<tr><td><strong>Extraction</strong></td><td>{_e(' · '.join(extraction_bits))}</td></tr>
<tr><td><strong>API resolution</strong></td><td>{_e(api.get('imports', '—'))} imports · {_e(api.get('thunks', '—'))} thunks · loaded={_e(api.get('loaded', '—'))}</td></tr>
<tr><td><strong>Stage 1 checkpoint</strong></td><td><code>{_e(models.get('stage1_checkpoint', '—'))}</code></td></tr>
<tr><td><strong>Stage 2 checkpoint</strong></td><td><code>{_e(models.get('stage2_checkpoint', '—'))}</code></td></tr>
<tr><td><strong>Stage 1 thresholds</strong></td><td>{_e(models.get('stage1_thresholds', '—'))}</td></tr>
<tr><td><strong>Stage 2 thresholds</strong></td><td>{_e(models.get('stage2_thresholds', '—'))}</td></tr>
</tbody>
</table>

{''.join(target_sections)}

<h2>Warnings</h2>
{warning_html}

<div class="foot">
Generated from schema <code>{_e(report.get('schema_version', '—'))}</code>.
The PDF lists Stage 1 selected functions; the JSON can additionally contain
unselected function scores when <code>--all-functions</code> is used.
</div>
</body>
</html>
"""


def find_chromium() -> str | None:
    return (
        shutil.which("chromium")
        or shutil.which("chromium-browser")
        or shutil.which("google-chrome")
    )


def render_sample_pdf(
    report: dict[str, Any],
    pdf_path: Path,
    *,
    html_path: Path | None = None,
    open_pdf: bool = False,
    timeout: float = 120.0,
) -> Path:
    """Render one sample report to PDF, optionally keeping the HTML source."""
    pdf_path = Path(pdf_path).expanduser()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    html_text = build_sample_html(report)
    chromium = find_chromium()
    if not chromium:
        raise RuntimeError("Chromium not found; cannot render the PDF report")

    if html_path is not None:
        html_path = Path(html_path).expanduser()
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html_text, encoding="utf-8")
        source = html_path
        cleanup = None
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="cfg-gnn-pdf-")
        source = Path(cleanup.name) / "report.html"
        source.write_text(html_text, encoding="utf-8")

    tmp_pdf = pdf_path.with_name(pdf_path.name + ".tmp")
    try:
        cmd = [
            chromium,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--print-to-pdf={tmp_pdf}",
            source.resolve().as_uri(),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0 or not tmp_pdf.exists():
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"Chromium PDF render failed: {detail[-2000:]}")
        tmp_pdf.replace(pdf_path)
    finally:
        if tmp_pdf.exists():
            tmp_pdf.unlink()
        if cleanup is not None:
            cleanup.cleanup()

    if open_pdf and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        opener = shutil.which("xdg-open")
        if opener:
            subprocess.Popen(
                [opener, str(pdf_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    return pdf_path
