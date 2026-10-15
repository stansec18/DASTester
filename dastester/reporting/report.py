"""Render scan results to HTML and PDF (and JSON) reports."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..__version__ import __version__
from ..models import Severity, owasp_meta, stride_meta, OWASP_TOP10, STRIDE

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _context(result):
    findings = []
    for f in result.findings:
        d = f.to_dict()
        d["owasp_meta"] = owasp_meta(f.owasp)
        d["stride_meta"] = [stride_meta(c) for c in f.stride]
        findings.append(d)

    owasp_breakdown = []
    for key, meta in OWASP_TOP10.items():
        count = sum(1 for f in result.findings if f.owasp == key)
        owasp_breakdown.append((key, {"meta": meta, "count": count}))

    stride_breakdown = []
    for code, meta in STRIDE.items():
        count = sum(1 for f in result.findings if code in f.stride)
        stride_breakdown.append((code, {"meta": meta, "count": count}))

    import datetime as _dt
    return {
        "version": __version__,
        "generated": _dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "targets": result.config.targets,
        "pages_scanned": result.pages_scanned,
        "started": result.started,
        "finished": result.finished,
        "active": result.config.active and result.config.authorized,
        "findings": findings,
        "severity_counts": result.by_severity(),
        "owasp_breakdown": owasp_breakdown,
        "stride_breakdown": stride_breakdown,
        "errors": result.errors,
    }


def render_html(result) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    return template.render(**_context(result))


def render_json(result) -> str:
    return json.dumps(_context(result), indent=2, default=str)


def _html_to_pdf(html: str, out_path: str, logger=None) -> bool:
    """Try WeasyPrint, then xhtml2pdf. Returns True on success."""
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=html).write_pdf(out_path)
        return True
    except Exception as exc:  # noqa: BLE001
        if logger:
            logger(f"WeasyPrint unavailable ({exc}); trying xhtml2pdf.")
    try:
        from xhtml2pdf import pisa  # type: ignore
        with open(out_path, "wb") as fh:
            status = pisa.CreatePDF(html, dest=fh)
        return not status.err
    except Exception as exc:  # noqa: BLE001
        if logger:
            logger(f"xhtml2pdf unavailable ({exc}); PDF not generated.")
        return False


def build_reports(result, logger=None) -> List[str]:
    cfg = result.config
    out_dir = Path(cfg.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = cfg.report_name
    written: List[str] = []

    html = render_html(result)

    if "html" in cfg.formats:
        p = out_dir / f"{base}.html"
        p.write_text(html, encoding="utf-8")
        written.append(str(p))

    if "json" in cfg.formats:
        p = out_dir / f"{base}.json"
        p.write_text(render_json(result), encoding="utf-8")
        written.append(str(p))

    if "pdf" in cfg.formats:
        p = out_dir / f"{base}.pdf"
        if _html_to_pdf(html, str(p), logger=logger):
            written.append(str(p))
        elif logger:
            logger("PDF generation failed; HTML report is still available.")

    return written
