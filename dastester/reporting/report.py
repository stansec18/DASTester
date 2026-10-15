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
