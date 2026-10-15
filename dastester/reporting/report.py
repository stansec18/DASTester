# In dastester/reporting/report.py
def generate_report(scan_results, output_format="html"):
    # Ensure severity counts cover all standard levels
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    for f in scan_results.get("findings", []):
        sev_label = f.get("severity", "Info")
        # Normalize casing
        sev_label = sev_label.capitalize()
        if sev_label in severity_counts:
            severity_counts[sev_label] += 1

    context = {
        "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "version": __version__,
        "targets": scan_results.get("targets", []),
        "pages_scanned": scan_results.get("pages_scanned", 0),
        "started": scan_results.get("started", ""),
        "finished": scan_results.get("finished", ""),
        "active": scan_results.get("active", False),
        "findings": scan_results.get("findings", []),
        "severity_counts": severity_counts,
        "owasp_breakdown": scan_results.get("owasp_breakdown", []),
        "stride_breakdown": scan_results.get("stride_breakdown", []),
        "errors": scan_results.get("errors", [])
    }
    # Render HTML / PDF...
