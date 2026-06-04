"""Single source of truth for findings aggregation and counts."""
from typing import List, Dict, Optional
from .models import Domain, Asset, Scan
from .report_summary_views import _extract_findings
from .report_style_config import findings_preview

def get_normalized_findings_and_counts(domain_obj: Domain, asset_obj: Optional[Asset], scan_obj: Optional[Scan]):
    """
    Returns (ordered_findings, summary_counts, total_count)
    - ordered_findings: deduped, normalized findings list
    - summary_counts: dict of severity counts
    - total_count: total findings
    """
    findings_raw = _extract_findings(domain_obj, asset_obj, scan_obj)
    findings = []
    for f in findings_raw:
        findings.append({
            'title': f.get('title'),
            'category': f.get('finding_type'),
            'asset': f.get('affected_asset'),
            'risk_rating': f.get('severity'),
            'status': '',
            'evidence': f.get('risk_summary'),
            'recommendation': f.get('recommendation_summary'),
            'links': [f.get('external_reference')] if f.get('external_reference') else [],
        })
    ordered, preview, remaining = findings_preview(findings)
    summary_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in ordered:
        sev = (item.get('risk_rating') or 'Low').title()
        if sev in summary_counts:
            summary_counts[sev] += 1
    summary_total = len(ordered)
    return ordered, summary_counts, summary_total