"""
HIPAA audit orchestrator for the RampID Detector.

Runs the existing website scanner and feeds the results through the HIPAA
engine to produce an AuditReport with findings, compliance score, and summary.
Optionally incorporates web research findings.

This module wraps the existing scanner.researcher modules without modifying them.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from hipaa_engine import (
    Finding,
    AuditReport,
    calculate_score,
    summarize,
    sort_findings,
    findings_from_scan_result,
    findings_from_research,
)


def run_hipaa_audit(scan_result, research_report=None) -> AuditReport:
    """
    Produce a HIPAA AuditReport from a ScanResult.

    Args:
        scan_result: A ScanResult from scanner.scan_website().
        research_report: Optional ResearchReport from researcher module.

    Returns:
        AuditReport with HIPAA findings, compliance score, and summary.
    """
    all_findings: list[Finding] = []

    # Generate findings from the scan result
    all_findings.extend(findings_from_scan_result(scan_result))

    # Generate findings from web research (if available)
    if research_report:
        all_findings.extend(findings_from_research(research_report))

    # --- PII context escalation ---
    # If the scanned page is a PII/PHI page (auth, condition, booking),
    # escalate LiveRamp findings to higher severity
    pii_cats = getattr(scan_result, "pii_categories", [])
    ats_signals = getattr(scan_result, "ats_signals", [])
    liveramp_cookies = getattr(scan_result, "liveramp_cookies", [])

    is_pii_page = bool(pii_cats)
    is_condition_page = "condition" in pii_cats
    is_auth_page = "auth" in pii_cats

    if is_pii_page:
        # Add a PII context finding if LiveRamp was detected
        has_liveramp = bool(
            getattr(scan_result, "rlcdn_requests", [])
            or getattr(scan_result, "rampid_matches", [])
            or getattr(scan_result, "script_references", [])
            or liveramp_cookies
            or ats_signals
        )

        if has_liveramp:
            if is_condition_page and ats_signals:
                all_findings.append(Finding(
                    hipaa_category="technical",
                    severity="critical",
                    title="LiveRamp ATS on condition-lookup page — PHI disclosure chain",
                    description=(
                        "This page allows users to search for doctors by medical condition "
                        "AND has LiveRamp ATS active. ATS captures the user's authenticated "
                        "email and converts it to a RampID. This creates a direct chain: "
                        "medical condition query → user email → RampID → real-world identity. "
                        "This is an unauthorized PHI disclosure to LiveRamp."
                    ),
                    evidence=(
                        f"PII categories: {', '.join(pii_cats)}. "
                        f"ATS signals: {', '.join(ats_signals[:5])}. "
                        f"LiveRamp cookies: {len(liveramp_cookies)}."
                    ),
                    recommendation=(
                        "Remove LiveRamp ATS from condition-lookup pages immediately. "
                        "If identity resolution is required, use server-side resolution "
                        "that does not expose the condition query to LiveRamp."
                    ),
                    citation="§164.312(e)(1) Transmission Security; §164.502(b) Minimum Necessary",
                    url=getattr(scan_result, "url", ""),
                ))
            elif is_condition_page:
                all_findings.append(Finding(
                    hipaa_category="technical",
                    severity="critical",
                    title="LiveRamp identity resolution on condition-lookup page",
                    description=(
                        "This page allows users to search for doctors by medical condition "
                        "and LiveRamp identity resolution is active. RampID links the "
                        "visitor's online identifiers to offline PII (name, address, phone), "
                        "meaning the medical condition query is linked to real-world identity."
                    ),
                    evidence=(
                        f"PII categories: {', '.join(pii_cats)}. "
                        f"LiveRamp cookies: {len(liveramp_cookies)}. "
                        f"ATS signals: {', '.join(ats_signals[:3]) or 'none'}."
                    ),
                    recommendation=(
                        "Remove LiveRamp tracking from condition-lookup pages. Ensure "
                        "RampIDs are not generated on pages where users search by condition."
                    ),
                    citation="§164.312(e)(1) Transmission Security",
                    url=getattr(scan_result, "url", ""),
                ))
            elif is_auth_page and ats_signals:
                all_findings.append(Finding(
                    hipaa_category="technical",
                    severity="critical",
                    title="LiveRamp ATS on login page — capturing user emails for RampID",
                    description=(
                        "This is an authentication (login/signup) page with LiveRamp ATS "
                        "active. ATS captures the user's email or user ID and converts it "
                        "to a RampID. If the same identity is active on health-related pages, "
                        "the user's login identity is linked to their health activity."
                    ),
                    evidence=(
                        f"PII categories: {', '.join(pii_cats)}. "
                        f"ATS signals: {', '.join(ats_signals[:5])}."
                    ),
                    recommendation=(
                        "Evaluate whether ATS should be active on login pages. If users "
                        "can access PHI pages after login, the RampID from their email may "
                        "link identity to health queries. Ensure a BAA or disable ATS."
                    ),
                    citation="§164.312(e)(1) Transmission Security; §164.312(a)(1) Access Control",
                    url=getattr(scan_result, "url", ""),
                ))

    # Add a PII page identification finding (informational)
    if pii_cats and not has_liveramp if is_pii_page else False:
        all_findings.append(Finding(
            hipaa_category="technical",
            severity="low",
            title=f"PII-handling page identified: {', '.join(pii_cats)}",
            description=(
                f"This page handles {', '.join(pii_cats)} data. No LiveRamp signals "
                f"were detected, but manual review is recommended to verify data handling."
            ),
            evidence=f"Categories: {', '.join(pii_cats)}",
            recommendation="Manually verify data flows and ensure PHI is handled per policy.",
            citation="§164.312(a)(1) Access Control",
            url=getattr(scan_result, "url", ""),
        ))

    # Sort and score
    all_findings = sort_findings(all_findings)
    score = calculate_score(all_findings)
    summary = summarize(all_findings)

    # Serialize scan result for the report
    scan_dict = {
        "url": getattr(scan_result, "url", ""),
        "scan_mode": getattr(scan_result, "scan_mode", ""),
        "page_title": getattr(scan_result, "page_title", ""),
        "has_rampid": getattr(scan_result, "has_rampid", False),
        "confidence": getattr(scan_result, "confidence", "None"),
        "pii_categories": pii_cats,
        "ats_signals": ats_signals,
        "liveramp_cookies": liveramp_cookies,
        "rlcdn_requests": getattr(scan_result, "rlcdn_requests", []),
        "rampid_matches": [
            {"value": m.value, "source": m.source, "variant": m.variant}
            for m in getattr(scan_result, "rampid_matches", [])
        ],
        "script_references": getattr(scan_result, "script_references", []),
        "error": getattr(scan_result, "error", None),
    }

    return AuditReport(
        target_url=getattr(scan_result, "url", ""),
        scanned_at=datetime.now(timezone.utc).isoformat(),
        compliance_score=score,
        findings=all_findings,
        summary=summary,
        scan_result=scan_dict,
    )
