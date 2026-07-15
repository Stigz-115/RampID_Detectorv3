"""
HIPAA compliance engine for RampID detection.

Maps LiveRamp / RampID detections to HIPAA Safeguard categories with severity
ratings, regulatory citations, and remediation recommendations. Produces a
compliance score (0-100) and structured findings.

This module is designed to work alongside the existing RampID Detector scanner
and patterns modules without modifying their behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


@dataclass
class Finding:
    hipaa_category: str        # "administrative" | "physical" | "technical"
    severity: str              # "critical" | "high" | "medium" | "low"
    title: str
    description: str
    evidence: str
    recommendation: str
    citation: str = ""
    url: str = ""


@dataclass
class AuditReport:
    target_url: str
    scanned_at: str
    compliance_score: int
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    scan_result: dict | None = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_DEDUCTIONS = {"critical": 25, "high": 15, "medium": 8, "low": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": "#b02525", "high": "#c25514",
    "medium": "#b07908", "low": "#1f7a5c",
}
HIPAA_CATEGORY_LABELS = {
    "administrative": "Administrative Safeguards (§164.308)",
    "physical": "Physical Safeguards (§164.310)",
    "technical": "Technical Safeguards (§164.312)",
}


def calculate_score(findings: list[Finding]) -> int:
    score = 100
    for f in findings:
        score -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
    return max(score, 0)


def summarize(findings: list[Finding]) -> dict:
    by_cat = {"administrative": 0, "physical": 0, "technical": 0}
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_cat[f.hipaa_category] = by_cat.get(f.hipaa_category, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {"total": len(findings), "by_category": by_cat, "by_severity": by_sev}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    cat_order = {"technical": 0, "administrative": 1, "physical": 2}
    return sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 9),
        cat_order.get(f.hipaa_category, 9),
    ))


# ---------------------------------------------------------------------------
# Finding generators — work with ScanResult from the existing scanner
# ---------------------------------------------------------------------------

def findings_from_scan_result(scan_result) -> list[Finding]:
    """
    Generate HIPAA findings from a ScanResult (from scanner.py).

    Uses the existing ScanResult fields:
      - rlcdn_requests, liveramp_requests
      - rampid_matches
      - script_references
      - cookie_matches
      - page_title, url
    """
    findings: list[Finding] = []
    url = getattr(scan_result, "url", "")
    page_title = getattr(scan_result, "page_title", "")

    # Combine context for evidence
    rlcdn_reqs = getattr(scan_result, "rlcdn_requests", [])
    liveramp_reqs = getattr(scan_result, "liveramp_requests", [])
    rampid_matches = getattr(scan_result, "rampid_matches", [])
    script_refs = getattr(scan_result, "script_references", [])
    cookie_matches = getattr(scan_result, "cookie_matches", [])

    has_rampid = bool(rlcdn_reqs or rampid_matches or script_refs)

    if not has_rampid and not cookie_matches:
        return findings

    # --- rlcdn.com network calls ---
    if rlcdn_reqs:
        req_urls = [r.get("url", "") for r in rlcdn_reqs[:5]]
        findings.append(Finding(
            hipaa_category="technical",
            severity="high",
            title="LiveRamp rlcdn.com ID sync calls detected",
            description=(
                "The website makes network calls to rlcdn.com, LiveRamp's "
                "cookie-matching / ID sync endpoint. This means visitor identifiers "
                "(cookies, device IDs) are being transmitted to LiveRamp for "
                "identity resolution. On a healthcare site, this can link a "
                "visitor's IP address to LiveRamp's people-based identity graph."
            ),
            evidence=f"rlcdn.com requests: {', '.join(req_urls)}",
            recommendation=(
                "If this site handles PHI, remove rlcdn.com calls from health-related "
                "pages or ensure a BAA is in place with LiveRamp and that no PHI is "
                "transmitted to the identity graph."
            ),
            citation="§164.312(e)(1) Transmission Security",
            url=url,
        ))

    # --- RampID identifiers found ---
    if rampid_matches:
        match_details = [
            f"{m.value[:25]}... ({m.variant}, source: {m.source})"
            for m in rampid_matches[:5]
        ]
        findings.append(Finding(
            hipaa_category="technical",
            severity="critical",
            title=f"RampID identifiers detected in page content ({len(rampid_matches)} found)",
            description=(
                "LiveRamp RampID identifiers were found in the page content. RampIDs "
                "are persistent, people-based identifiers that link cookies, device "
                "IDs, mobile devices, and offline PII (email, name, address, phone) "
                "to a single identity. The presence of RampIDs means visitor browsing "
                "activity is being tied to a resolved real-world identity. "
                "XY-prefix = maintained (full PII match), Xi-prefix = derived (partial "
                "PII match, may be upgraded to maintained)."
            ),
            evidence=f"RampIDs: {'; '.join(match_details)}",
            recommendation=(
                "Remove RampID generation from health-related pages immediately. "
                "If identity resolution is required, ensure a BAA with LiveRamp and "
                "use server-side resolution that does not expose PHI to the identity "
                "graph. Verify that condition-lookup pages do not generate RampIDs."
            ),
            citation="§164.312(e)(1) Transmission Security; §164.502(b) Minimum Necessary",
            url=url,
        ))

    # --- Script references (ATS, enabler, etc.) ---
    ats_refs = [s for s in script_refs if "ats" in s.lower()]
    other_refs = [s for s in script_refs if "ats" not in s.lower()]

    if ats_refs:
        findings.append(Finding(
            hipaa_category="technical",
            severity="critical",
            title="LiveRamp ATS (Authenticated Traffic Solution) detected",
            description=(
                "LiveRamp ATS script references were found. ATS captures "
                "authenticated user identifiers (e.g., email addresses from login "
                "forms) and converts them to RampIDs for identity resolution. This "
                "is especially dangerous on healthcare sites: if a user logs in and "
                "then visits a condition-lookup page, their email → RampID → medical "
                "condition query creates an unauthorized PHI disclosure chain."
            ),
            evidence=f"ATS scripts: {', '.join(ats_refs[:5])}",
            recommendation=(
                "Evaluate whether ATS should be active on pages where users may "
                "access PHI. If users can search for providers by condition after "
                "login, their authenticated identity is linked to health queries "
                "through the RampID. Ensure a BAA with LiveRamp or disable ATS."
            ),
            citation="§164.312(e)(1) Transmission Security; §164.312(a)(1) Access Control",
            url=url,
        ))

    if other_refs:
        findings.append(Finding(
            hipaa_category="technical",
            severity="medium",
            title="LiveRamp script references detected",
            description=(
                "LiveRamp-related scripts (enabler.js, idsync, etc.) were found on "
                "the page. These scripts facilitate identity resolution and data "
                "onboarding."
            ),
            evidence=f"Scripts: {', '.join(other_refs[:5])}",
            recommendation=(
                "Review LiveRamp script usage. Ensure identity resolution does not "
                "occur on PHI-bearing pages."
            ),
            citation="§164.312(e)(1) Transmission Security",
            url=url,
        ))

    # --- Cookie matches ---
    rampid_cookies = [c for c in cookie_matches if c.get("rampids_found")]
    liveramp_name_cookies = [c for c in cookie_matches if not c.get("rampids_found")]

    if rampid_cookies:
        cookie_names = [c.get("name", "?") for c in rampid_cookies]
        findings.append(Finding(
            hipaa_category="technical",
            severity="high",
            title=f"RampID values found in cookies ({', '.join(cookie_names[:5])})",
            description=(
                "RampID identifiers were found stored in browser cookies. These "
                "persistent cookies maintain the LiveRamp identity link across "
                "sessions, meaning the visitor's identity resolution persists even "
                "on return visits. On a healthcare site, this creates an ongoing "
                "pathway for linking health-related browsing to real-world identity."
            ),
            evidence=(
                f"Cookies with RampIDs: {', '.join(cookie_names)}. "
                f"Sample: {rampid_cookies[0].get('value_preview', '')[:60]}..."
            ),
            recommendation=(
                "Remove RampID cookies from health-related pages, or ensure a BAA "
                "is in place and that cookies are not associated with PHI pages."
            ),
            citation="§164.312(e)(1) Transmission Security; §164.312(a)(2)(i) Unique User Identification",
            url=url,
        ))

    if liveramp_name_cookies:
        cookie_names = [c.get("name", "?") for c in liveramp_name_cookies]
        findings.append(Finding(
            hipaa_category="technical",
            severity="medium",
            title=f"LiveRamp-named cookies detected ({', '.join(cookie_names[:5])})",
            description=(
                "Cookies with LiveRamp-related names were detected. These cookies "
                "are used by LiveRamp's identity resolution infrastructure to "
                "maintain persistent visitor identifiers."
            ),
            evidence=f"Cookies: {', '.join(cookie_names)}",
            recommendation=(
                "Review LiveRamp cookie usage on the site. Ensure cookies are not "
                "set on PHI-bearing pages."
            ),
            citation="§164.312(a)(2)(i) Unique User Identification",
            url=url,
        ))

    # --- Other LiveRamp domain requests ---
    if liveramp_reqs:
        req_urls = [r.get("url", "") for r in liveramp_reqs[:5]]
        findings.append(Finding(
            hipaa_category="technical",
            severity="medium",
            title="LiveRamp domain requests detected",
            description=(
                "Network requests to LiveRamp-owned domains (liveramp.com, "
                "pippio.com, etc.) were detected. These may be used for identity "
                "resolution, data onboarding, or measurement."
            ),
            evidence=f"LiveRamp requests: {', '.join(req_urls)}",
            recommendation="Review LiveRamp domain usage and ensure no PHI is transmitted.",
            citation="§164.312(e)(1) Transmission Security",
            url=url,
        ))

    return findings


def findings_from_research(research_report) -> list[Finding]:
    """Generate an administrative finding if public partnership evidence exists."""
    findings = []
    confidence = getattr(research_report, "confidence", "None")
    results = getattr(research_report, "results", [])
    company = getattr(research_report, "company", "")

    if confidence in ("High", "Medium") and results:
        high_conf = [r for r in results if r.relevance_score >= 0.5]
        titles = [r.title[:80] for r in high_conf[:3]]
        findings.append(Finding(
            hipaa_category="administrative",
            severity="medium" if confidence == "Medium" else "high",
            title=f"Public evidence of LiveRamp partnership found ({confidence} confidence)",
            description=(
                f"Web research found {len(results)} result(s) mentioning '{company}' "
                f"alongside LiveRamp/RampID, with {len(high_conf)} high-relevance "
                f"result(s). Public partnership evidence suggests LiveRamp is actively "
                f"used, which has HIPAA implications if PHI is involved."
            ),
            evidence=f"Top results: {'; '.join(titles)}",
            recommendation=(
                "Verify the scope of the LiveRamp partnership. Ensure a BAA is in "
                "place if LiveRamp has access to PHI. Review which pages trigger "
                "identity resolution."
            ),
            citation="§164.308(b)(1) Business Associate Contracts",
        ))

    return findings


def report_to_dict(report: AuditReport) -> dict:
    return {
        "target_url": report.target_url,
        "scanned_at": report.scanned_at,
        "compliance_score": report.compliance_score,
        "findings": [asdict(f) for f in report.findings],
        "summary": report.summary,
    }
