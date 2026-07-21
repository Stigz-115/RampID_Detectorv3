"""
RampID pattern matching utilities.

Detects LiveRamp RampID signals in network traffic, cookies, and page content.

RampID identifiers follow these formats:
  - XY<4-digit-number><random hash>   (49 or 70 characters total)
  - Xi<4-digit-number><random hash>   (49 or 70 characters total)

The rlcdn.com domain is LiveRamp's cookie-matching / ID sync endpoint.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Domain / URL patterns
# ---------------------------------------------------------------------------

# LiveRamp's primary delivery domain for ID syncs and cookie matching
RLCDN_PATTERN = re.compile(r"rlcdn\.com", re.IGNORECASE)

# Additional LiveRamp / RampID related domains and endpoints
LIVERAMP_DOMAINS = [
    "rlcdn.com",
    "liveramp.com",
    "idsync.rlcdn.com",
    "tags.rlcdn.com",
    "pippio.com",          # Legacy LiveRamp domain
    "live.ramp.com",
    "ramp.com",
]

# Keywords that may appear in script URLs or inline JS referencing RampID
RAMPID_KEYWORDS = [
    "rampid",
    "ramp_id",
    "ramp-id",
    "liveramp",
    "live_ramp",
    "live-ramp",
    "idsync",
    "id_sync",
    "ats.js",              # LiveRamp's Authenticated Traffic Solution script
    "enabler.js",          # Legacy LiveRamp enabler
    "pippio",
    "rlcdn",
]

# URL path keywords that make a discovered link worth crawling first — RampID
# often only fires on pages like these rather than the homepage.
PAGE_PRIORITY_KEYWORDS = [
    "privacy", "cookie", "consent", "login", "signin", "sign-in",
    "account", "checkout", "cart", "subscribe", "register", "signup", "sign-up",
]


# ---------------------------------------------------------------------------
# RampID identifier regex
# ---------------------------------------------------------------------------

# XY or Xi prefix, followed by 4 digits, then a base64-ish hash.
# The hash portion is alphanumeric with possible - and _ characters.
# Total length is either 49 (hash=43) or 70 (hash=64).

_HASH_CHARS = r"[A-Za-z0-9_\-]"

# The hash charset includes '-'/'_', which are non-word characters, so a
# plain \b boundary can fail to match right after them (e.g. a RampID ending
# in '-' immediately followed by a quote). Use explicit lookarounds tied to
# the actual charset instead of \b so boundaries are correctness-based.
_LEFT_BOUND = r"(?<![A-Za-z0-9_\-])"
_RIGHT_BOUND = r"(?![A-Za-z0-9_\-])"

# XY<4 digits><43 hash chars> = 2 + 4 + 43 = 49
_RAMPID_49 = re.compile(rf"{_LEFT_BOUND}(XY|Xi)\d{{4}}{_HASH_CHARS}{{43}}{_RIGHT_BOUND}")

# XY<4 digits><64 hash chars> = 2 + 4 + 64 = 70
_RAMPID_70 = re.compile(rf"{_LEFT_BOUND}(XY|Xi)\d{{4}}{_HASH_CHARS}{{64}}{_RIGHT_BOUND}")

# Combined pattern for any valid RampID
RAMPID_PATTERN = re.compile(
    rf"{_LEFT_BOUND}(XY|Xi)\d{{4}}{_HASH_CHARS}{{43}}{_RIGHT_BOUND}"   # 49-char variant
    rf"|"
    rf"{_LEFT_BOUND}(XY|Xi)\d{{4}}{_HASH_CHARS}{{64}}{_RIGHT_BOUND}",   # 70-char variant
)

# Broader fallback: XY/Xi + 4 digits + at least 20 hash chars (catches truncated IDs)
RAMPID_BROAD = re.compile(rf"{_LEFT_BOUND}(XY|Xi)\d{{4}}{_HASH_CHARS}{{20,}}{_RIGHT_BOUND}")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RampIDMatch:
    """A single RampID identifier found in content."""
    value: str
    source: str          # Where it was found: "cookie", "network", "script", "html"
    length: int
    variant: str         # "49-char" or "70-char" or "broad"


@dataclass
class ScanResult:
    """Aggregated results from a website scan."""
    url: str = ""
    scan_mode: str = ""                              # "playwright" or "requests"

    # Network-level findings
    rlcdn_requests: list[dict] = field(default_factory=list)     # URLs containing rlcdn
    liveramp_requests: list[dict] = field(default_factory=list)  # Other LiveRamp domains
    all_network_requests: list[dict] = field(default_factory=list)

    # Content findings
    rampid_matches: list[RampIDMatch] = field(default_factory=list)
    script_references: list[str] = field(default_factory=list)   # Script URLs referencing LiveRamp
    cookie_matches: list[dict] = field(default_factory=list)

    # Metadata
    page_title: str = ""
    error: Optional[str] = None

    @property
    def has_rampid(self) -> bool:
        """True if any RampID signal was detected."""
        return bool(self.rlcdn_requests or self.rampid_matches or self.script_references)

    @property
    def _has_exact_rampid(self) -> bool:
        """True if any RampID match is a full-length (49/70-char) identifier,
        as opposed to a "broad"/truncated fallback match."""
        return any(m.variant in ("49-char", "70-char") for m in self.rampid_matches)

    @property
    def _has_cookie_name_only_match(self) -> bool:
        """True if cookie_matches contains only weak name-keyword hits (no
        RampID values actually found in any cookie)."""
        return bool(self.cookie_matches) and not any(c.get("rampids_found") for c in self.cookie_matches)

    @property
    def confidence(self) -> str:
        """Confidence level of the detection.

        rlcdn.com calls and exact RampID matches are direct technical proof
        and reach High on their own. Script references / broad RampID matches
        are corroborating-but-not-definitive (Medium). A bare cookie-name
        keyword match with no actual RampID value found is the weakest signal
        (Low) since it can false-positive on unrelated cookies.
        """
        if self.rlcdn_requests or self._has_exact_rampid:
            return "High"

        weak_signal_count = sum([
            bool(self.script_references),
            bool(self.rampid_matches),   # broad-only matches at this point
            bool(self.cookie_matches),
        ])
        if self.script_references or (self.rampid_matches and not self._has_exact_rampid) or weak_signal_count >= 2:
            return "Medium"
        if self._has_cookie_name_only_match:
            return "Low"
        return "None"

    @property
    def summary(self) -> str:
        """Human-readable summary."""
        if self.error:
            return f"Error: {self.error}"
        if not self.has_rampid:
            return "No RampID / LiveRamp signals detected."
        parts = []
        if self.rlcdn_requests:
            parts.append(f"{len(self.rlcdn_requests)} rlcdn.com network call(s)")
        if self.rampid_matches:
            parts.append(f"{len(self.rampid_matches)} RampID identifier(s)")
        if self.script_references:
            parts.append(f"{len(self.script_references)} LiveRamp script reference(s)")
        if self.cookie_matches:
            parts.append(f"{len(self.cookie_matches)} cookie match(es)")
        return "Detected: " + ", ".join(parts) + f" (Confidence: {self.confidence})"


@dataclass
class CrawlResult:
    """Aggregated results from scanning a URL plus a handful of its same-domain pages."""
    url: str = ""                                       # entry URL
    scan_mode: str = ""
    pages: list[ScanResult] = field(default_factory=list)   # one ScanResult per page scanned
    error: Optional[str] = None

    def merged_result(self) -> ScanResult:
        """Build a synthetic ScanResult with the union of all per-page signals,
        deduped by value, so existing confidence/summary logic (and display code)
        can be reused as-is."""
        merged = ScanResult(url=self.url, scan_mode=self.scan_mode)
        seen_rlcdn, seen_liveramp, seen_rampid, seen_script, seen_cookie = set(), set(), set(), set(), set()

        for page in self.pages:
            for req in page.rlcdn_requests:
                if req["url"] not in seen_rlcdn:
                    seen_rlcdn.add(req["url"])
                    merged.rlcdn_requests.append(req)
            for req in page.liveramp_requests:
                if req["url"] not in seen_liveramp:
                    seen_liveramp.add(req["url"])
                    merged.liveramp_requests.append(req)
            for m in page.rampid_matches:
                if m.value not in seen_rampid:
                    seen_rampid.add(m.value)
                    merged.rampid_matches.append(m)
            for ref in page.script_references:
                if ref not in seen_script:
                    seen_script.add(ref)
                    merged.script_references.append(ref)
            for cookie in page.cookie_matches:
                key = (cookie.get("name"), cookie.get("domain"))
                if key not in seen_cookie:
                    seen_cookie.add(key)
                    merged.cookie_matches.append(cookie)

        return merged

    @property
    def has_rampid(self) -> bool:
        return self.merged_result().has_rampid

    @property
    def confidence(self) -> str:
        return self.merged_result().confidence

    @property
    def pages_with_signal(self) -> list[ScanResult]:
        """Pages that individually contributed at least one signal."""
        return [p for p in self.pages if p.has_rampid]

    @property
    def summary(self) -> str:
        if self.error:
            return f"Error: {self.error}"
        if not self.pages:
            return "No pages were scanned."
        base = self.merged_result().summary
        return f"{base} — across {len(self.pages)} page(s) scanned ({len(self.pages_with_signal)} with signals)"


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def find_rampids(text: str, source: str = "unknown") -> list[RampIDMatch]:
    """
    Find all RampID identifiers in a text string.

    Args:
        text: The text to search (cookie value, URL, script content, HTML).
        source: Where this text came from (for reporting).

    Returns:
        List of RampIDMatch objects.
    """
    matches = []
    seen = set()

    # Exact 49-char matches
    for m in _RAMPID_49.finditer(text):
        val = m.group()
        if val not in seen:
            seen.add(val)
            matches.append(RampIDMatch(
                value=val, source=source, length=49, variant="49-char"
            ))

    # Exact 70-char matches
    for m in _RAMPID_70.finditer(text):
        val = m.group()
        if val not in seen:
            seen.add(val)
            matches.append(RampIDMatch(
                value=val, source=source, length=70, variant="70-char"
            ))

    # Broad fallback for partial/truncated IDs (only if no exact match for same value)
    for m in RAMPID_BROAD.finditer(text):
        val = m.group()
        if val not in seen:
            # Check if an exact match already captured a superset
            already_found = any(
                existing.value in val or val in existing.value
                for existing in matches
            )
            if not already_found:
                seen.add(val)
                matches.append(RampIDMatch(
                    value=val, source=source, length=len(val), variant="broad"
                ))

    return matches


def is_rlcdn_url(url: str) -> bool:
    """Check if a URL references rlcdn.com."""
    return bool(RLCDN_PATTERN.search(url))


def is_liveramp_url(url: str) -> bool:
    """Check if a URL references any known LiveRamp domain."""
    url_lower = url.lower()
    return any(domain in url_lower for domain in LIVERAMP_DOMAINS)


def find_script_references(html: str) -> list[str]:
    """
    Find <script> tags whose src attribute references LiveRamp/RampID.

    Returns a list of script src URLs.
    """
    refs = []
    # Match script tags with src attributes
    script_pattern = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in script_pattern.finditer(html):
        src = m.group(1)
        src_lower = src.lower()
        if is_liveramp_url(src) or any(kw in src_lower for kw in RAMPID_KEYWORDS):
            refs.append(src)

    # Also check inline scripts for LiveRamp keywords
    inline_pattern = re.compile(
        r'<script[^>]*>(.*?)</script>',
        re.IGNORECASE | re.DOTALL,
    )
    for m in inline_pattern.finditer(html):
        content = m.group(1)
        content_lower = content.lower()
        if any(kw in content_lower for kw in ["rlcdn", "liveramp", "rampid", "pippio", "ats.js"]):
            # Try to extract a URL if one is referenced
            url_match = re.search(r'https?://[^\s"\'<>]+rlcdn[^\s"\'<>]*', content, re.IGNORECASE)
            if url_match:
                refs.append(url_match.group())
            else:
                refs.append("inline script referencing LiveRamp/RampID")

    return list(dict.fromkeys(refs))  # dedupe preserving order
