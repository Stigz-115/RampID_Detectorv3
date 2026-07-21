"""
Website scanner with two modes:

1. **Playwright** – launches a headless Chromium browser, loads the page (JS executes),
   and intercepts all network requests + cookies. This is the most accurate mode,
   simulating what you'd see in Chrome Dev Tools → Network tab.

2. **Requests** – fetches static HTML with the `requests` library and parses it with
   BeautifulSoup. Faster and lighter, but misses dynamically loaded scripts and
   network calls that only fire after JS execution.

Both modes also support crawling: starting from an entry URL, same-domain links are
discovered and a handful of additional pages are scanned too, since RampID/LiveRamp
signals often only fire on specific pages (login, checkout, privacy policy, etc.)
rather than the homepage.
"""

import asyncio
import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from patterns import (
    ScanResult,
    CrawlResult,
    RampIDMatch,
    find_rampids,
    find_script_references,
    is_rlcdn_url,
    is_liveramp_url,
    LIVERAMP_DOMAINS,
    RAMPID_KEYWORDS,
    PAGE_PRIORITY_KEYWORDS,
)


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Ensure URL has a scheme; prepend https:// if missing."""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


# ---------------------------------------------------------------------------
# Same-domain link discovery (shared by requests + Playwright crawling)
# ---------------------------------------------------------------------------

_SKIP_LINK_EXTENSIONS = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".zip", ".mp4", ".mp3", ".css", ".js", ".woff", ".woff2", ".doc", ".docx",
)


def _strip_www(netloc: str) -> str:
    return netloc.lower().removeprefix("www.")


def _same_domain(candidate_url: str, base_url: str) -> bool:
    return _strip_www(urlparse(candidate_url).netloc) == _strip_www(urlparse(base_url).netloc)


def _normalize_link(link: str) -> str:
    """Strip fragment/query and trailing slash so equivalent links dedupe."""
    parsed = urlparse(link)
    return parsed._replace(fragment="", query="").geturl().rstrip("/")


def _extract_same_domain_links(html: str, base_url: str) -> list[str]:
    """Find same-domain <a href> links in HTML, excluding non-page assets."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    seen: set[str] = set()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if not _same_domain(absolute, base_url):
            continue
        if parsed.path.lower().endswith(_SKIP_LINK_EXTENSIONS):
            continue
        normalized = _normalize_link(absolute)
        if normalized in seen:
            continue
        seen.add(normalized)
        links.append(normalized)

    return links


def _rank_links(links: list[str]) -> list[str]:
    """Sort links so priority pages (privacy, login, checkout, ...) come first."""
    def priority(link: str) -> int:
        path = urlparse(link).path.lower()
        return 0 if any(kw in path for kw in PAGE_PRIORITY_KEYWORDS) else 1

    return sorted(links, key=priority)


# ---------------------------------------------------------------------------
# Playwright scanner
# ---------------------------------------------------------------------------

# Best-effort selectors for common cookie-consent "accept all" buttons.
_CONSENT_SELECTORS = [
    "#onetrust-accept-btn-handler",                                  # OneTrust
    "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",        # Cookiebot
    "button:has-text(\"Accept all\")",
    "button:has-text(\"Accept All\")",
    "button:has-text(\"Accept all cookies\")",
    "button:has-text(\"Accept\")",
    "button:has-text(\"I Accept\")",
    "button:has-text(\"Allow all\")",
    "button:has-text(\"Allow All\")",
    "[aria-label=\"Accept all\"]",
    "[aria-label=\"Accept cookies\"]",
]


async def _dismiss_consent_banners(page) -> None:
    """Best-effort click of common cookie-consent accept buttons.

    Many sites gate tracking scripts (including LiveRamp's) behind a CMP
    banner, so networkidle can fire before those scripts ever load. Failures
    here are expected (no banner present) and must never fail the scan.
    """
    for selector in _CONSENT_SELECTORS:
        try:
            locator = page.locator(selector).first
            await locator.click(timeout=1500)
            return  # one click is enough; most CMPs dismiss the whole overlay
        except Exception:
            continue


async def _scan_page_with_playwright(
    context, url: str, timeout_ms: int, dismiss_consent: bool
) -> tuple[ScanResult, Optional[str]]:
    """Scan a single page within an existing Playwright browser context.

    Returns (ScanResult, page_html) — page_html is None on error, and is
    used by the caller for same-domain link discovery when crawling.
    """
    result = ScanResult(url=url, scan_mode="playwright")
    page = await context.new_page()
    network_log: list[dict] = []

    def on_request(request):
        req_url = request.url
        entry = {
            "url": req_url,
            "method": request.method,
            "resource_type": request.resource_type,
            "headers": dict(request.headers),
        }
        network_log.append(entry)
        if is_rlcdn_url(req_url):
            result.rlcdn_requests.append(entry)
        elif is_liveramp_url(req_url):
            result.liveramp_requests.append(entry)

    page.on("request", on_request)

    try:
        response = await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        if response is None:
            result.error = "No response received (page did not load)"
            await page.close()
            return result, None

        if dismiss_consent:
            await _dismiss_consent_banners(page)
            try:
                await page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except Exception:
                pass

        # Wait a bit more for any delayed tracking scripts (post-consent or lazy-loaded).
        await page.wait_for_timeout(3000)

        result.all_network_requests = network_log
        result.page_title = await page.title()

        # --- Cookies ---
        cookies = await context.cookies()
        for cookie in cookies:
            matches = find_rampids(cookie.get("value", ""), source="cookie")
            if matches:
                for m in matches:
                    result.rampid_matches.append(m)
                result.cookie_matches.append({
                    "name": cookie.get("name"),
                    "domain": cookie.get("domain"),
                    "value_preview": cookie.get("value", "")[:80] + "..." if len(cookie.get("value", "")) > 80 else cookie.get("value", ""),
                    "rampids_found": [m.value for m in matches],
                })
            cookie_name_lower = cookie.get("name", "").lower()
            if any(kw in cookie_name_lower for kw in ["ramp", "rlcdn", "pippio", "liveramp"]):
                result.cookie_matches.append({
                    "name": cookie.get("name"),
                    "domain": cookie.get("domain"),
                    "value_preview": cookie.get("value", "")[:80] + "..." if len(cookie.get("value", "")) > 80 else cookie.get("value", ""),
                    "rampids_found": [],
                    "note": "Cookie name matches LiveRamp keyword",
                })

        # --- Page content ---
        page_content = await page.content()
        result.script_references = find_script_references(page_content)

        for m in find_rampids(page_content, source="html"):
            if not any(existing.value == m.value and existing.source == m.source for existing in result.rampid_matches):
                result.rampid_matches.append(m)

        # --- Network URLs ---
        for entry in network_log:
            for m in find_rampids(entry["url"], source="network"):
                if not any(existing.value == m.value for existing in result.rampid_matches):
                    result.rampid_matches.append(m)

        await page.close()
        return result, page_content

    except Exception as e:
        result.error = str(e)
        try:
            await page.close()
        except Exception:
            pass
        return result, None


async def _scan_with_playwright(url: str, timeout_ms: int = 30000, dismiss_consent: bool = True) -> ScanResult:
    """Scan a single website using Playwright headless browser."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        result = ScanResult(url=url, scan_mode="playwright")
        result.error = "Playwright is not installed. Use 'requests' mode instead."
        return result

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
        except Exception as e:
            result = ScanResult(url=url, scan_mode="playwright")
            result.error = f"Could not launch browser: {e}. Try 'requests' mode or run: playwright install chromium"
            return result

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )
        result, _html = await _scan_page_with_playwright(context, url, timeout_ms, dismiss_consent)
        await browser.close()
        return result


async def _crawl_with_playwright(
    url: str, max_pages: int, timeout_ms: int, dismiss_consent: bool
) -> CrawlResult:
    """Crawl a website using one shared Playwright browser context across pages."""
    from playwright.async_api import async_playwright

    crawl = CrawlResult(url=url, scan_mode="playwright")

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
        except Exception as e:
            crawl.error = f"Could not launch browser: {e}. Try 'requests' mode or run: playwright install chromium"
            return crawl

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )

        visited: set[str] = set()
        candidate_seen: set[str] = {url}
        candidates = [url]

        while candidates and len(crawl.pages) < max_pages:
            next_url = candidates.pop(0)
            if next_url in visited:
                continue
            visited.add(next_url)

            page_result, html = await _scan_page_with_playwright(context, next_url, timeout_ms, dismiss_consent)
            crawl.pages.append(page_result)

            if html:
                new_links = [
                    link for link in _extract_same_domain_links(html, url)
                    if link not in candidate_seen and link not in visited
                ]
                for link in new_links:
                    candidate_seen.add(link)
                candidates = _rank_links(candidates + new_links)

        await browser.close()

    return crawl


def scan_with_playwright(url: str, timeout_ms: int = 30000, dismiss_consent: bool = True) -> ScanResult:
    """Synchronous wrapper for the Playwright scanner.
    Falls back to requests mode if Playwright browser is not installed."""
    result = asyncio.run(_scan_with_playwright(url, timeout_ms, dismiss_consent))
    if result.error and "Executable doesn't exist" in result.error:
        # Playwright browser not installed — fall back to requests mode
        fallback = scan_with_requests(url, timeout=timeout_ms // 1000)
        fallback.scan_mode = "requests (fallback from playwright)"
        fallback.summary = f"Playwright browser not available. Used requests mode instead. {fallback.summary}"
        return fallback
    return result


def crawl_with_playwright(url: str, max_pages: int = 5, timeout_ms: int = 30000, dismiss_consent: bool = True) -> CrawlResult:
    """Synchronous wrapper for the Playwright crawler."""
    crawl = asyncio.run(_crawl_with_playwright(url, max_pages, timeout_ms, dismiss_consent))
    if crawl.error and "Executable doesn't exist" in crawl.error:
        return crawl_with_requests(url, max_pages=max_pages, timeout=timeout_ms // 1000)
    return crawl


# ---------------------------------------------------------------------------
# Requests-based scanner
# ---------------------------------------------------------------------------

def _analyze_html_requests(url: str, html: str, response_cookies) -> ScanResult:
    """Build a ScanResult from already-fetched HTML + response cookies (requests mode)."""
    from bs4 import BeautifulSoup

    result = ScanResult(url=url, scan_mode="requests")

    soup = BeautifulSoup(html, "html.parser")
    if soup.title:
        result.page_title = soup.title.string or ""

    # --- Response cookies ---
    for cookie in response_cookies:
        cookie_name = cookie.name
        cookie_value = cookie.value or ""
        matches = find_rampids(cookie_value, source="cookie")
        if matches:
            for m in matches:
                result.rampid_matches.append(m)
            result.cookie_matches.append({
                "name": cookie_name,
                "domain": cookie.domain or "",
                "value_preview": cookie_value[:80] + "..." if len(cookie_value) > 80 else cookie_value,
                "rampids_found": [m.value for m in matches],
            })
        cookie_name_lower = (cookie_name or "").lower()
        if any(kw in cookie_name_lower for kw in ["ramp", "rlcdn", "pippio", "liveramp"]):
            result.cookie_matches.append({
                "name": cookie_name,
                "domain": cookie.domain or "",
                "value_preview": cookie_value[:80] + "..." if len(cookie_value) > 80 else cookie_value,
                "rampids_found": [],
                "note": "Cookie name matches LiveRamp keyword",
            })

    # --- Script references ---
    result.script_references = find_script_references(html)

    # --- Script src URLs ---
    for script_tag in soup.find_all("script", src=True):
        src = script_tag["src"]
        if is_rlcdn_url(src):
            result.rlcdn_requests.append({"url": src, "method": "GET", "resource_type": "script"})
        elif is_liveramp_url(src):
            result.liveramp_requests.append({"url": src, "method": "GET", "resource_type": "script"})

    # --- Full HTML RampID search ---
    for m in find_rampids(html, source="html"):
        if not any(existing.value == m.value for existing in result.rampid_matches):
            result.rampid_matches.append(m)

    # --- Inline scripts ---
    for script_tag in soup.find_all("script"):
        content = script_tag.string or ""
        if content:
            url_matches = re.findall(r'https?://[^\s"\'<>]+rlcdn[^\s"\'<>]*', content, re.IGNORECASE)
            for url_match in url_matches:
                if not any(e["url"] == url_match for e in result.rlcdn_requests):
                    result.rlcdn_requests.append({"url": url_match, "method": "GET", "resource_type": "inline-script"})

            for m in find_rampids(content, source="script"):
                if not any(existing.value == m.value for existing in result.rampid_matches):
                    result.rampid_matches.append(m)

    # --- link/preconnect tags ---
    for link_tag in soup.find_all("link", href=True):
        href = link_tag["href"]
        if is_rlcdn_url(href):
            result.rlcdn_requests.append({"url": href, "method": "GET", "resource_type": "link"})
        elif is_liveramp_url(href):
            result.liveramp_requests.append({"url": href, "method": "GET", "resource_type": "link"})

    return result


def _fetch_and_analyze_requests(url: str, timeout: int = 15) -> tuple[ScanResult, Optional[str]]:
    """Fetch a page with `requests` and analyze it. Returns (ScanResult, html-or-None)."""
    import requests as req

    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        response = req.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        html = response.text
        result = _analyze_html_requests(url, html, response.cookies)
        return result, html

    except req.exceptions.Timeout:
        result = ScanResult(url=url, scan_mode="requests")
        result.error = "Request timed out"
        return result, None
    except req.exceptions.ConnectionError as e:
        result = ScanResult(url=url, scan_mode="requests")
        result.error = f"Connection error: {e}"
        return result, None
    except Exception as e:
        result = ScanResult(url=url, scan_mode="requests")
        result.error = str(e)
        return result, None


def scan_with_requests(url: str, timeout: int = 15) -> ScanResult:
    """
    Scan a website using the requests library (static HTML only).

    Fetches the page, parses HTML for script tags and inline scripts,
    checks response cookies, and searches for RampID patterns.
    """
    result, _html = _fetch_and_analyze_requests(url, timeout=timeout)
    return result


def crawl_with_requests(url: str, max_pages: int = 5, timeout: int = 15) -> CrawlResult:
    """Crawl a website using static HTML fetches, discovering same-domain links."""
    crawl = CrawlResult(url=url, scan_mode="requests")

    visited: set[str] = set()
    candidate_seen: set[str] = {url}
    candidates = [url]

    while candidates and len(crawl.pages) < max_pages:
        next_url = candidates.pop(0)
        if next_url in visited:
            continue
        visited.add(next_url)

        page_result, html = _fetch_and_analyze_requests(next_url, timeout=timeout)
        crawl.pages.append(page_result)

        if html:
            new_links = [
                link for link in _extract_same_domain_links(html, url)
                if link not in candidate_seen and link not in visited
            ]
            for link in new_links:
                candidate_seen.add(link)
            candidates = _rank_links(candidates + new_links)

    return crawl


# ---------------------------------------------------------------------------
# Unified entry points
# ---------------------------------------------------------------------------

def scan_website(url: str, mode: str = "playwright", timeout_ms: int = 30000, dismiss_consent: bool = True) -> ScanResult:
    """
    Scan a single page for RampID / LiveRamp signals.

    Args:
        url: The URL to scan (will be normalized with https:// if needed).
        mode: "playwright" for full browser scan, "requests" for static HTML.
        timeout_ms: Timeout in milliseconds (Playwright) or seconds (requests).
        dismiss_consent: Whether to best-effort click cookie-consent banners (Playwright only).

    Returns:
        ScanResult with all findings.
    """
    url = normalize_url(url)
    if not url:
        return ScanResult(error="No URL provided")

    if mode == "playwright":
        return scan_with_playwright(url, timeout_ms=timeout_ms, dismiss_consent=dismiss_consent)
    else:
        return scan_with_requests(url, timeout=timeout_ms // 1000)


def crawl_website(
    url: str,
    mode: str = "playwright",
    max_pages: int = 5,
    timeout_ms: int = 30000,
    dismiss_consent: bool = True,
) -> CrawlResult:
    """
    Scan a URL plus up to `max_pages` total same-domain pages for RampID / LiveRamp signals.

    Same-domain links are discovered from each page scanned and ranked so that
    likely-relevant pages (privacy policy, login, checkout, etc.) are visited
    before generic navigation links. With max_pages=1 this behaves like a
    single-page scan_website() call.

    Args:
        url: The entry URL to scan (will be normalized with https:// if needed).
        mode: "playwright" for full browser scan, "requests" for static HTML.
        max_pages: Total number of pages to scan, including the entry URL.
        timeout_ms: Timeout in milliseconds (Playwright) or seconds (requests).
        dismiss_consent: Whether to best-effort click cookie-consent banners (Playwright only).

    Returns:
        CrawlResult aggregating findings across all pages scanned.
    """
    url = normalize_url(url)
    if not url:
        crawl = CrawlResult(scan_mode=mode)
        crawl.error = "No URL provided"
        return crawl

    max_pages = max(1, max_pages)

    if mode == "playwright":
        return crawl_with_playwright(url, max_pages=max_pages, timeout_ms=timeout_ms, dismiss_consent=dismiss_consent)
    else:
        return crawl_with_requests(url, max_pages=max_pages, timeout=timeout_ms // 1000)
