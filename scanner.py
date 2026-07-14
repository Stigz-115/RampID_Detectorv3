"""
Website scanner with two modes:

1. **Playwright** – launches a headless Chromium browser, loads the page (JS executes),
   and intercepts all network requests + cookies. This is the most accurate mode,
   simulating what you'd see in Chrome Dev Tools → Network tab.

2. **Requests** – fetches static HTML with the `requests` library and parses it with
   BeautifulSoup. Faster and lighter, but misses dynamically loaded scripts and
   network calls that only fire after JS execution.
"""

import asyncio
import re
from typing import Optional

from patterns import (
    ScanResult,
    RampIDMatch,
    find_rampids,
    find_script_references,
    is_rlcdn_url,
    is_liveramp_url,
    LIVERAMP_DOMAINS,
    RAMPID_KEYWORDS,
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
# Playwright scanner
# ---------------------------------------------------------------------------

async def _scan_with_playwright(url: str, timeout_ms: int = 30000) -> ScanResult:
    """
    Scan a website using Playwright headless browser.

    Intercepts all network requests, checks for rlcdn.com calls,
    inspects cookies, and scans page content for RampID identifiers.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        result = ScanResult(url=url, scan_mode="playwright")
        result.error = "Playwright is not installed. Use 'requests' mode instead."
        return result

    result = ScanResult(url=url, scan_mode="playwright")

    try:
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True)
            except Exception as e:
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
            page = await context.new_page()

            # Collect all network requests
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

            # Navigate and wait for network to settle
            response = await page.goto(url, wait_until="networkidle", timeout=timeout_ms)

            if response is None:
                result.error = "No response received (page did not load)"
                await browser.close()
                return result

            # Wait a bit more for any delayed tracking scripts
            await page.wait_for_timeout(3000)

            # Collect all network requests for the full log
            result.all_network_requests = network_log

            # Get page title
            result.page_title = await page.title()

            # --- Check cookies ---
            cookies = await context.cookies()
            for cookie in cookies:
                cookie_str = f"{cookie.get('name')}={cookie.get('value', '')}"
                # Check cookie values for RampID patterns
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
                # Check cookie names for LiveRamp keywords
                cookie_name_lower = cookie.get("name", "").lower()
                if any(kw in cookie_name_lower for kw in ["ramp", "rlcdn", "pippio", "liveramp"]):
                    result.cookie_matches.append({
                        "name": cookie.get("name"),
                        "domain": cookie.get("domain"),
                        "value_preview": cookie.get("value", "")[:80] + "..." if len(cookie.get("value", "")) > 80 else cookie.get("value", ""),
                        "rampids_found": [],
                        "note": "Cookie name matches LiveRamp keyword",
                    })

            # --- Check page content ---
            page_content = await page.content()

            # Find script references
            result.script_references = find_script_references(page_content)

            # Search for RampID patterns in the full page HTML
            for m in find_rampids(page_content, source="html"):
                # Avoid duplicates from cookie matches
                if not any(existing.value == m.value and existing.source == m.source for existing in result.rampid_matches):
                    result.rampid_matches.append(m)

            # --- Check network request URLs and responses for RampIDs ---
            for entry in network_log:
                req_url = entry["url"]
                # Check URL query params for RampID values
                url_matches = find_rampids(req_url, source="network")
                for m in url_matches:
                    if not any(existing.value == m.value for existing in result.rampid_matches):
                        result.rampid_matches.append(m)

            await browser.close()

    except Exception as e:
        result.error = str(e)

    return result


def scan_with_playwright(url: str, timeout_ms: int = 30000) -> ScanResult:
    """Synchronous wrapper for the Playwright scanner.
    Falls back to requests mode if Playwright browser is not installed."""
    result = asyncio.run(_scan_with_playwright(url, timeout_ms))
    if result.error and "Executable doesn't exist" in result.error:
        # Playwright browser not installed — fall back to requests mode
        fallback = scan_with_requests(url, timeout=timeout_ms // 1000)
        fallback.scan_mode = "requests (fallback from playwright)"
        fallback.summary = f"Playwright browser not available. Used requests mode instead. {fallback.summary}"
        return fallback
    return result


# ---------------------------------------------------------------------------
# Requests-based scanner
# ---------------------------------------------------------------------------

def scan_with_requests(url: str, timeout: int = 15) -> ScanResult:
    """
    Scan a website using the requests library (static HTML only).

    Fetches the page, parses HTML for script tags and inline scripts,
    checks response cookies, and searches for RampID patterns.
    """
    result = ScanResult(url=url, scan_mode="requests")

    try:
        import requests as req
        from bs4 import BeautifulSoup

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

        result.page_title = ""
        soup = BeautifulSoup(html, "html.parser")
        if soup.title:
            result.page_title = soup.title.string or ""

        # --- Check response cookies ---
        for cookie in response.cookies:
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

        # --- Find script references ---
        result.script_references = find_script_references(html)

        # --- Check all script src URLs for rlcdn / LiveRamp ---
        for script_tag in soup.find_all("script", src=True):
            src = script_tag["src"]
            if is_rlcdn_url(src):
                result.rlcdn_requests.append({"url": src, "method": "GET", "resource_type": "script"})
            elif is_liveramp_url(src):
                result.liveramp_requests.append({"url": src, "method": "GET", "resource_type": "script"})

        # --- Search full HTML for RampID patterns ---
        for m in find_rampids(html, source="html"):
            if not any(existing.value == m.value for existing in result.rampid_matches):
                result.rampid_matches.append(m)

        # --- Check for rlcdn / LiveRamp references in inline scripts ---
        for script_tag in soup.find_all("script"):
            content = script_tag.string or ""
            if content:
                # Check for rlcdn URLs in inline JS
                url_matches = re.findall(r'https?://[^\s"\'<>]+rlcdn[^\s"\'<>]*', content, re.IGNORECASE)
                for url_match in url_matches:
                    entry = {"url": url_match, "method": "GET", "resource_type": "inline-script"}
                    if not any(e["url"] == url_match for e in result.rlcdn_requests):
                        result.rlcdn_requests.append(entry)

                # Check for RampIDs in inline script content
                for m in find_rampids(content, source="script"):
                    if not any(existing.value == m.value for existing in result.rampid_matches):
                        result.rampid_matches.append(m)

        # --- Check link/preconnect tags for LiveRamp domains ---
        for link_tag in soup.find_all("link", href=True):
            href = link_tag["href"]
            if is_rlcdn_url(href):
                result.rlcdn_requests.append({"url": href, "method": "GET", "resource_type": "link"})
            elif is_liveramp_url(href):
                result.liveramp_requests.append({"url": href, "method": "GET", "resource_type": "link"})

    except req.exceptions.Timeout:
        result.error = "Request timed out"
    except req.exceptions.ConnectionError as e:
        result.error = f"Connection error: {e}"
    except Exception as e:
        result.error = str(e)

    return result


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def scan_website(url: str, mode: str = "playwright", timeout_ms: int = 30000) -> ScanResult:
    """
    Scan a website for RampID / LiveRamp signals.

    Args:
        url: The URL to scan (will be normalized with https:// if needed).
        mode: "playwright" for full browser scan, "requests" for static HTML.
        timeout_ms: Timeout in milliseconds (Playwright) or seconds (requests).

    Returns:
        ScanResult with all findings.
    """
    url = normalize_url(url)
    if not url:
        return ScanResult(error="No URL provided")

    if mode == "playwright":
        return scan_with_playwright(url, timeout_ms=timeout_ms)
    else:
        return scan_with_requests(url, timeout=timeout_ms // 1000)
