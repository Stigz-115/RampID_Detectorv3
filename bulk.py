"""
Bulk scanning: parse a batch of URLs from pasted text and/or an uploaded CSV,
then scan all of them (with the same crawl logic as the single-URL scanner)
using mode-appropriate concurrency.

- requests mode is I/O-bound, so URLs are scanned concurrently via a thread pool.
- playwright mode launches a full headless Chromium process per worker, so
  concurrency is capped low regardless of the requested value — Streamlit
  Community Cloud's free tier has limited CPU/RAM and many concurrent
  browsers can crash the app.
"""

import asyncio
import csv as csv_module
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

import pandas as pd

from patterns import CrawlResult
from scanner import normalize_url, crawl_website, _crawl_with_playwright

MAX_PLAYWRIGHT_CONCURRENCY = 3

_URL_COLUMN_NAMES = ("url", "website", "domain", "site", "company_url", "link")


def parse_bulk_input(text: str, csv_file) -> list[str]:
    """Merge pasted textarea lines and an uploaded CSV's URL column into a
    deduped, normalized list of URLs."""
    urls: list[str] = []
    seen: set[str] = set()

    def add(raw: str):
        normalized = normalize_url((raw or "").strip())
        if normalized and normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)

    for line in (text or "").splitlines():
        add(line)

    if csv_file is not None:
        content = csv_file.getvalue()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")
        reader = csv_module.DictReader(io.StringIO(content))
        fieldnames = reader.fieldnames or []
        lower_fieldnames = [f.lower() for f in fieldnames]

        url_col = None
        for name in _URL_COLUMN_NAMES:
            if name in lower_fieldnames:
                url_col = fieldnames[lower_fieldnames.index(name)]
                break
        if url_col is None and fieldnames:
            url_col = fieldnames[0]

        if url_col:
            for row in reader:
                add(row.get(url_col, ""))

    return urls


def run_bulk_scan(
    urls: list[str],
    mode: str = "requests",
    max_pages: int = 5,
    timeout_ms: int = 30000,
    dismiss_consent: bool = True,
    max_concurrency: int = 5,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> list[CrawlResult]:
    """Scan many URLs (with crawling) and return one CrawlResult per URL, in input order."""
    if mode == "playwright":
        concurrency = min(max(1, max_concurrency), MAX_PLAYWRIGHT_CONCURRENCY)
        return asyncio.run(
            _run_bulk_playwright(urls, max_pages, timeout_ms, dismiss_consent, concurrency, progress_callback)
        )

    total = len(urls)
    results: list[Optional[CrawlResult]] = [None] * total
    concurrency = max(1, max_concurrency)
    done = 0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_to_index = {
            pool.submit(crawl_website, url, mode, max_pages, timeout_ms, dismiss_consent): i
            for i, url in enumerate(urls)
        }
        for future in as_completed(future_to_index):
            i = future_to_index[future]
            try:
                results[i] = future.result()
            except Exception as e:
                err = CrawlResult(url=urls[i], scan_mode=mode)
                err.error = str(e)
                results[i] = err
            done += 1
            if progress_callback:
                progress_callback(done, total)

    return results


async def _run_bulk_playwright(
    urls: list[str],
    max_pages: int,
    timeout_ms: int,
    dismiss_consent: bool,
    concurrency: int,
    progress_callback: Optional[Callable[[int, int], None]],
) -> list[CrawlResult]:
    total = len(urls)
    results: list[Optional[CrawlResult]] = [None] * total
    done = 0
    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()

    async def worker(i: int, url: str):
        nonlocal done
        async with sem:
            try:
                results[i] = await _crawl_with_playwright(url, max_pages, timeout_ms, dismiss_consent)
            except Exception as e:
                err = CrawlResult(url=url, scan_mode="playwright")
                err.error = str(e)
                results[i] = err
        async with lock:
            done += 1
            if progress_callback:
                progress_callback(done, total)

    await asyncio.gather(*(worker(i, url) for i, url in enumerate(urls)))
    return results


def results_to_dataframe(results: list[CrawlResult]) -> pd.DataFrame:
    """Flatten CrawlResults into a table suitable for st.dataframe / CSV export."""
    rows = []
    for crawl in results:
        merged = crawl.merged_result()
        rows.append({
            "URL": crawl.url,
            "Confidence": merged.confidence if not crawl.error else "Error",
            "rlcdn.com Calls": len(merged.rlcdn_requests),
            "RampID IDs": len(merged.rampid_matches),
            "Script Refs": len(merged.script_references),
            "Cookie Matches": len(merged.cookie_matches),
            "Pages Crawled": len(crawl.pages),
            "Error": crawl.error or "",
        })
    return pd.DataFrame(rows)
