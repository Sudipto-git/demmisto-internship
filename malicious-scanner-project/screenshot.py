"""
╔══════════════════════════════════════════╗
║   MODULE: Site Screenshot               ║
║   Uses  : Playwright headless Chrome    ║
╚══════════════════════════════════════════╝
"""

import os
import logging
from datetime import datetime

log = logging.getLogger(__name__)

SCREENSHOTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "reports", "screenshots"
)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)


def take_screenshot(target: str, scan_id: str) -> str:
    """
    Take screenshot of target domain/URL.
    Returns path to screenshot file, or "" if failed.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        log.error("[SCREENSHOT] Playwright not installed. Run: pip3 install playwright && playwright install chromium")
        return ""

    # Build URL
    url = target if target.startswith("http") else f"https://{target}"
    filename = os.path.join(SCREENSHOTS_DIR, f"screenshot_{scan_id}.png")

    log.info(f"[SCREENSHOT] Taking screenshot of: {url}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--ignore-certificate-errors",
                    "--disable-web-security"
                ]
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            )
            page = context.new_page()

            try:
                page.goto(url, timeout=15000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)  # let JS render
            except PWTimeout:
                log.warning(f"[SCREENSHOT] Page load timeout — taking partial screenshot")
            except Exception as e:
                log.warning(f"[SCREENSHOT] Navigation warning: {e}")

            page.screenshot(path=filename, full_page=False)
            browser.close()

        log.info(f"[SCREENSHOT] ✅ Saved: {filename}")
        return filename

    except Exception as e:
        log.error(f"[SCREENSHOT] ❌ Failed: {e}")
        return ""
