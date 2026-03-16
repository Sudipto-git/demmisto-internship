"""
╔══════════════════════════════════════════╗
║   MODULE: Site Screenshot               ║
║   Primary  : Playwright (local)         ║
║   Fallback : screenshotone.com API      ║
╚══════════════════════════════════════════╝
"""

import os
import requests
import logging

log = logging.getLogger(__name__)

SCREENSHOTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "reports", "screenshots"
)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# Free screenshot API — no key needed for basic use
SCREENSHOT_API = "https://image.thum.io/get/width/1280/crop/800/noanimate/"


def _take_playwright(url: str, filename: str) -> str:
    """Try Playwright headless Chrome"""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--ignore-certificate-errors",
                    "--disable-web-security",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()
            try:
                page.goto(url, timeout=15000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
            except PWTimeout:
                log.warning(
                    "[SCREENSHOT] Playwright timeout — taking partial screenshot"
                )
            except Exception as e:
                log.warning(f"[SCREENSHOT] Navigation warning: {e}")

            page.screenshot(path=filename, full_page=False)
            browser.close()

        log.info(f"[SCREENSHOT] ✅ Playwright saved: {filename}")
        return filename

    except Exception as e:
        log.warning(f"[SCREENSHOT] Playwright failed: {e}")
        return ""


def _take_api(url: str, filename: str) -> str:
    """Fallback: thum.io free screenshot API — no key needed"""
    try:
        api_url = f"{SCREENSHOT_API}{url}"
        log.info(f"[SCREENSHOT] Using thum.io API for: {url}")

        resp = requests.get(
            api_url,
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0 (compatible; DarkwebMonitor/2.0)"},
        )

        if resp.status_code == 200 and len(resp.content) > 5000:
            with open(filename, "wb") as f:
                f.write(resp.content)
            log.info(f"[SCREENSHOT] ✅ API saved: {filename}")
            return filename
        else:
            log.warning(f"[SCREENSHOT] API returned {resp.status_code} or empty image")
            return ""

    except Exception as e:
        log.warning(f"[SCREENSHOT] API fallback failed: {e}")
        return ""


def take_screenshot(target: str, scan_id: str) -> str:
    """
    Take screenshot — tries Playwright first, falls back to thum.io API.
    Returns path to screenshot file, or "" if both fail.
    """
    url = target if target.startswith("http") else f"https://{target}"
    filename = os.path.join(SCREENSHOTS_DIR, f"screenshot_{scan_id}.png")

    log.info(f"[SCREENSHOT] Taking screenshot of: {url}")

    # Try Playwright first (works locally on Mac)
    result = _take_playwright(url, filename)
    if result:
        return result

    # Fallback to free API (works on Render)
    log.info("[SCREENSHOT] Playwright unavailable — using API fallback")
    result = _take_api(url, filename)
    if result:
        return result

    log.error("[SCREENSHOT] ❌ Both methods failed")
    return ""
