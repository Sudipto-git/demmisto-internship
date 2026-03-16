"""
╔══════════════════════════════════════════╗
║   ALERT: Telegram Notification          ║
║   Fixed: plain text + screenshot        ║
╚══════════════════════════════════════════╝
"""

import os
import requests
import logging
import time
from datetime import datetime
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TG_ENABLED

log = logging.getLogger(__name__)
TG_API = "https://api.telegram.org/bot"


def _clean_text(text: str) -> str:
    """Strip all markdown to prevent Telegram parse errors"""
    return (
        text.replace("**", "")
        .replace("*", "")
        .replace("`", "")
        .replace("#", "")
        .replace("[", "(")
        .replace("]", ")")
        .replace("<", "")
        .replace(">", "")
        .strip()
    )


def _post_with_retry(url, payload=None, files=None, retries=3, delay=2) -> dict:
    """POST to Telegram with retry + exponential backoff"""
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            if files:
                resp = requests.post(url, data=payload, files=files, timeout=20)
            else:
                resp = requests.post(url, json=payload, timeout=20)

            data = resp.json()
            if data.get("ok"):
                return data

            err = data.get("description", "Unknown error")
            log.warning(f"[TELEGRAM] Attempt {attempt} failed: {err}")
            last_error = err

            if resp.status_code in [400, 401, 403]:
                break

        except requests.exceptions.Timeout:
            last_error = "Timed out"
            log.warning(f"[TELEGRAM] Attempt {attempt} timed out")
        except requests.exceptions.ConnectionError:
            last_error = "Connection error"
            log.warning(f"[TELEGRAM] Attempt {attempt} connection error")
        except Exception as e:
            last_error = str(e)
            log.warning(f"[TELEGRAM] Attempt {attempt} error: {e}")

        if attempt < retries:
            time.sleep(delay * attempt)

    return {"ok": False, "description": last_error}


def send_telegram_alert(report: dict) -> dict:
    """Send plain text alert"""

    if not TG_ENABLED:
        return {"status": "skipped", "reason": "Telegram disabled"}

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {"status": "error", "reason": "Bot token or chat ID not set"}

    threat_level = report.get("threat_level", "UNKNOWN")
    target_type = report.get("target_type", "unknown")
    target = report.get("target", "N/A")
    scan_id = report.get("scan_id", "N/A")
    ai_analysis = _clean_text(report.get("ai_analysis", ""))
    completed_at = report.get("completed_at", datetime.utcnow().isoformat())

    emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "CLEAN": "✅",
    }.get(threat_level, "⚪")

    # First meaningful AI summary line
    summary = ""
    for line in ai_analysis.split("\n"):
        line = line.strip()
        if line and "THREAT SUMMARY" not in line.upper() and len(line) > 20:
            summary = line[:300]
            break
    if not summary:
        summary = "No summary available."

    message = (
        f"{emoji} DARKWEB MONITOR ALERT\n"
        f"{'─' * 30}\n"
        f"Target  : {target}\n"
        f"Type    : {target_type.upper()}\n"
        f"Threat  : {threat_level}\n"
        f"Scan ID : {scan_id}\n"
        f"Time    : {completed_at[:19]} UTC\n"
        f"{'─' * 30}\n"
        f"AI Summary:\n{summary}\n"
        f"{'─' * 30}\n"
        f"DARKWEB MONITOR v2.0"
    )

    data = _post_with_retry(
        f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendMessage",
        {"chat_id": TELEGRAM_CHAT_ID, "text": message},
    )

    if data.get("ok"):
        log.info(f"[TELEGRAM] ✅ Alert sent. ID: {data['result']['message_id']}")
        return {"status": "sent", "message_id": data["result"]["message_id"]}
    else:
        err = data.get("description", "Unknown")
        log.error(f"[TELEGRAM] ❌ Failed: {err}")
        return {"status": "error", "reason": err}


def send_telegram_screenshot(
    screenshot_path: str, scan_id: str, target: str, threat_level: str
) -> dict:
    """Send screenshot — file if exists, otherwise fetch from thum.io directly"""

    if not TG_ENABLED:
        return {"status": "skipped"}

    emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "CLEAN": "✅",
    }.get(threat_level, "⚪")

    caption = (
        f"{emoji} SITE SCREENSHOT\n"
        f"Target  : {target}\n"
        f"Threat  : {threat_level}\n"
        f"Scan ID : {scan_id}"
    )

    # Try file first
    if screenshot_path and os.path.exists(screenshot_path):
        try:
            with open(screenshot_path, "rb") as f:
                data = _post_with_retry(
                    f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendPhoto",
                    payload={"chat_id": TELEGRAM_CHAT_ID, "caption": caption},
                    files={"photo": f},
                )
            if data.get("ok"):
                log.info(f"[TELEGRAM] ✅ Screenshot sent from file: {scan_id}")
                return {"status": "sent"}
        except Exception as e:
            log.warning(f"[TELEGRAM] File screenshot failed: {e}")

    # Screenshot APIs — no key needed, tried in order
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    url = target if target.startswith("http") else f"https://{target}"

    screenshot_apis = [
        # 1. thum.io — reliable, free, no key
        (f"https://image.thum.io/get/width/1280/crop/800/{url}", "thum.io"),
        # 2. s-shot.ru — free, no key
        (f"https://mini.s-shot.ru/1280x800/PNG/1024/Z100/?{url}", "s-shot"),
        # 3. screenshotapi via free proxy
        (
            f"https://shot.screenshotapi.net/screenshot?url={url}&width=1280&height=800&output=image&file_type=png&wait_for_event=load",
            "screenshotapi",
        ),
    ]

    for api_url, api_name in screenshot_apis:
        try:
            log.info(f"[TELEGRAM] Trying {api_name}...")
            resp = requests.get(
                api_url,
                timeout=30,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )
            content_type = resp.headers.get("content-type", "")
            # Must be real image — check content type AND size AND not a placeholder
            is_real_image = (
                "image/png" in content_type or "image/jpeg" in content_type
            ) and len(
                resp.content
            ) > 50000  # real screenshots are >50KB

            if resp.status_code == 200 and is_real_image:
                data = _post_with_retry(
                    f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendPhoto",
                    payload={"chat_id": TELEGRAM_CHAT_ID, "caption": caption},
                    files={"photo": ("screenshot.png", resp.content, "image/png")},
                )
                if data.get("ok"):
                    log.info(f"[TELEGRAM] ✅ Screenshot sent via {api_name}: {scan_id}")
                    return {"status": "sent"}
                else:
                    err = data.get("description", "Unknown")
                    log.warning(f"[TELEGRAM] {api_name} send failed: {err}")
            else:
                log.warning(
                    f"[TELEGRAM] {api_name} returned {resp.status_code} size={len(resp.content)}"
                )
        except Exception as e:
            log.warning(f"[TELEGRAM] {api_name} error: {e}")
            continue

    log.error("[TELEGRAM] All screenshot APIs failed")
    return {"status": "error", "reason": "All screenshot APIs failed"}


def send_telegram_pdf(pdf_path: str, scan_id: str, threat_level: str) -> dict:
    """Send PDF report"""

    if not TG_ENABLED:
        return {"status": "skipped"}

    if not pdf_path:
        return {"status": "skipped", "reason": "No PDF path"}

    try:
        with open(pdf_path, "rb") as f:
            data = _post_with_retry(
                f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendDocument",
                payload={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "caption": f"Threat Report {scan_id} — {threat_level}",
                },
                files={"document": f},
            )

        if data.get("ok"):
            log.info(f"[TELEGRAM] ✅ PDF sent: {scan_id}")
            return {"status": "sent"}
        else:
            err = data.get("description", "Unknown")
            log.error(f"[TELEGRAM] ❌ PDF failed: {err}")
            return {"status": "error", "reason": err}

    except FileNotFoundError:
        return {"status": "error", "reason": "PDF not found"}
    except Exception as e:
        log.error(f"[TELEGRAM] PDF send failed: {e}")
        return {"status": "error", "reason": str(e)}


def send_telegram_simple(message: str) -> dict:
    """Plain text test message"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {"status": "error", "reason": "Keys not set"}
    data = _post_with_retry(
        f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendMessage",
        {"chat_id": TELEGRAM_CHAT_ID, "text": message},
    )
    return (
        {"status": "sent"}
        if data.get("ok")
        else {"status": "error", "reason": data.get("description")}
    )
