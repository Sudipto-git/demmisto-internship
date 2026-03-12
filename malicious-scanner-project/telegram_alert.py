"""
╔══════════════════════════════════════════╗
║   ALERT: Telegram Notification          ║
║   With retry logic + connection fix     ║
╚══════════════════════════════════════════╝
"""

import requests
import logging
import time
from datetime import datetime
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TG_ENABLED

log = logging.getLogger(__name__)
TG_API = "https://api.telegram.org/bot"


def _post_with_retry(url, payload=None, files=None, retries=3, delay=2) -> dict:
    """POST to Telegram with retry logic"""
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

            err = data.get("description", "Unknown Telegram error")
            log.warning(f"[TELEGRAM] Attempt {attempt} failed: {err}")
            last_error = err

            # Don't retry on permanent errors
            if resp.status_code in [400, 401, 403]:
                break

        except requests.exceptions.Timeout:
            log.warning(f"[TELEGRAM] Attempt {attempt} timed out")
            last_error = "Request timed out"
        except requests.exceptions.ConnectionError:
            log.warning(f"[TELEGRAM] Attempt {attempt} connection error")
            last_error = "Connection error"
        except Exception as e:
            log.warning(f"[TELEGRAM] Attempt {attempt} error: {e}")
            last_error = str(e)

        if attempt < retries:
            time.sleep(delay * attempt)  # exponential backoff

    return {"ok": False, "description": last_error}


def send_telegram_alert(report: dict) -> dict:
    """Send Telegram alert with scan report"""

    if not TG_ENABLED:
        return {"status": "skipped", "reason": "Telegram disabled in .env"}

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {
            "status": "error",
            "reason": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set",
        }

    threat_level = report.get("threat_level", "UNKNOWN")
    target_type = report.get("target_type", "unknown")
    target = report.get("target", "N/A")
    scan_id = report.get("scan_id", "N/A")
    ai_analysis = report.get("ai_analysis", "")
    completed_at = report.get("completed_at", datetime.utcnow().isoformat())

    emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "CLEAN": "✅",
    }.get(threat_level, "⚪")

    # Extract first meaningful AI summary line
    summary = ""
    for line in ai_analysis.split("\n"):
        line = line.strip().replace("**", "")
        if line and "THREAT SUMMARY" not in line and len(line) > 20:
            summary = line[:300]
            break
    if not summary:
        summary = "No AI summary available."

    # Escape special markdown chars for Telegram
    def safe(text):
        return (
            str(text)
            .replace("_", "\\_")
            .replace("*", "\\*")
            .replace("`", "\\`")
            .replace("[", "\\[")
        )

    message = (
        f"{emoji} *DARKWEB MONITOR ALERT*\n"
        f"{'─' * 28}\n"
        f"🎯 *Target:* `{target}`\n"
        f"📌 *Type:* `{target_type.upper()}`\n"
        f"⚠️ *Threat:* *{threat_level}*\n"
        f"🆔 *Scan ID:* `{scan_id}`\n"
        f"🕐 *Time:* `{completed_at[:19]} UTC`\n"
        f"{'─' * 28}\n"
        f"🤖 *AI Summary:*\n{summary}\n"
        f"{'─' * 28}\n"
        f"_DARKWEB MONITOR v2.0_"
    )

    url = f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = _post_with_retry(
        url, {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    )

    if data.get("ok"):
        msg_id = data["result"]["message_id"]
        log.info(f"[TELEGRAM] ✅ Alert sent. Message ID: {msg_id}")
        return {"status": "sent", "message_id": msg_id}
    else:
        err = data.get("description", "Unknown error")
        log.error(f"[TELEGRAM] ❌ Failed after retries: {err}")
        return {"status": "error", "reason": err}


def send_telegram_pdf(pdf_path: str, scan_id: str, threat_level: str) -> dict:
    """Send PDF report as document"""

    if not TG_ENABLED:
        return {"status": "skipped"}

    if not pdf_path:
        return {"status": "skipped", "reason": "No PDF path"}

    try:
        url = f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendDocument"
        with open(pdf_path, "rb") as f:
            data = _post_with_retry(
                url,
                payload={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "caption": f"📄 Report `{scan_id}` — *{threat_level}*",
                    "parse_mode": "Markdown",
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
        log.error(f"[TELEGRAM] PDF file not found: {pdf_path}")
        return {"status": "error", "reason": "PDF file not found"}
    except Exception as e:
        log.error(f"[TELEGRAM] PDF send failed: {e}")
        return {"status": "error", "reason": str(e)}


def send_telegram_simple(message: str) -> dict:
    """Send a plain text message — used for testing"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {"status": "error", "reason": "Keys not set"}

    url = f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = _post_with_retry(url, {"chat_id": TELEGRAM_CHAT_ID, "text": message})
    return (
        {"status": "sent"}
        if data.get("ok")
        else {"status": "error", "reason": data.get("description")}
    )
