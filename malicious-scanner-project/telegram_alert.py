"""
╔══════════════════════════════════════════╗
║   ALERT: Telegram Notification          ║
║   Uses Telegram Bot API (free)          ║
╚══════════════════════════════════════════╝
"""

import requests
import logging
from datetime import datetime
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TG_ENABLED

log = logging.getLogger(__name__)
TG_API = "https://api.telegram.org/bot"


def send_telegram_alert(report: dict) -> dict:
    if not TG_ENABLED:
        return {"status": "skipped", "reason": "Telegram disabled in .env"}

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {"status": "error", "reason": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set"}

    threat_level = report.get("threat_level", "UNKNOWN")
    target_type  = report.get("target_type",  "unknown")
    target       = report.get("target",       "N/A")
    scan_id      = report.get("scan_id",      "N/A")
    ai_analysis  = report.get("ai_analysis",  "")
    completed_at = report.get("completed_at", datetime.utcnow().isoformat())

    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
             "LOW": "🟢", "CLEAN": "✅"}.get(threat_level, "⚪")

    # Extract first meaningful summary line
    summary = ""
    for line in ai_analysis.split("\n"):
        line = line.strip().replace("**", "")
        if line and "THREAT SUMMARY" not in line and len(line) > 20:
            summary = line[:300]
            break

    message = (
        f"{emoji} *DARKWEB MONITOR ALERT*\n"
        f"{'─' * 30}\n"
        f"🎯 *Target:* `{target}`\n"
        f"📌 *Type:* `{target_type.upper()}`\n"
        f"⚠️ *Threat Level:* *{threat_level}*\n"
        f"🆔 *Scan ID:* `{scan_id}`\n"
        f"🕐 *Time:* `{completed_at[:19]} UTC`\n"
        f"{'─' * 30}\n"
        f"🤖 *AI Summary:*\n{summary}\n"
        f"{'─' * 30}\n"
        f"_DARKWEB MONITOR v2.0_"
    )

    try:
        resp = requests.post(
            f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id":    TELEGRAM_CHAT_ID,
                "text":       message,
                "parse_mode": "Markdown"
            },
            timeout=15
        )
        data = resp.json()
        if data.get("ok"):
            log.info(f"[TELEGRAM] Alert sent. ID: {data['result']['message_id']}")
            return {"status": "sent", "message_id": data["result"]["message_id"]}
        else:
            return {"status": "error", "reason": data.get("description", "Unknown")}
    except Exception as e:
        log.error(f"[TELEGRAM] Failed: {e}")
        return {"status": "error", "reason": str(e)}


def send_telegram_pdf(pdf_path: str, scan_id: str, threat_level: str) -> dict:
    if not TG_ENABLED or not pdf_path:
        return {"status": "skipped"}
    try:
        with open(pdf_path, "rb") as f:
            resp = requests.post(
                f"{TG_API}{TELEGRAM_BOT_TOKEN}/sendDocument",
                data={
                    "chat_id":    TELEGRAM_CHAT_ID,
                    "caption":    f"📄 Report `{scan_id}` — *{threat_level}*",
                    "parse_mode": "Markdown"
                },
                files={"document": f},
                timeout=30
            )
        data = resp.json()
        if data.get("ok"):
            log.info(f"[TELEGRAM] PDF sent: {scan_id}")
            return {"status": "sent"}
        return {"status": "error", "reason": data.get("description")}
    except Exception as e:
        log.error(f"[TELEGRAM] PDF failed: {e}")
        return {"status": "error", "reason": str(e)}
