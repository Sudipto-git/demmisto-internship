"""
╔══════════════════════════════════════════╗
║   ALERT: WhatsApp Notification          ║
║   Uses Twilio WhatsApp API              ║
╚══════════════════════════════════════════╝

Setup:
1. Create free account at twilio.com
2. Enable WhatsApp sandbox at:
   console.twilio.com/us1/develop/sms/try-it-out/whatsapp-learn
3. Send "join <sandbox-word>" to +14155238886 on WhatsApp
4. Fill TWILIO_* keys in .env
"""

import logging
from datetime import datetime
from config import (
    WA_ENABLED, TWILIO_SID, TWILIO_TOKEN,
    TWILIO_WA_FROM, TWILIO_WA_TO
)

log = logging.getLogger(__name__)


def send_whatsapp_alert(report: dict) -> dict:
    """Send WhatsApp alert via Twilio"""

    if not WA_ENABLED:
        return {"status": "skipped", "reason": "WhatsApp alerts disabled in .env"}

    if not all([TWILIO_SID, TWILIO_TOKEN, TWILIO_WA_FROM, TWILIO_WA_TO]):
        return {"status": "error", "reason": "Twilio credentials not set in .env"}

    try:
        from twilio.rest import Client
    except ImportError:
        return {"status": "error", "reason": "twilio not installed. Run: pip3 install twilio"}

    threat_level = report.get("threat_level", "UNKNOWN")
    target_type  = report.get("target_type",  "unknown")
    scan_id      = report.get("scan_id",      "N/A")
    ai_analysis  = report.get("ai_analysis",  "")

    # ── Build WhatsApp message ────────────────────────
    emoji = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
        "CLEAN":    "✅"
    }.get(threat_level, "⚪")

    # Extract first meaningful line from AI analysis
    summary = ""
    for line in ai_analysis.split("\n"):
        line = line.strip().replace("**", "")
        if line and "THREAT SUMMARY" not in line and len(line) > 20:
            summary = line[:200]
            break

    message = (
        f"{emoji} *DARKWEB MONITOR ALERT*\n\n"
        f"*Threat Level:* {threat_level}\n"
        f"*Scan Type:* {target_type.upper()}\n"
        f"*Scan ID:* {scan_id}\n"
        f"*Time:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        f"*Summary:*\n{summary}\n\n"
        f"_Check dashboard for full report._"
    )

    try:
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        msg = client.messages.create(
            from_=TWILIO_WA_FROM,
            to=TWILIO_WA_TO,
            body=message
        )

        log.info(f"[WHATSAPP] Alert sent. SID: {msg.sid}")
        return {
            "status":    "sent",
            "sid":       msg.sid,
            "recipient": TWILIO_WA_TO
        }

    except Exception as e:
        log.error(f"[WHATSAPP] Send failed: {e}")
        return {"status": "error", "reason": str(e)}
