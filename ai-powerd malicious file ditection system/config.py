"""
╔══════════════════════════════════════════╗
║   DARKWEB MONITOR — Central Config      ║
╚══════════════════════════════════════════╝
All settings loaded from .env file.
Never hardcode keys here.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ───────────────────────────────────────────
VT_API_KEY    = os.getenv("VT_API_KEY",    "")
GROQ_API_KEY  = os.getenv("GROQ_API_KEY",  "")
API_SECRET    = os.getenv("API_SECRET",    "darkweb_secret_2024")

# ── Groq Model ─────────────────────────────────────────
GROQ_MODEL    = "llama-3.3-70b-versatile"
GROQ_BASE_URL = "https://api.groq.com/openai/v1/chat/completions"

# ── VirusTotal ─────────────────────────────────────────
VT_BASE_URL   = "https://www.virustotal.com/api/v3"

# ── Email Alert Settings ───────────────────────────────
EMAIL_ENABLED  = os.getenv("EMAIL_ENABLED",  "false").lower() == "true"
EMAIL_SENDER   = os.getenv("EMAIL_SENDER",   "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "")
EMAIL_SMTP     = os.getenv("EMAIL_SMTP",     "smtp.gmail.com")
EMAIL_PORT     = int(os.getenv("EMAIL_PORT", "587"))

# ── WhatsApp Alert Settings (Twilio) ──────────────────
WA_ENABLED         = os.getenv("WA_ENABLED",         "false").lower() == "true"
TWILIO_SID         = os.getenv("TWILIO_SID",         "")
TWILIO_TOKEN       = os.getenv("TWILIO_TOKEN",       "")
TWILIO_WA_FROM     = os.getenv("TWILIO_WA_FROM",     "")  # whatsapp:+14155238886
TWILIO_WA_TO       = os.getenv("TWILIO_WA_TO",       "")  # whatsapp:+91xxxxxxxxxx

# ── Alert Thresholds ───────────────────────────────────
# Only alert if threat level is in this list
ALERT_ON_LEVELS = ["CRITICAL", "HIGH", "MEDIUM"]

# ── PDF Report ─────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports", "output")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Pastebin Monitor ───────────────────────────────────
PASTE_MONITOR_KEYWORDS = os.getenv(
    "PASTE_KEYWORDS",
    "password,leaked,hack,breach,credentials,dump,exploit"
).split(",")

PASTE_MONITOR_DOMAINS  = os.getenv(
    "PASTE_DOMAINS", ""
).split(",")   # comma separated domains to watch

# ── Flask ──────────────────────────────────────────────
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = 5000
FLASK_DEBUG = False
