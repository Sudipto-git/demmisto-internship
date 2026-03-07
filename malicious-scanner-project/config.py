"""
╔══════════════════════════════════════════╗
║   DARKWEB MONITOR — Central Config      ║
╚══════════════════════════════════════════╝
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ───────────────────────────────────────────
VT_API_KEY    = os.getenv("VT_API_KEY",    "")
GROQ_API_KEY  = os.getenv("GROQ_API_KEY",  "")
API_SECRET    = os.getenv("API_SECRET",    "darkweb_secret_2024")

# ── Groq ───────────────────────────────────────────────
GROQ_MODEL    = "llama-3.3-70b-versatile"
GROQ_BASE_URL = "https://api.groq.com/openai/v1/chat/completions"

# ── VirusTotal ─────────────────────────────────────────
VT_BASE_URL   = "https://www.virustotal.com/api/v3"

# ── Telegram ───────────────────────────────────────────
TG_ENABLED         = os.getenv("TG_ENABLED",         "true").lower() == "true"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",   "")

# ── Alert Thresholds ───────────────────────────────────
ALERT_ON_LEVELS = ["CRITICAL", "HIGH", "MEDIUM"]

# ── PDF Report ─────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "output")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Pastebin Monitor ───────────────────────────────────
PASTE_MONITOR_KEYWORDS = os.getenv(
    "PASTE_KEYWORDS",
    "password,leaked,hack,breach,credentials,dump,exploit"
).split(",")

PASTE_MONITOR_DOMAINS = os.getenv(
    "PASTE_DOMAINS", ""
).split(",")

# ── Flask ──────────────────────────────────────────────
# Render uses PORT env variable — fallback to 5001 for local
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = int(os.getenv("PORT", os.getenv("FLASK_PORT", "5001")))
FLASK_DEBUG = False
