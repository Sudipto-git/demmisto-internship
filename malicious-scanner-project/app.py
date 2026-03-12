"""
╔══════════════════════════════════════════════════════════╗
║         DARKWEB MONITOR — Main Flask API v2.0           ║
╠══════════════════════════════════════════════════════════╣
║  Endpoints:                                             ║
║   GET  /api/health                                      ║
║   POST /api/scan/domain                                 ║
║   POST /api/scan/ip                                     ║
║   POST /api/scan/paste                                  ║
║   POST /api/analyze                                     ║
║   POST /api/scan/full                                   ║
║   GET  /api/report/<scan_id>   (download PDF)           ║
╚══════════════════════════════════════════════════════════╝

Run: python3 app.py
"""

import sys
import os

# ── Ensure current directory is in path ───────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uuid
import logging
from datetime import datetime

from flask      import Flask, request, jsonify, send_file
from flask_cors import CORS

from config         import API_SECRET, FLASK_HOST, FLASK_PORT, FLASK_DEBUG, ALERT_ON_LEVELS, REPORTS_DIR
from domain_osint   import scan_domain
from ip_scanner     import scan_ip
from paste_monitor  import monitor_pastes
from ai_analyst     import analyze
from telegram_alert import send_telegram_alert, send_telegram_pdf, send_telegram_screenshot
from pdf_report     import generate_pdf
from screenshot     import take_screenshot

# ── Logging ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("darkweb_monitor.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)


# ── Auth ───────────────────────────────────────────────
def auth():
    return request.headers.get("X-API-Secret", "") == API_SECRET


# ══════════════════════════════════════════════════════
#  HEALTH
# ══════════════════════════════════════════════════════
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "online",
        "service":   "DARKWEB MONITOR v2.0",
        "timestamp": datetime.utcnow().isoformat(),
        "modules":   ["domain_osint", "ip_scanner", "paste_monitor", "ai_analyst", "screenshot"],
        "alerts":    ["telegram"],
        "reports":   ["pdf"]
    }), 200


# ══════════════════════════════════════════════════════
#  DOMAIN SCAN
# ══════════════════════════════════════════════════════
@app.route("/api/scan/domain", methods=["POST"])
def api_scan_domain():
    if not auth():
        return jsonify({"error": "Unauthorized"}), 401
    data   = request.get_json() or {}
    target = data.get("domain", "").strip()
    if not target:
        return jsonify({"error": "Missing field: domain"}), 400
    return jsonify(scan_domain(target)), 200


# ══════════════════════════════════════════════════════
#  IP SCAN
# ══════════════════════════════════════════════════════
@app.route("/api/scan/ip", methods=["POST"])
def api_scan_ip():
    if not auth():
        return jsonify({"error": "Unauthorized"}), 401
    data   = request.get_json() or {}
    target = data.get("ip", "").strip()
    if not target:
        return jsonify({"error": "Missing field: ip"}), 400
    return jsonify(scan_ip(target)), 200


# ══════════════════════════════════════════════════════
#  PASTE MONITOR
# ══════════════════════════════════════════════════════
@app.route("/api/scan/paste", methods=["POST"])
def api_scan_paste():
    if not auth():
        return jsonify({"error": "Unauthorized"}), 401
    data     = request.get_json() or {}
    keywords = data.get("keywords", [])
    domains  = data.get("domains",  [])
    return jsonify(monitor_pastes(keywords or None, domains or None)), 200


# ══════════════════════════════════════════════════════
#  GROQ AI ANALYSIS
# ══════════════════════════════════════════════════════
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if not auth():
        return jsonify({"error": "Unauthorized"}), 401
    data        = request.get_json() or {}
    scan_result = data.get("scan_result", {})
    target_type = data.get("target_type", "unknown")
    if not scan_result:
        return jsonify({"error": "Missing field: scan_result"}), 400
    return jsonify(analyze(scan_result, target_type)), 200


# ══════════════════════════════════════════════════════
#  FULL SCAN — scan + screenshot + AI + PDF + Telegram
# ══════════════════════════════════════════════════════
@app.route("/api/scan/full", methods=["POST"])
def api_full_scan():
    if not auth():
        return jsonify({"error": "Unauthorized"}), 401

    data        = request.get_json() or {}
    target      = data.get("target", "").strip()
    target_type = data.get("type",   "").strip().lower()

    if not target or not target_type:
        return jsonify({"error": "Missing fields: target and type (domain|ip|paste)"}), 400

    scan_id = f"DWM-{uuid.uuid4().hex[:8].upper()}"
    log.info(f"[FULL SCAN] {scan_id} | {target_type}: {target}")

    # ── Step 1: Scan ──────────────────────────────────
    if target_type == "domain":
        scan_result = scan_domain(target)
    elif target_type == "ip":
        scan_result = scan_ip(target)
    elif target_type == "paste":
        scan_result = monitor_pastes(
            keywords=data.get("keywords") or None,
            domains=data.get("domains")   or None
        )
    else:
        return jsonify({"error": f"Invalid type '{target_type}'. Use: domain|ip|paste"}), 400

    # ── Step 2: AI Analysis ───────────────────────────
    ai_result = analyze(scan_result, target_type)

    # ── Step 3: Build report ──────────────────────────
    threat_level = (
        scan_result.get("threat_level") or
        scan_result.get("virustotal", {}).get("threat_level", "UNKNOWN")
    )

    # Use AI verdict as fallback if VT failed
    if threat_level in ["CLEAN", "UNKNOWN"]:
        ai_text = ai_result.get("ai_analysis", "").upper()
        if "CRITICAL" in ai_text:
            threat_level = "CRITICAL"
        elif "HIGH" in ai_text:
            threat_level = "HIGH"
        elif "MEDIUM" in ai_text:
            threat_level = "MEDIUM"

    report = {
        "scan_id":      scan_id,
        "target":       target,
        "target_type":  target_type,
        "threat_level": threat_level,
        "scan_result":  scan_result,
        "ai_analysis":  ai_result.get("ai_analysis", ""),
        "model":        ai_result.get("model", ""),
        "tokens_used":  ai_result.get("tokens_used", 0),
        "completed_at": datetime.utcnow().isoformat()
    }

    # ── Step 4: Screenshot ────────────────────────────
    screenshot_path = ""
    if target_type in ["domain", "ip"]:
        try:
            log.info(f"[FULL SCAN] Taking screenshot of {target}...")
            screenshot_path = take_screenshot(target, scan_id)
            if screenshot_path:
                report["screenshot_path"] = screenshot_path
                log.info(f"[FULL SCAN] Screenshot saved: {screenshot_path}")
            else:
                log.warning("[FULL SCAN] Screenshot returned empty path")
        except Exception as e:
            log.warning(f"[FULL SCAN] Screenshot failed: {e}")

    # ── Step 5: Generate PDF ──────────────────────────
    pdf_path = ""
    try:
        pdf_path = generate_pdf(report)
        report["pdf_url"] = f"/api/report/{scan_id}"
        log.info(f"[FULL SCAN] PDF: {pdf_path}")
    except Exception as e:
        log.warning(f"[FULL SCAN] PDF failed: {e}")
        report["pdf_error"] = str(e)

    # ── Step 6: Telegram alerts ───────────────────────
    alerts_sent = {}
    if threat_level in ALERT_ON_LEVELS:
        log.info(f"[FULL SCAN] Sending Telegram alerts for {threat_level}...")

        # 1. Text alert
        alerts_sent["telegram"] = send_telegram_alert(report)

        # 2. Screenshot (sent before PDF so user sees site first)
        if screenshot_path:
            alerts_sent["telegram_screenshot"] = send_telegram_screenshot(
                screenshot_path, scan_id, target, threat_level
            )
        else:
            alerts_sent["telegram_screenshot"] = {"status": "skipped", "reason": "No screenshot"}

        # 3. PDF report
        alerts_sent["telegram_pdf"] = send_telegram_pdf(pdf_path, scan_id, threat_level)

        report["alerts_sent"] = alerts_sent
        log.info(f"[FULL SCAN] Alerts: {alerts_sent}")
    else:
        report["alerts_sent"] = {"reason": f"No alert — threat is {threat_level}"}

    log.info(f"[FULL SCAN] Complete: {scan_id} | {threat_level}")
    return jsonify(report), 200


# ══════════════════════════════════════════════════════
#  DOWNLOAD PDF
# ══════════════════════════════════════════════════════
@app.route("/api/report/<scan_id>", methods=["GET"])
def download_report(scan_id):
    pdf_file = os.path.join(REPORTS_DIR, f"threat_report_{scan_id}.pdf")
    if not os.path.exists(pdf_file):
        return jsonify({"error": f"Report not found: {scan_id}"}), 404
    return send_file(pdf_file, as_attachment=True,
                     download_name=f"threat_report_{scan_id}.pdf")


# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    log.info("╔══════════════════════════════════════════╗")
    log.info("║   DARKWEB MONITOR v2.0 — Starting...    ║")
    log.info("╚══════════════════════════════════════════╝")
    log.info(f"📡  http://{FLASK_HOST}:{FLASK_PORT}")
    log.info(f"📁  Reports : {REPORTS_DIR}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
