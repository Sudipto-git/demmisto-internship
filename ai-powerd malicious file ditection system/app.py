"""
╔══════════════════════════════════════════════════════════╗
║         DARKWEB MONITOR — Main Flask API                ║
║         Version 2.0 — Full Production Build             ║
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

import os
import json
import logging
import uuid
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from config import API_SECRET, FLASK_HOST, FLASK_PORT, ALERT_ON_LEVELS, REPORTS_DIR

from modules.domain_osint  import scan_domain
from modules.ip_scanner    import scan_ip
from modules.paste_monitor import monitor_pastes
from modules.ai_analyst    import analyze

from alerts.email_alert     import send_email_alert
from alerts.whatsapp_alert  import send_whatsapp_alert

from reports.pdf_report     import generate_pdf

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


# ══════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════
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
        "modules":   ["domain_osint", "ip_scanner", "paste_monitor", "ai_analyst"],
        "alerts":    ["email", "whatsapp"],
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

    result = scan_domain(target)
    return jsonify(result), 200


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

    result = scan_ip(target)
    return jsonify(result), 200


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

    result = monitor_pastes(
        keywords=keywords or None,
        domains=domains   or None
    )
    return jsonify(result), 200


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

    result = analyze(scan_result, target_type)
    return jsonify(result), 200


# ══════════════════════════════════════════════════════
#  FULL SCAN — scan + AI + alerts + PDF
# ══════════════════════════════════════════════════════
@app.route("/api/scan/full", methods=["POST"])
def api_full_scan():
    """
    Complete automated pipeline:
    1. Run scan (domain / ip / paste)
    2. Groq AI analysis
    3. Generate PDF report
    4. Send email + WhatsApp alerts if threat level warrants
    5. Return full report
    """
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
    scan_result = {}
    if target_type == "domain":
        scan_result = scan_domain(target)
    elif target_type == "ip":
        scan_result = scan_ip(target)
    elif target_type == "paste":
        keywords = data.get("keywords", [])
        domains  = data.get("domains",  [])
        scan_result = monitor_pastes(keywords or None, domains or None)
    else:
        return jsonify({"error": f"Invalid type '{target_type}'. Use: domain|ip|paste"}), 400

    # ── Step 2: AI Analysis ───────────────────────────
    ai_result = analyze(scan_result, target_type)

    # ── Step 3: Build report object ───────────────────
    threat_level = (
        scan_result.get("threat_level") or
        scan_result.get("virustotal", {}).get("threat_level", "UNKNOWN")
    )

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

    # ── Step 4: Generate PDF ──────────────────────────
    pdf_path = ""
    try:
        pdf_path = generate_pdf(report)
        report["pdf_path"] = pdf_path
        report["pdf_url"]  = f"/api/report/{scan_id}"
        log.info(f"[FULL SCAN] PDF generated: {pdf_path}")
    except Exception as e:
        log.warning(f"[FULL SCAN] PDF generation failed: {e}")
        report["pdf_error"] = str(e)

    # ── Step 5: Send alerts if threat warrants ────────
    alerts_sent = {}
    if threat_level in ALERT_ON_LEVELS:
        log.info(f"[FULL SCAN] Threat level {threat_level} — sending alerts...")

        alerts_sent["email"]     = send_email_alert(report, pdf_path or None)
        alerts_sent["whatsapp"]  = send_whatsapp_alert(report)

        report["alerts_sent"] = alerts_sent
        log.info(f"[FULL SCAN] Alerts: {alerts_sent}")
    else:
        report["alerts_sent"] = {"reason": f"No alert — threat level is {threat_level}"}

    log.info(f"[FULL SCAN] Complete: {scan_id} | {threat_level}")
    return jsonify(report), 200


# ══════════════════════════════════════════════════════
#  DOWNLOAD PDF REPORT
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
    log.info(f"📡  API running at http://{FLASK_HOST}:{FLASK_PORT}")
    log.info(f"📁  Reports saved to: {REPORTS_DIR}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
