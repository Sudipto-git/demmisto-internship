"""
╔══════════════════════════════════════════════════════════╗
║         DARKWEB MONITOR — Kali Flask API Server         ║
║         Step 1: Core API + All Route Handlers           ║
╚══════════════════════════════════════════════════════════╝
Run on Kali: python3 app.py
n8n calls this at: http://<KALI_IP>:5000/api/...
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import requests
import socket
import hashlib
import logging
import os
import json
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ── Logging setup ──────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("darkweb_monitor.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────
VT_API_KEY     = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "YOUR_GROQ_API_KEY")
API_SECRET     = os.getenv("API_SECRET", "darkweb_secret_2024")   # n8n sends this in header

VT_BASE        = "https://www.virustotal.com/api/v3"
GROQ_BASE      = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL     = "llama3-70b-8192"


# ══════════════════════════════════════════════════════════
#  AUTH MIDDLEWARE
# ══════════════════════════════════════════════════════════
def verify_token():
    token = request.headers.get("X-API-Secret", "")
    if token != API_SECRET:
        return False
    return True


# ══════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "DARKWEB MONITOR — Kali API",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "modules": ["hash_scan", "domain_osint", "ip_scan", "username_hunt"]
    }), 200


# ══════════════════════════════════════════════════════════
#  MODULE 1 — FILE HASH SCAN (VirusTotal)
# ══════════════════════════════════════════════════════════
@app.route("/api/scan/hash", methods=["POST"])
def scan_hash():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401

    data    = request.get_json()
    target  = data.get("hash", "").strip()

    if not target:
        return jsonify({"error": "No hash provided"}), 400

    # Validate hash format (MD5 / SHA1 / SHA256)
    if not re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", target):
        return jsonify({"error": "Invalid hash format. Use MD5/SHA1/SHA256"}), 400

    log.info(f"[HASH SCAN] Scanning: {target}")

    try:
        headers  = {"x-apikey": VT_API_KEY}
        response = requests.get(f"{VT_BASE}/files/{target}", headers=headers, timeout=15)

        if response.status_code == 404:
            return jsonify({
                "hash": target,
                "status": "not_found",
                "message": "Hash not found in VirusTotal database",
                "threat_level": "unknown"
            }), 200

        vt_data    = response.json()
        stats      = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) if stats else 0

        threat_level = (
            "CRITICAL"  if malicious >= 10 else
            "HIGH"      if malicious >= 5  else
            "MEDIUM"    if malicious >= 1  else
            "SUSPICIOUS" if suspicious >= 1 else
            "CLEAN"
        )

        result = {
            "hash":          target,
            "status":        "found",
            "threat_level":  threat_level,
            "malicious":     malicious,
            "suspicious":    suspicious,
            "total_engines": total,
            "scan_date":     datetime.utcnow().isoformat(),
            "vt_link":       f"https://www.virustotal.com/gui/file/{target}"
        }

        log.info(f"[HASH SCAN] Result: {threat_level} | {malicious}/{total} engines")
        return jsonify(result), 200

    except requests.exceptions.Timeout:
        return jsonify({"error": "VirusTotal API timeout"}), 504
    except Exception as e:
        log.error(f"[HASH SCAN] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════
#  MODULE 2 — DOMAIN / EMAIL OSINT (theHarvester + whois)
# ══════════════════════════════════════════════════════════
@app.route("/api/scan/domain", methods=["POST"])
def scan_domain():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401

    data   = request.get_json()
    target = data.get("domain", "").strip()

    if not target:
        return jsonify({"error": "No domain provided"}), 400

    log.info(f"[DOMAIN SCAN] Scanning: {target}")
    results = {"domain": target, "scan_date": datetime.utcnow().isoformat()}

    # ── theHarvester ──────────────────────────────────────
    try:
        harvester_cmd = [
            "theHarvester",
            "-d", target,
            "-l", "100",
            "-b", "bing,certspotter,crtsh,otx,threatminer",
            "-f", f"/tmp/harvester_{target}"
        ]
        proc = subprocess.run(
            harvester_cmd,
            capture_output=True, text=True, timeout=60
        )
        raw_output = proc.stdout + proc.stderr

        # Parse emails from output
        emails = list(set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw_output
        )))

        # Parse IPs from output
        ips = list(set(re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_output
        )))
        # Filter out private/localhost IPs
        ips = [ip for ip in ips if not ip.startswith(("127.", "192.168.", "10.", "172."))]

        results["harvester"] = {
            "emails_found": emails,
            "ips_found":    ips,
            "total_emails": len(emails),
            "total_ips":    len(ips)
        }
        log.info(f"[DOMAIN SCAN] Harvester: {len(emails)} emails, {len(ips)} IPs")

    except subprocess.TimeoutExpired:
        results["harvester"] = {"error": "theHarvester timed out"}
    except FileNotFoundError:
        results["harvester"] = {"error": "theHarvester not installed. Run: sudo apt install theharvester"}
    except Exception as e:
        results["harvester"] = {"error": str(e)}

    # ── WHOIS ─────────────────────────────────────────────
    try:
        whois_proc = subprocess.run(
            ["whois", target],
            capture_output=True, text=True, timeout=20
        )
        whois_raw = whois_proc.stdout

        # Extract key fields
        def extract_whois_field(pattern, text):
            match = re.search(pattern, text, re.IGNORECASE)
            return match.group(1).strip() if match else "N/A"

        results["whois"] = {
            "registrar":    extract_whois_field(r"Registrar:\s*(.+)", whois_raw),
            "created":      extract_whois_field(r"Creation Date:\s*(.+)", whois_raw),
            "expires":      extract_whois_field(r"Registry Expiry Date:\s*(.+)", whois_raw),
            "name_servers": re.findall(r"Name Server:\s*(.+)", whois_raw, re.IGNORECASE)[:4],
            "status":       re.findall(r"Domain Status:\s*(.+)", whois_raw, re.IGNORECASE)[:2]
        }
    except Exception as e:
        results["whois"] = {"error": str(e)}

    # ── DNS Resolution ────────────────────────────────────
    try:
        ip = socket.gethostbyname(target)
        results["dns"] = {"resolved_ip": ip, "status": "resolved"}
    except Exception:
        results["dns"] = {"resolved_ip": None, "status": "unresolved"}

    # ── VirusTotal Domain Check ───────────────────────────
    try:
        headers  = {"x-apikey": VT_API_KEY}
        response = requests.get(f"{VT_BASE}/domains/{target}", headers=headers, timeout=15)
        if response.status_code == 200:
            vt_data   = response.json()
            vt_stats  = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = vt_stats.get("malicious", 0)
            results["virustotal"] = {
                "malicious":     malicious,
                "suspicious":    vt_stats.get("suspicious", 0),
                "threat_level":  "HIGH" if malicious >= 3 else "MEDIUM" if malicious >= 1 else "CLEAN",
                "vt_link":       f"https://www.virustotal.com/gui/domain/{target}"
            }
    except Exception as e:
        results["virustotal"] = {"error": str(e)}

    return jsonify(results), 200


# ══════════════════════════════════════════════════════════
#  MODULE 3 — IP ADDRESS SCAN
# ══════════════════════════════════════════════════════════
@app.route("/api/scan/ip", methods=["POST"])
def scan_ip():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401

    data   = request.get_json()
    target = data.get("ip", "").strip()

    if not target:
        return jsonify({"error": "No IP provided"}), 400

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return jsonify({"error": "Invalid IP format"}), 400

    log.info(f"[IP SCAN] Scanning: {target}")
    results = {"ip": target, "scan_date": datetime.utcnow().isoformat()}

    # ── Nmap quick scan ───────────────────────────────────
    try:
        nmap_proc = subprocess.run(
            ["nmap", "-sV", "--open", "-T4", "--top-ports", "100", target],
            capture_output=True, text=True, timeout=90
        )
        nmap_output = nmap_proc.stdout

        # Parse open ports
        ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", nmap_output)
        open_ports = [{"port": p[0], "service": p[1], "version": p[2].strip()} for p in ports]

        results["nmap"] = {
            "open_ports":   open_ports,
            "total_open":   len(open_ports),
            "raw_summary":  nmap_output[:500]   # truncated for n8n
        }
        log.info(f"[IP SCAN] Nmap: {len(open_ports)} open ports")

    except subprocess.TimeoutExpired:
        results["nmap"] = {"error": "Nmap scan timed out"}
    except FileNotFoundError:
        results["nmap"] = {"error": "nmap not installed"}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    # ── VirusTotal IP check ───────────────────────────────
    try:
        headers  = {"x-apikey": VT_API_KEY}
        response = requests.get(f"{VT_BASE}/ip_addresses/{target}", headers=headers, timeout=15)
        if response.status_code == 200:
            vt_data   = response.json()
            attrs     = vt_data.get("data", {}).get("attributes", {})
            vt_stats  = attrs.get("last_analysis_stats", {})
            malicious = vt_stats.get("malicious", 0)
            results["virustotal"] = {
                "malicious":     malicious,
                "suspicious":    vt_stats.get("suspicious", 0),
                "country":       attrs.get("country", "N/A"),
                "as_owner":      attrs.get("as_owner", "N/A"),
                "threat_level":  "HIGH" if malicious >= 3 else "MEDIUM" if malicious >= 1 else "CLEAN",
                "vt_link":       f"https://www.virustotal.com/gui/ip-address/{target}"
            }
    except Exception as e:
        results["virustotal"] = {"error": str(e)}

    # ── Reverse DNS ───────────────────────────────────────
    try:
        hostname = socket.gethostbyaddr(target)[0]
        results["reverse_dns"] = hostname
    except Exception:
        results["reverse_dns"] = "No PTR record"

    return jsonify(results), 200


# ══════════════════════════════════════════════════════════
#  MODULE 4 — USERNAME HUNT (OSINT)
# ══════════════════════════════════════════════════════════
@app.route("/api/scan/username", methods=["POST"])
def scan_username():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401

    data     = request.get_json()
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "No username provided"}), 400

    log.info(f"[USERNAME HUNT] Hunting: {username}")
    results = {"username": username, "scan_date": datetime.utcnow().isoformat()}

    # ── Sherlock ──────────────────────────────────────────
    try:
        sherlock_proc = subprocess.run(
            ["python3", "/usr/share/sherlock/sherlock.py", username,
             "--print-found", "--timeout", "10"],
            capture_output=True, text=True, timeout=120
        )
        raw = sherlock_proc.stdout

        # Parse found profiles
        found_profiles = re.findall(r"\[\+\]\s+(.+?):\s+(https?://\S+)", raw)
        profiles = [{"platform": p[0], "url": p[1]} for p in found_profiles]

        results["sherlock"] = {
            "profiles_found": profiles,
            "total_found":    len(profiles),
            "platforms":      [p[0] for p in found_profiles]
        }
        log.info(f"[USERNAME HUNT] Sherlock: {len(profiles)} profiles found")

    except subprocess.TimeoutExpired:
        results["sherlock"] = {"error": "Sherlock timed out"}
    except FileNotFoundError:
        results["sherlock"] = {"error": "Sherlock not installed. Run: sudo apt install sherlock"}
    except Exception as e:
        results["sherlock"] = {"error": str(e)}

    # ── Manual platform checks ────────────────────────────
    platforms_to_check = {
        "GitHub":   f"https://github.com/{username}",
        "Twitter":  f"https://twitter.com/{username}",
        "Reddit":   f"https://reddit.com/user/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}"
    }

    manual_results = {}
    for platform, url in platforms_to_check.items():
        try:
            resp = requests.head(url, timeout=8, allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0"})
            manual_results[platform] = {
                "url":    url,
                "exists": resp.status_code == 200
            }
        except Exception:
            manual_results[platform] = {"url": url, "exists": False}

    results["manual_checks"] = manual_results

    return jsonify(results), 200


# ══════════════════════════════════════════════════════════
#  MODULE 5 — GROQ AI THREAT ANALYSIS
# ══════════════════════════════════════════════════════════
@app.route("/api/analyze", methods=["POST"])
def analyze_with_groq():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401

    data        = request.get_json()
    scan_result = data.get("scan_result", {})
    target_type = data.get("target_type", "unknown")   # hash | domain | ip | username

    if not scan_result:
        return jsonify({"error": "No scan result provided"}), 400

    log.info(f"[GROQ AI] Analyzing {target_type} scan result...")

    prompt = f"""You are an elite cybersecurity threat analyst working on a DARKWEB MONITOR system.

Analyze the following {target_type.upper()} scan result and provide:

1. **THREAT SUMMARY** (2-3 sentences, direct and clear)
2. **THREAT LEVEL**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN  
3. **KEY FINDINGS**: Bullet list of most important findings
4. **RISK INDICATORS**: What specific things indicate danger?
5. **RECOMMENDED ACTIONS**: What should the security team do RIGHT NOW?
6. **CONFIDENCE SCORE**: 0-100% how confident are you in this assessment

Scan Data:
{json.dumps(scan_result, indent=2)}

Be concise, technical, and actionable. No fluff."""

    try:
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type":  "application/json"
        }
        payload = {
            "model":       GROQ_MODEL,
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens":  1024
        }
        response = requests.post(GROQ_BASE, headers=headers, json=payload, timeout=30)
        resp_data = response.json()

        ai_analysis = resp_data["choices"][0]["message"]["content"]
        tokens_used = resp_data.get("usage", {}).get("total_tokens", 0)

        log.info(f"[GROQ AI] Analysis complete. Tokens used: {tokens_used}")

        return jsonify({
            "target_type": target_type,
            "ai_analysis": ai_analysis,
            "model":       GROQ_MODEL,
            "tokens_used": tokens_used,
            "analyzed_at": datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        log.error(f"[GROQ AI] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════
#  MODULE 6 — FULL SCAN (all modules in one call)
# ══════════════════════════════════════════════════════════
@app.route("/api/scan/full", methods=["POST"])
def full_scan():
    """n8n calls this for a complete automated scan + AI analysis"""
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401

    data        = request.get_json()
    target      = data.get("target", "").strip()
    target_type = data.get("type", "").strip()   # hash | domain | ip | username

    if not target or not target_type:
        return jsonify({"error": "Provide both 'target' and 'type' fields"}), 400

    log.info(f"[FULL SCAN] Starting full scan: {target_type} → {target}")

    # Step 1: Run appropriate scan
    scan_result = {}
    with app.test_request_context():
        pass

    endpoint_map = {
        "hash":     scan_hash,
        "domain":   scan_domain,
        "ip":       scan_ip,
        "username": scan_username
    }

    if target_type not in endpoint_map:
        return jsonify({"error": f"Unknown type '{target_type}'. Use: hash|domain|ip|username"}), 400

    # Rebuild request and call internally
    import io
    fake_data = json.dumps({"hash": target, "domain": target, "ip": target, "username": target})

    with app.test_client() as client:
        scan_resp = client.post(
            f"/api/scan/{target_type}",
            data=fake_data,
            content_type="application/json",
            headers={"X-API-Secret": API_SECRET}
        )
        scan_result = json.loads(scan_resp.data)

    # Step 2: Groq AI analysis
    ai_resp = requests.post(
        "http://localhost:5000/api/analyze",
        json={"scan_result": scan_result, "target_type": target_type},
        headers={"X-API-Secret": API_SECRET},
        timeout=45
    )
    ai_result = ai_resp.json() if ai_resp.status_code == 200 else {"error": "AI analysis failed"}

    return jsonify({
        "target":      target,
        "target_type": target_type,
        "scan_result": scan_result,
        "ai_analysis": ai_result,
        "completed_at": datetime.utcnow().isoformat()
    }), 200


# ══════════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    log.info("🚀 DARKWEB MONITOR — Kali API Server starting...")
    log.info("📡 Listening on http://0.0.0.0:5000")
    log.info("🔑 Make sure .env has VT_API_KEY and GROQ_API_KEY set")
    app.run(host="0.0.0.0", port=5000, debug=False)
