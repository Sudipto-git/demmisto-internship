"""
╔══════════════════════════════════════════╗
║   MODULE: Domain + Email OSINT          ║
║   Tools: theHarvester, whois, VT        ║
╚══════════════════════════════════════════╝
"""

import subprocess
import requests
import socket
import re
import logging
from datetime import datetime
from config import VT_API_KEY, VT_BASE_URL

log = logging.getLogger(__name__)


def scan_domain(target: str) -> dict:
    """Full domain OSINT scan — theHarvester + WHOIS + DNS + VirusTotal"""

    log.info(f"[DOMAIN] Scanning: {target}")
    result = {
        "domain":    target,
        "scan_date": datetime.utcnow().isoformat(),
        "harvester": {},
        "whois":     {},
        "dns":       {},
        "virustotal": {}
    }

    # ── theHarvester ──────────────────────────────────
    result["harvester"] = _run_harvester(target)

    # ── WHOIS ─────────────────────────────────────────
    result["whois"] = _run_whois(target)

    # ── DNS Resolution ────────────────────────────────
    result["dns"] = _resolve_dns(target)

    # ── VirusTotal ────────────────────────────────────
    result["virustotal"] = _vt_domain(target)

    # ── Overall threat level ──────────────────────────
    result["threat_level"] = _calc_threat(result)

    log.info(f"[DOMAIN] Done. Threat: {result['threat_level']}")
    return result


def _run_harvester(target: str) -> dict:
    try:
        proc = subprocess.run(
            ["theHarvester", "-d", target, "-l", "100",
             "-b", "bing,certspotter,crtsh,otx,threatminer"],
            capture_output=True, text=True, timeout=60
        )
        raw = proc.stdout + proc.stderr

        emails = list(set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw
        )))
        ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)))
        ips = [ip for ip in ips if not ip.startswith(("127.", "192.168.", "10.", "172."))]

        return {
            "emails_found": emails,
            "ips_found":    ips,
            "total_emails": len(emails),
            "total_ips":    len(ips)
        }
    except FileNotFoundError:
        return {"error": "theHarvester not installed. Run: pip3 install theharvester"}
    except subprocess.TimeoutExpired:
        return {"error": "theHarvester timed out"}
    except Exception as e:
        return {"error": str(e)}


def _run_whois(target: str) -> dict:
    try:
        proc = subprocess.run(
            ["whois", target],
            capture_output=True, text=True, timeout=20
        )
        raw = proc.stdout

        def extract(pattern):
            m = re.search(pattern, raw, re.IGNORECASE)
            return m.group(1).strip() if m else "N/A"

        return {
            "registrar":    extract(r"Registrar:\s*(.+)"),
            "created":      extract(r"Creation Date:\s*(.+)"),
            "expires":      extract(r"Registry Expiry Date:\s*(.+)"),
            "name_servers": re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)[:4],
            "status":       re.findall(r"Domain Status:\s*(.+)", raw, re.IGNORECASE)[:2]
        }
    except Exception as e:
        return {"error": str(e)}


def _resolve_dns(target: str) -> dict:
    try:
        ip = socket.gethostbyname(target)
        return {"resolved_ip": ip, "status": "resolved"}
    except Exception:
        return {"resolved_ip": None, "status": "unresolved"}


def _vt_domain(target: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    try:
        headers  = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"{VT_BASE_URL}/domains/{target}",
            headers=headers, timeout=15
        )
        if response.status_code != 200:
            return {"error": f"VT API returned {response.status_code}"}

        attrs     = response.json().get("data", {}).get("attributes", {})
        stats     = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        return {
            "malicious":    malicious,
            "suspicious":   stats.get("suspicious", 0),
            "harmless":     stats.get("harmless", 0),
            "threat_level": "HIGH" if malicious >= 3 else "MEDIUM" if malicious >= 1 else "CLEAN",
            "categories":   attrs.get("categories", {}),
            "vt_link":      f"https://www.virustotal.com/gui/domain/{target}"
        }
    except Exception as e:
        return {"error": str(e)}


def _calc_threat(result: dict) -> str:
    vt_level = result.get("virustotal", {}).get("threat_level", "CLEAN")
    if vt_level in ["HIGH", "CRITICAL"]:
        return vt_level
    emails = result.get("harvester", {}).get("total_emails", 0)
    if emails > 10:
        return "MEDIUM"
    return vt_level or "CLEAN"
