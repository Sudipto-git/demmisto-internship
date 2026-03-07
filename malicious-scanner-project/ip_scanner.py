"""
╔══════════════════════════════════════════╗
║   MODULE: IP Address Scanner            ║
║   Tools : nmap, VirusTotal              ║
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


def scan_ip(target: str) -> dict:
    log.info(f"[IP] Scanning: {target}")
    result = {
        "ip":           target,
        "scan_date":    datetime.utcnow().isoformat(),
        "nmap":         {},
        "virustotal":   {},
        "reverse_dns":  "N/A",
        "threat_level": "UNKNOWN"
    }

    result["nmap"]        = _run_nmap(target)
    result["virustotal"]  = _vt_ip(target)
    result["reverse_dns"] = _reverse_dns(target)
    result["threat_level"] = _calc_threat(result)

    log.info(f"[IP] Done. Threat: {result['threat_level']}")
    return result


def _run_nmap(target: str) -> dict:
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "--open", "-T4", "--top-ports", "100", target],
            capture_output=True, text=True, timeout=90
        )
        raw   = proc.stdout
        ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", raw)
        open_ports = [
            {"port": p[0], "service": p[1], "version": p[2].strip()}
            for p in ports
        ]
        return {
            "open_ports":  open_ports,
            "total_open":  len(open_ports),
            "raw_summary": raw[:600]
        }
    except FileNotFoundError:
        return {"error": "nmap not installed. Run: brew install nmap"}
    except subprocess.TimeoutExpired:
        return {"error": "Nmap timed out"}
    except Exception as e:
        return {"error": str(e)}


def _vt_ip(target: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    try:
        headers  = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"{VT_BASE_URL}/ip_addresses/{target}",
            headers=headers, timeout=15
        )
        if response.status_code != 200:
            return {"error": f"VT returned {response.status_code}"}

        attrs     = response.json().get("data", {}).get("attributes", {})
        stats     = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        return {
            "malicious":    malicious,
            "suspicious":   stats.get("suspicious", 0),
            "country":      attrs.get("country", "N/A"),
            "as_owner":     attrs.get("as_owner", "N/A"),
            "threat_level": "CRITICAL" if malicious >= 10 else
                            "HIGH"     if malicious >= 3  else
                            "MEDIUM"   if malicious >= 1  else "CLEAN",
            "vt_link":      f"https://www.virustotal.com/gui/ip-address/{target}"
        }
    except Exception as e:
        return {"error": str(e)}


def _reverse_dns(target: str) -> str:
    try:
        return socket.gethostbyaddr(target)[0]
    except Exception:
        return "No PTR record"


def _calc_threat(result: dict) -> str:
    vt = result.get("virustotal", {}).get("threat_level", "CLEAN")
    if vt in ["CRITICAL", "HIGH"]:
        return vt
    risky = {"21", "23", "445", "3389", "4444", "6666", "31337"}
    ports = result.get("nmap", {}).get("open_ports", [])
    if any(p["port"] in risky for p in ports):
        return "HIGH"
    if len(ports) > 10:
        return "MEDIUM"
    return vt or "CLEAN"
