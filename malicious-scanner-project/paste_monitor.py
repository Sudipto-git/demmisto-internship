"""
╔══════════════════════════════════════════╗
║   MODULE: Pastebin Leak Monitor         ║
╚══════════════════════════════════════════╝
"""

import requests
import re
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from config import PASTE_MONITOR_KEYWORDS, PASTE_MONITOR_DOMAINS

log = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}


def monitor_pastes(keywords: list = None, domains: list = None) -> dict:
    keywords = keywords or PASTE_MONITOR_KEYWORDS
    domains  = domains  or [d for d in PASTE_MONITOR_DOMAINS if d.strip()]

    log.info(f"[PASTE] Keywords: {keywords} | Domains: {domains}")

    result = {
        "scan_date":     datetime.utcnow().isoformat(),
        "keywords_used": keywords,
        "domains_used":  domains,
        "matches":       [],
        "total_matches": 0,
        "threat_level":  "CLEAN"
    }

    recent = _fetch_recent_pastes()
    if not recent:
        result["error"] = "Could not fetch recent pastes"
        return result

    log.info(f"[PASTE] Fetched {len(recent)} pastes")

    for paste in recent[:20]:
        try:
            content = _fetch_paste_content(paste["key"])
            if not content:
                continue

            matched_kw  = _find_keywords(content, keywords)
            matched_dom = _find_domains(content, domains)

            if matched_kw or matched_dom:
                result["matches"].append({
                    "paste_key":        paste["key"],
                    "paste_url":        f"https://pastebin.com/{paste['key']}",
                    "title":            paste.get("title", "Untitled"),
                    "matched_keywords": matched_kw,
                    "matched_domains":  matched_dom,
                    "snippet":          content[:300].replace("\n", " "),
                    "severity":         _calc_severity(matched_kw, matched_dom)
                })
        except Exception as e:
            log.warning(f"[PASTE] Error: {e}")

    result["total_matches"] = len(result["matches"])
    result["threat_level"]  = (
        "CRITICAL" if result["total_matches"] >= 5 else
        "HIGH"     if result["total_matches"] >= 3 else
        "MEDIUM"   if result["total_matches"] >= 1 else
        "CLEAN"
    )

    log.info(f"[PASTE] Done. {result['total_matches']} matches.")
    return result


def _fetch_recent_pastes() -> list:
    try:
        resp = requests.get("https://pastebin.com/archive", headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return []
        soup  = BeautifulSoup(resp.text, "lxml")
        table = soup.find("table", class_="maintable")
        if not table:
            return []
        pastes = []
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if cols:
                link = cols[0].find("a")
                if link and link.get("href"):
                    pastes.append({
                        "key":   link["href"].strip("/"),
                        "title": link.text.strip()
                    })
        return pastes
    except Exception as e:
        log.error(f"[PASTE] Fetch error: {e}")
        return []


def _fetch_paste_content(key: str) -> str:
    try:
        resp = requests.get(
            f"https://pastebin.com/raw/{key}",
            headers=HEADERS, timeout=10
        )
        return resp.text[:5000] if resp.status_code == 200 else ""
    except Exception:
        return ""


def _find_keywords(content: str, keywords: list) -> list:
    lower = content.lower()
    return [kw for kw in keywords if kw.lower() in lower]


def _find_domains(content: str, domains: list) -> list:
    if not domains:
        return []
    lower = content.lower()
    return [d for d in domains if d.lower() in lower]


def _calc_severity(keywords: list, domains: list) -> str:
    high_risk = {"password", "credentials", "dump", "breach", "leaked", "exploit"}
    if domains:
        return "CRITICAL"
    if any(k.lower() in high_risk for k in keywords):
        return "HIGH"
    return "MEDIUM"
