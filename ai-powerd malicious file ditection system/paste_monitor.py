"""
╔══════════════════════════════════════════╗
║   MODULE: Pastebin Leak Monitor         ║
║   Monitors paste sites for leaks        ║
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
    """
    Scan recent Pastebin pastes for sensitive keywords or domain mentions.
    Returns list of matched pastes with content snippets.
    """
    keywords = keywords or PASTE_MONITOR_KEYWORDS
    domains  = domains  or [d for d in PASTE_MONITOR_DOMAINS if d.strip()]

    log.info(f"[PASTE] Monitoring for keywords: {keywords}")
    log.info(f"[PASTE] Monitoring for domains:  {domains}")

    result = {
        "scan_date":     datetime.utcnow().isoformat(),
        "keywords_used": keywords,
        "domains_used":  domains,
        "matches":       [],
        "total_matches": 0,
        "threat_level":  "CLEAN"
    }

    # ── Fetch recent pastes from Pastebin archive ─────
    recent_pastes = _fetch_recent_pastes()
    if not recent_pastes:
        result["error"] = "Could not fetch recent pastes"
        return result

    log.info(f"[PASTE] Fetched {len(recent_pastes)} recent pastes")

    # ── Scan each paste ───────────────────────────────
    for paste in recent_pastes[:20]:   # limit to 20 to avoid rate limits
        try:
            content = _fetch_paste_content(paste["key"])
            if not content:
                continue

            matched_keywords = _find_keywords(content, keywords)
            matched_domains  = _find_domains(content, domains)

            if matched_keywords or matched_domains:
                result["matches"].append({
                    "paste_key":       paste["key"],
                    "paste_url":       f"https://pastebin.com/{paste['key']}",
                    "title":           paste.get("title", "Untitled"),
                    "date":            paste.get("date", "N/A"),
                    "matched_keywords": matched_keywords,
                    "matched_domains":  matched_domains,
                    "snippet":         content[:300].replace("\n", " "),
                    "severity":        _calc_severity(matched_keywords, matched_domains)
                })

        except Exception as e:
            log.warning(f"[PASTE] Error processing paste: {e}")
            continue

    result["total_matches"] = len(result["matches"])
    result["threat_level"]  = (
        "CRITICAL" if result["total_matches"] >= 5 else
        "HIGH"     if result["total_matches"] >= 3 else
        "MEDIUM"   if result["total_matches"] >= 1 else
        "CLEAN"
    )

    log.info(f"[PASTE] Done. {result['total_matches']} matches found.")
    return result


def _fetch_recent_pastes() -> list:
    """Fetch list of recent public pastes from Pastebin archive"""
    try:
        resp = requests.get(
            "https://pastebin.com/archive",
            headers=HEADERS, timeout=15
        )
        if resp.status_code != 200:
            return []

        soup   = BeautifulSoup(resp.text, "lxml")
        table  = soup.find("table", class_="maintable")
        if not table:
            return []

        pastes = []
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) >= 1:
                link = cols[0].find("a")
                if link and link.get("href"):
                    key = link["href"].strip("/")
                    pastes.append({
                        "key":   key,
                        "title": link.text.strip(),
                        "date":  cols[-1].text.strip() if len(cols) > 1 else "N/A"
                    })
        return pastes

    except Exception as e:
        log.error(f"[PASTE] Fetch error: {e}")
        return []


def _fetch_paste_content(key: str) -> str:
    """Fetch raw content of a paste"""
    try:
        resp = requests.get(
            f"https://pastebin.com/raw/{key}",
            headers=HEADERS, timeout=10
        )
        if resp.status_code == 200:
            return resp.text[:5000]   # limit to 5KB per paste
        return ""
    except Exception:
        return ""


def _find_keywords(content: str, keywords: list) -> list:
    """Find which keywords appear in paste content"""
    content_lower = content.lower()
    return [kw for kw in keywords if kw.lower() in content_lower]


def _find_domains(content: str, domains: list) -> list:
    """Find which monitored domains appear in paste content"""
    if not domains:
        return []
    content_lower = content.lower()
    return [d for d in domains if d.lower() in content_lower]


def _calc_severity(keywords: list, domains: list) -> str:
    """Calculate severity of a single paste match"""
    high_risk = {"password", "credentials", "dump", "breach", "leaked", "exploit"}
    if domains:
        return "CRITICAL"
    if any(k.lower() in high_risk for k in keywords):
        return "HIGH"
    return "MEDIUM"
