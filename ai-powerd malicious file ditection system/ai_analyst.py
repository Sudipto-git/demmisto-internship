"""
╔══════════════════════════════════════════╗
║   MODULE: Groq AI Threat Analyst        ║
║   Model: llama-3.3-70b-versatile        ║
╚══════════════════════════════════════════╝
"""

import requests
import json
import logging
from datetime import datetime
from config import GROQ_API_KEY, GROQ_MODEL, GROQ_BASE_URL

log = logging.getLogger(__name__)


def analyze(scan_result: dict, target_type: str) -> dict:
    """Send scan result to Groq AI for threat analysis"""

    if not GROQ_API_KEY:
        return {"error": "GROQ_API_KEY not set in .env"}

    log.info(f"[AI] Analyzing {target_type} scan with Groq...")

    prompt = _build_prompt(scan_result, target_type)

    try:
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type":  "application/json"
        }
        payload = {
            "model":       GROQ_MODEL,
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens":  1024
        }
        response  = requests.post(GROQ_BASE_URL, headers=headers, json=payload, timeout=30)
        resp_data = response.json()

        if "error" in resp_data:
            return {"error": resp_data["error"].get("message", "Groq API error")}

        analysis    = resp_data["choices"][0]["message"]["content"]
        tokens_used = resp_data.get("usage", {}).get("total_tokens", 0)

        log.info(f"[AI] Done. Tokens: {tokens_used}")

        return {
            "ai_analysis": analysis,
            "model":       GROQ_MODEL,
            "tokens_used": tokens_used,
            "target_type": target_type,
            "analyzed_at": datetime.utcnow().isoformat()
        }

    except requests.exceptions.Timeout:
        return {"error": "Groq API timed out"}
    except Exception as e:
        log.error(f"[AI] Error: {e}")
        return {"error": str(e)}


def _build_prompt(scan_result: dict, target_type: str) -> str:
    return f"""You are an elite cybersecurity threat analyst for a DARKWEB MONITOR system.

Analyze the following {target_type.upper()} scan result and provide a structured report:

1. **THREAT SUMMARY** — 2-3 sentences, direct and clear
2. **THREAT LEVEL** — CRITICAL / HIGH / MEDIUM / LOW / CLEAN
3. **KEY FINDINGS** — Bullet list of most important findings
4. **RISK INDICATORS** — What specific things indicate danger?
5. **RECOMMENDED ACTIONS** — What should the security team do RIGHT NOW?
6. **CONFIDENCE SCORE** — 0-100% how confident are you?

Scan Data:
{json.dumps(scan_result, indent=2)}

Be concise, technical, and actionable. No fluff. Format clearly."""
