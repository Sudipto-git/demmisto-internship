"""
Terminal output formatting with colors and ASCII art
"""

from typing import List, Dict
from datetime import datetime


class TerminalFormatter:
    """Format and display results in terminal"""

    # ANSI Color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    def accent(self, text: str) -> str:
        """Accent color (cyan)"""
        return f"{self.CYAN}{self.BOLD}{text}{self.RESET}"

    def danger(self, text: str) -> str:
        """Danger color (red)"""
        return f"{self.RED}{self.BOLD}{text}{self.RESET}"

    def warning(self, text: str) -> str:
        """Warning color (yellow)"""
        return f"{self.YELLOW}{self.BOLD}{text}{self.RESET}"

    def safe(self, text: str) -> str:
        """Safe color (green)"""
        return f"{self.GREEN}{self.BOLD}{text}{self.RESET}"

    def muted(self, text: str) -> str:
        """Muted color (gray)"""
        return f"{self.GRAY}{text}{self.RESET}"

    def print_result(self, result) -> None:
        """Print complete scan result"""
        print("\n" + "=" * 70)

        # Header with verdict
        verdict_icon = "⚠" if result.verdict == "danger" else "⚑" if result.verdict == "warning" else "✓"
        verdict_text = self.danger(result.verdict.upper()) if result.verdict == "danger" else \
                       self.warning(result.verdict.upper()) if result.verdict == "warning" else \
                       self.safe(result.verdict.upper())

        print(f"{verdict_icon} Verdict: {verdict_text}")
        print(f"🎯 Target: {result.target}")
        print(f"📅 Time: {result.timestamp}")

        print("\n" + "-" * 70)

        # VirusTotal results
        if result.vt:
            self._print_vt_result(result.vt)

        # Hybrid Analysis results
        if result.ha:
            self._print_ha_result(result.ha)

        print("=" * 70 + "\n")

    def _print_vt_result(self, vt) -> None:
        """Print VirusTotal results"""
        print(f"\n🔵 {self.accent('VirusTotal')}")

        if vt.error:
            print(f"  ❌ {vt.error}")
            return

        # Stats
        print(f"  Malicious:  {self.danger(str(vt.malicious))}")
        print(f"  Suspicious: {self.warning(str(vt.suspicious))}")
        print(f"  Harmless:   {self.safe(str(vt.harmless))}")
        print(f"  Undetected: {self.muted(str(vt.undetected))}")

        # Detection bar
        if vt.total > 0:
            total = vt.total
            mal_pct = int(vt.malicious * 20 / total)
            sus_pct = int(vt.suspicious * 20 / total)
            clean_pct = int(vt.harmless * 20 / total)
            un_pct = int(vt.undetected * 20 / total)

            bar = ("█" * mal_pct) + ("▓" * sus_pct) + ("▒" * clean_pct) + ("░" * un_pct)
            bar = f"{self.RED}{bar[:mal_pct]}{self.RESET}{self.YELLOW}{bar[mal_pct:mal_pct+sus_pct]}{self.RESET}" + \
                  f"{self.GREEN}{bar[mal_pct+sus_pct:mal_pct+sus_pct+clean_pct]}{self.RESET}" + \
                  f"{self.GRAY}{bar[mal_pct+sus_pct+clean_pct:]}{self.RESET}"
            print(f"  [{bar}]")

        # Details
        if vt.sha256:
            print(f"  SHA256: {vt.sha256[:32]}...")
        if vt.file_type:
            print(f"  Type: {vt.file_type}")
        if vt.detected_by:
            print(f"  Detected by: {', '.join(vt.detected_by[:3])}")

    def _print_ha_result(self, ha) -> None:
        """Print Hybrid Analysis results"""
        print(f"\n🟠 {self.accent('Hybrid Analysis')}")

        if ha.error:
            print(f"  ❌ {ha.error}")
            return

        if ha.verdict:
            verdict_str = self.danger(ha.verdict.upper()) if ha.verdict == "malicious" else \
                         self.warning(ha.verdict.upper()) if ha.verdict == "suspicious" else \
                         self.safe(ha.verdict.upper())
            print(f"  Verdict: {verdict_str}")

        if ha.threat_score is not None:
            score = ha.threat_score
            score_color = self.danger if score >= 75 else self.warning if score >= 50 else self.safe
            print(f"  Threat Score: {score_color(str(score))}/100")

        if ha.malware_family:
            print(f"  Malware Family: {self.danger(ha.malware_family)}")

        if ha.tags:
            print(f"  Tags: {', '.join(ha.tags[:5])}")

    def print_history(self, history: List[Dict]) -> None:
        """Print scan history"""
        print(f"\n{self.accent('📜 Scan History')}\n")

        if not history:
            print("No scans yet.")
            return

        for i, item in enumerate(history[:10], 1):
            verdict = item["verdict"]
            verdict_emoji = "⚠" if verdict == "danger" else "⚑" if verdict == "warning" else "✓"
            verdict_color = self.danger if verdict == "danger" else \
                           self.warning if verdict == "warning" else \
                           self.safe

            target = item["target"]
            if len(target) > 50:
                target = target[:47] + "..."

            timestamp = item["timestamp"][:10]

            print(f"  {i}. {verdict_emoji} {verdict_color(verdict.upper())} {target}")
            print(f"     {self.muted(timestamp)}\n")

        if len(history) > 10:
            print(f"  ... and {len(history) - 10} more")