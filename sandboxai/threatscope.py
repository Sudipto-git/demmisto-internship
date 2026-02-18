#!/usr/bin/env python3
"""
ThreatScope - Multi-Engine Security Scanner CLI
Converts URLs, domains, file hashes, and files to VirusTotal & Hybrid Analysis
"""

import argparse
import sys
import json
from pathlib import Path
from scanner import ThreatScopeScanner
from config import ConfigManager
from formatter import TerminalFormatter
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as messagebox

__version__ = "1.0.0"


def main():
    parser = argparse.ArgumentParser(
        description="ThreatScope - Multi-Engine Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  threatscope https://example.com --vt-key YOUR_KEY
  threatscope --hash abc123def456 --json
  threatscope malware.exe --vt-key KEY --ha-key HAKEY
  threatscope google.com --engines vt,ha --save results.json
  threatscope --history
        """,
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="URL, domain, IP address, file hash, or file path to scan",
    )
    parser.add_argument(
        "--vt-key", help="VirusTotal API key (or set VT_API_KEY env var)"
    )
    parser.add_argument(
        "--ha-key", help="Hybrid Analysis API key (or set HA_API_KEY env var)"
    )
    parser.add_argument(
        "--engines",
        default="vt,ha",
        help="Scanning engines: vt (VirusTotal), ha (Hybrid Analysis). Default: vt,ha",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--save", help="Save results to file (JSON format)")
    parser.add_argument("--history", action="store_true", help="Show scan history")
    parser.add_argument(
        "--clear-history", action="store_true", help="Clear scan history"
    )
    parser.add_argument(
        "--version", action="version", version=f"ThreatScope {__version__}"
    )

    args = parser.parse_args()

    config = ConfigManager()
    formatter = TerminalFormatter()

    # Handle history commands
    if args.history:
        history = config.load_history()
        if not history:
            print("No scan history.")
            return
        formatter.print_history(history)
        return

    if args.clear_history:
        config.clear_history()
        print("✓ Scan history cleared.")
        return

    # Require target if no history operation
    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Get API keys
    vt_key = args.vt_key or config.get_api_key("vt")
    ha_key = args.ha_key or config.get_api_key("ha")

    # Parse engines
    engines = set(e.strip().lower() for e in args.engines.split(","))
    if "vt" in engines and not vt_key:
        print("❌ VirusTotal API key required. Use --vt-key or set VT_API_KEY env var")
        sys.exit(1)
    if "ha" in engines and not ha_key:
        print(
            "❌ Hybrid Analysis API key required. Use --ha-key or set HA_API_KEY env var"
        )
        sys.exit(1)

    # Run scan
    scanner = ThreatScopeScanner(vt_key, ha_key)

    try:
        print(f"\n🔬 {formatter.accent('ThreatScope')} - Scanning target...")
        result = scanner.scan(args.target, engines)

        # Save to history
        config.add_to_history(result)

        # Display results
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            formatter.print_result(result)

        # Save to file if requested
        if args.save:
            with open(args.save, "w") as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"\n✓ Results saved to {args.save}")

    except KeyboardInterrupt:
        print("\n\n⚠ Scan cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
