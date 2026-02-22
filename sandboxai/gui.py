#!/usr/bin/env python3
"""
ThreatScope GUI - Desktop application for multi-engine security scanning
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import json
import os
import ipaddress
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from scanner import ThreatScopeScanner, ScanResult
from config import ConfigManager, load_env_file
from formatter import TerminalFormatter
import requests

load_env_file()

DEFAULT_N8N_BASE_URL = "http://localhost:5678"
DEFAULT_N8N_WEBHOOK_URL = f"{DEFAULT_N8N_BASE_URL}/webhook/scan"
DEFAULT_N8N_WEBHOOK_URL_TEST = f"{DEFAULT_N8N_BASE_URL}/webhook-test/scan"


def _normalized(url: str) -> str:
    return url.strip().rstrip("/")


def _from_workflow_url(workflow_url: str):
    if not workflow_url:
        return []
    parsed = urlparse(workflow_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return []
    base = f"{parsed.scheme}://{parsed.netloc}"
    return [f"{base}/webhook/scan", f"{base}/webhook-test/scan"]


def _is_local_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return host.endswith(".local")


def _url_with_default_n8n_port(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""

    if not parsed.hostname or parsed.port is not None:
        return ""
    if not _is_local_url(url):
        return ""

    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth += f":{parsed.password}"
        netloc = f"{auth}@{host}:5678"
    else:
        netloc = f"{host}:5678"
    return urlunparse(parsed._replace(netloc=netloc))


def _url_with_localhost_alias(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""

    host = parsed.hostname
    if not host:
        return ""

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""

    if not ip.is_private or ip.is_loopback:
        return ""

    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth += f":{parsed.password}"
        netloc = f"{auth}@localhost"
    else:
        netloc = "localhost"
    if parsed.port is not None:
        netloc += f":{parsed.port}"

    return urlunparse(parsed._replace(netloc=netloc))


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _should_verify_ssl(webhook_url: str) -> bool:
    # Explicit env var wins. If unset, allow self-signed certs on local/private hosts.
    if "N8N_VERIFY_SSL" in os.environ:
        return _env_bool("N8N_VERIFY_SSL", True)

    parsed = urlparse(webhook_url)
    if parsed.scheme == "https" and _is_local_url(webhook_url):
        return False
    if parsed.scheme == "http" and _is_local_url(webhook_url):
        return False
    return True


def _parse_webhook_response(response: requests.Response):
    if not response.text.strip():
        return {
            "message": (
                "Webhook call succeeded, but n8n returned an empty response body. "
                "Add/adjust a 'Respond to Webhook' node if you want structured output."
            )
        }
    try:
        return response.json()
    except ValueError:
        return {"raw_response": response.text}


def _build_webhook_payload(user_input: str) -> dict:
    # Include common aliases so n8n workflows that read different field names still work.
    return {
        "url": user_input,
        "target": user_input,
        "input": user_input,
        "target_url": user_input,
        "ioc": user_input,
    }


def build_webhook_candidates():
    webhook_url = os.getenv("N8N_WEBHOOK_URL", DEFAULT_N8N_WEBHOOK_URL).strip()
    webhook_url_test = os.getenv(
        "N8N_WEBHOOK_URL_TEST", DEFAULT_N8N_WEBHOOK_URL_TEST
    ).strip()
    workflow_url = os.getenv("N8N_WORKFLOW_URL", "").strip()
    prefer_test_webhook = _env_bool("N8N_PREFER_TEST_WEBHOOK", True)

    if prefer_test_webhook:
        configured_values = [webhook_url_test, webhook_url, *_from_workflow_url(workflow_url)]
    else:
        configured_values = [webhook_url, webhook_url_test, *_from_workflow_url(workflow_url)]
    candidates = []
    for value in configured_values:
        value = _normalized(value)
        if not value:
            continue
        variants = [value]
        port_variant = _url_with_default_n8n_port(value)
        if port_variant:
            variants.append(port_variant)
        localhost_variant = _url_with_localhost_alias(value)
        if localhost_variant:
            variants.append(localhost_variant)
            localhost_port_variant = _url_with_default_n8n_port(localhost_variant)
            if localhost_port_variant:
                variants.append(localhost_port_variant)

        if "/webhook/" in value:
            variants.append(value.replace("/webhook/", "/webhook-test/"))
            if port_variant:
                variants.append(port_variant.replace("/webhook/", "/webhook-test/"))
        elif "/webhook-test/" in value:
            variants.append(value.replace("/webhook-test/", "/webhook/"))
            if port_variant:
                variants.append(port_variant.replace("/webhook-test/", "/webhook/"))

        for candidate in variants:
            candidates.append(candidate)
            # Try alternate scheme only for non-local hosts.
            if not _is_local_url(candidate):
                if candidate.startswith("https://"):
                    candidates.append("http://" + candidate[len("https://") :])
                elif candidate.startswith("http://"):
                    candidates.append("https://" + candidate[len("http://") :])

    # Keep a deterministic local fallback only when nothing is configured.
    if not candidates:
        candidates.extend([DEFAULT_N8N_WEBHOOK_URL_TEST, DEFAULT_N8N_WEBHOOK_URL])
    return list(dict.fromkeys(candidates))


class ThreatScopeGUI:
    """Main GUI application"""

    # Colors matching original design
    BG_PRIMARY = "#0a0c0f"
    BG_SECONDARY = "#111418"
    BG_CARD = "#13181f"
    BORDER_COLOR = "#1e2530"
    ACCENT_GREEN = "#00f5a0"
    ACCENT_ORANGE = "#ff6b35"
    DANGER_RED = "#ff3366"
    WARN_YELLOW = "#ffd60a"
    TEXT_PRIMARY = "#e8edf5"
    TEXT_MUTED = "#5a6478"

    def __init__(self, root):
        self.root = root
        self.root.title("ThreatScope — Security Scanner")
        self.root.geometry("1100x1200")  # Make window taller
        self.root.configure(bg=self.BG_PRIMARY)

        self.config_manager = ConfigManager()
        self.scanner = None
        self.current_result = None
        self.latest_n8n_result = None
        self.scanning = False

        self.setup_styles()
        self.build_ui()
        self.load_api_keys()

    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use("clam")

        # Configure colors for dark theme
        style.configure("TFrame", background=self.BG_PRIMARY)
        style.configure(
            "TLabel", background=self.BG_PRIMARY, foreground=self.TEXT_PRIMARY
        )

        # Custom button styling with better hover contrast
        style.configure(
            "TButton",
            background=self.BG_SECONDARY,
            foreground=self.ACCENT_GREEN,
            borderwidth=1,
            relief="solid",
            font=("Arial", 10),
        )
        style.map(
            "TButton",
            background=[("active", self.ACCENT_GREEN), ("pressed", self.ACCENT_ORANGE)],
            foreground=[("active", self.BG_PRIMARY), ("pressed", self.BG_PRIMARY)],
        )

        style.configure(
            "Title.TLabel",
            font=("Arial", 20, "bold"),
            background=self.BG_PRIMARY,
            foreground=self.ACCENT_GREEN,
        )
        style.configure(
            "Subtitle.TLabel",
            font=("Arial", 10),
            background=self.BG_PRIMARY,
            foreground=self.TEXT_MUTED,
        )
        style.configure(
            "TEntry", fieldbackground=self.BG_SECONDARY, foreground=self.TEXT_PRIMARY
        )

        # Checkbox styling with better contrast
        style.configure(
            "TCheckbutton",
            background=self.BG_PRIMARY,
            foreground=self.TEXT_PRIMARY,
            font=("Arial", 10),
        )
        style.map(
            "TCheckbutton",
            background=[("active", self.BG_PRIMARY)],
            foreground=[("active", self.ACCENT_GREEN)],
        )

        style.configure(
            "TLabelFrame", background=self.BG_PRIMARY, foreground=self.TEXT_PRIMARY
        )
        style.configure(
            "TLabelFrame.Label",
            background=self.BG_PRIMARY,
            foreground=self.ACCENT_GREEN,
        )
        
    

    def build_ui(self):
        """Build the complete UI"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header
        self.build_header(main_frame)

        # API Keys section
        self.build_api_section(main_frame)

        # Scanner section
        self.build_scanner_section(main_frame)

        # Results section
        self.build_results_section(main_frame)

        # History section
        self.build_history_section(main_frame)

    def build_header(self, parent):
        """Build header section"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        title_label = ttk.Label(
            header_frame, text="🔬 ThreatScope", style="Title.TLabel"
        )
        title_label.pack(anchor=tk.W)

        subtitle_label = ttk.Label(
            header_frame, text="Multi-Engine Security Scanner", style="Subtitle.TLabel"
        )
        subtitle_label.pack(anchor=tk.W)

    def build_api_section(self, parent):
        """Build API configuration section"""
        api_frame = ttk.LabelFrame(parent, text="API Configuration", padding=15)
        api_frame.pack(fill=tk.X, pady=(0, 15))

        # VirusTotal
        ttk.Label(api_frame, text="VirusTotal API Key:").grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        self.vt_key_entry = ttk.Entry(api_frame, show="•", width=50)
        self.vt_key_entry.grid(row=0, column=1, sticky=tk.EW, padx=10)
        self.vt_key_entry.bind(
            "<KeyRelease>",
            lambda e: self.config_manager.set_api_key("vt", self.vt_key_entry.get()),
        )

        # Hybrid Analysis
        ttk.Label(api_frame, text="Hybrid Analysis API Key:").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        self.ha_key_entry = ttk.Entry(api_frame, show="•", width=50)
        self.ha_key_entry.grid(row=1, column=1, sticky=tk.EW, padx=10)
        self.ha_key_entry.bind(
            "<KeyRelease>",
            lambda e: self.config_manager.set_api_key("ha", self.ha_key_entry.get()),
        )

        api_frame.columnconfigure(1, weight=1)

        # Info
        info_label = ttk.Label(
            api_frame,
            text="🔒 Keys stored locally in ~/.threatscope/config.json",
            style="Subtitle.TLabel",
        )
        info_label.grid(row=2, column=0, columnspan=2, pady=10)

    def build_scanner_section(self, parent):
        """Build scanner input section"""
        scanner_frame = ttk.LabelFrame(parent, text="Scan Target", padding=15)
        scanner_frame.pack(fill=tk.X, pady=(0, 15))

        # Tabs
        self.notebook = ttk.Notebook(scanner_frame)
        self.notebook.pack(fill=tk.X, pady=(0, 15))

        # URL Tab
        url_frame = ttk.Frame(self.notebook)
        self.notebook.add(url_frame, text="🔗 URL / Domain / IP")
        ttk.Label(url_frame, text="Enter URL, domain, or IP address:").pack(
            anchor=tk.W, padx=5, pady=5
        )
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(fill=tk.X, padx=5, pady=5)

        # Hash Tab
        hash_frame = ttk.Frame(self.notebook)
        self.notebook.add(hash_frame, text="🔍 File Hash")
        ttk.Label(hash_frame, text="Enter MD5, SHA-1, or SHA-256 hash:").pack(
            anchor=tk.W, padx=5, pady=5
        )
        self.hash_entry = ttk.Entry(hash_frame)
        self.hash_entry.pack(fill=tk.X, padx=5, pady=5)

        # File Tab
        file_frame = ttk.Frame(self.notebook)
        self.notebook.add(file_frame, text="📁 File Upload")
        ttk.Label(file_frame, text="Select a file to scan:").pack(
            anchor=tk.W, padx=5, pady=5
        )
        file_button_frame = ttk.Frame(file_frame)
        file_button_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(
            file_button_frame, text="Browse File", command=self.select_file
        ).pack(side=tk.LEFT, padx=5)
        self.file_label = ttk.Label(
            file_button_frame, text="No file selected", foreground=self.TEXT_MUTED
        )
        self.file_label.pack(side=tk.LEFT, padx=5)
        self.selected_file = None

        # Engine toggles
        engine_frame = ttk.Frame(scanner_frame)
        engine_frame.pack(fill=tk.X, pady=10)
        ttk.Label(engine_frame, text="Scanning Engines:").pack(anchor=tk.W)

        check_frame = ttk.Frame(engine_frame)
        check_frame.pack(fill=tk.X, padx=5)

        self.vt_enabled = tk.BooleanVar(value=True)
        self.ha_enabled = tk.BooleanVar(value=True)

        ttk.Checkbutton(check_frame, text="VirusTotal", variable=self.vt_enabled).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Checkbutton(
            check_frame, text="Hybrid Analysis", variable=self.ha_enabled
        ).pack(side=tk.LEFT, padx=5)
        self.n8n_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(check_frame, text="n8n Workflow", variable=self.n8n_enabled).pack(
            side=tk.LEFT, padx=5
        )

        # Scan button
        self.scan_button = ttk.Button(
            scanner_frame, text="⚡ SCAN NOW", command=self.start_scan
        )
        self.scan_button.pack(fill=tk.X, pady=10)

        # Progress
        self.progress = ttk.Progressbar(scanner_frame, mode="indeterminate")
        self.progress_label = ttk.Label(scanner_frame, text="", style="Subtitle.TLabel")

    def build_results_section(self, parent):
        """Build results display section"""
        results_frame = ttk.LabelFrame(parent, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # Results display
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=10,
            bg=self.BG_CARD,
            fg=self.TEXT_PRIMARY,
            insertbackground=self.ACCENT_GREEN,
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for colors
        self.results_text.tag_config(
            "danger", foreground=self.DANGER_RED, font=("Courier", 10, "bold")
        )
        self.results_text.tag_config(
            "warning", foreground=self.WARN_YELLOW, font=("Courier", 10, "bold")
        )
        self.results_text.tag_config(
            "safe", foreground=self.ACCENT_GREEN, font=("Courier", 10, "bold")
        )
        self.results_text.tag_config("muted", foreground=self.TEXT_MUTED)
        self.results_text.tag_config(
            "header", foreground=self.ACCENT_GREEN, font=("Courier", 11, "bold")
        )
        self.results_text.tag_config("accent", foreground=self.ACCENT_ORANGE)

        # Buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X)

        ttk.Button(
            button_frame, text="💾 Save Results", command=self.save_results
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📋 Copy", command=self.copy_results).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="🗑 Clear", command=self.clear_results).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="📜 History", command=self.show_history).pack(
            side=tk.LEFT, padx=5
        )

    def build_history_section(self, parent):
        """Build history display section"""
        history_frame = ttk.LabelFrame(
            parent, text="📜 Recent Scans History", padding=10
        )
        history_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # History text
        self.history_text = scrolledtext.ScrolledText(
            history_frame,
            height=8,
            bg=self.BG_CARD,  # Increased from 6 to 8
            fg=self.TEXT_PRIMARY,
            wrap=tk.WORD,
        )
        self.history_text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for colors
        self.history_text.tag_config(
            "danger", foreground=self.DANGER_RED, font=("Courier", 9, "bold")
        )
        self.history_text.tag_config(
            "warning", foreground=self.WARN_YELLOW, font=("Courier", 9, "bold")
        )
        self.history_text.tag_config(
            "safe", foreground=self.ACCENT_GREEN, font=("Courier", 9, "bold")
        )
        self.history_text.tag_config(
            "muted", foreground=self.TEXT_MUTED, font=("Courier", 9)
        )

        # Buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(
            button_frame, text="🔄 Refresh History", command=self.refresh_history
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            button_frame, text="🗑 Clear History", command=self.clear_history_action
        ).pack(side=tk.LEFT, padx=5)

        # Load initial history
        self.refresh_history()

    def refresh_history(self):
        """Refresh and display history"""
        history = self.config_manager.load_history()

        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete(1.0, tk.END)

        if not history:
            self.history_text.insert(tk.END, "No scan history yet", "muted")
            self.history_text.config(state=tk.DISABLED)
            return

        for i, item in enumerate(history[:15], 1):
            verdict = item["verdict"]
            tag = (
                "danger"
                if verdict == "danger"
                else "warning" if verdict == "warning" else "safe"
            )

            emoji = "⚠" if verdict == "danger" else "⚑" if verdict == "warning" else "✓"

            # Line with verdict
            self.history_text.insert(tk.END, f"{i}. {emoji} ")
            self.history_text.insert(tk.END, f"{verdict.upper()}", tag)
            self.history_text.insert(tk.END, f"  -  {item['target']}\n")

            # Timestamp
            self.history_text.insert(
                tk.END, f"     {item['timestamp'][:10]}\n\n", "muted"
            )

        self.history_text.config(state=tk.DISABLED)

    def clear_history_action(self):
        """Clear history with confirmation"""
        if messagebox.askyesno(
            "Clear History", "Are you sure you want to delete all scan history?"
        ):
            self.config_manager.clear_history()
            messagebox.showinfo("Success", "Scan history cleared")
            self.refresh_history()

    def load_api_keys(self):
        """Load saved API keys"""
        vt_key = self.config_manager.get_api_key("vt")
        ha_key = self.config_manager.get_api_key("ha")

        if vt_key:
            self.vt_key_entry.insert(0, vt_key)
        if ha_key:
            self.ha_key_entry.insert(0, ha_key)

    def select_file(self):
        """Open file browser"""
        filename = filedialog.askopenfilename(title="Select file to scan")
        if filename:
            self.selected_file = filename
            self.file_label.config(
                text=Path(filename).name, foreground=self.ACCENT_GREEN
            )

    def scan_url(self, user_input):
        webhook_candidates = build_webhook_candidates()
        seen = set()
        last_error = None
        attempts = []
        payload = _build_webhook_payload(user_input)

        for webhook_url in webhook_candidates:
            if webhook_url in seen:
                continue
            seen.add(webhook_url)

            try:
                verify_ssl = _should_verify_ssl(webhook_url)
                response = requests.post(
                    webhook_url,
                    params=payload,
                    json=payload,
                    timeout=30,
                    verify=verify_ssl,
                )
            except requests.RequestException as e:
                last_error = f"{type(e).__name__}: {str(e)}"
                attempts.append(
                    {
                        "endpoint": webhook_url,
                        "result": "request_error",
                        "detail": last_error,
                        "verify_ssl": verify_ssl,
                    }
                )
                continue

            if 200 <= response.status_code < 300:
                body = _parse_webhook_response(response)
                return {
                    "endpoint": webhook_url,
                    "status_code": response.status_code,
                    "body": body,
                    "attempts": attempts
                    + [
                        {
                            "endpoint": webhook_url,
                            "result": "success",
                            "status_code": response.status_code,
                            "verify_ssl": verify_ssl,
                        }
                    ],
                }

            # 404 often means wrong n8n mode (test vs active). Try next candidate.
            if response.status_code == 404:
                last_error = f"404 Not Found on {webhook_url}"
                attempts.append(
                    {
                        "endpoint": webhook_url,
                        "result": "http_404",
                        "detail": last_error,
                        "verify_ssl": verify_ssl,
                    }
                )
                continue

            try:
                error_body = response.json()
            except ValueError:
                error_body = response.text
            return {
                "endpoint": webhook_url,
                "status_code": response.status_code,
                "error": error_body,
                "attempts": attempts
                + [
                    {
                        "endpoint": webhook_url,
                        "result": "http_error",
                        "status_code": response.status_code,
                        "verify_ssl": verify_ssl,
                    }
                ],
            }

        return {
            "error": f"n8n request failed: {last_error or 'unknown error'}",
            "hint": "Ensure n8n is running and, for /webhook-test/*, click 'Listen for test event' before scanning. Set N8N_PREFER_TEST_WEBHOOK=false to prioritize /webhook/* and set N8N_VERIFY_SSL=true to force certificate verification.",
            "attempts": attempts,
        }

    def send_to_n8n(self):
        user_input = self.url_entry.get().strip()
        result = self.scan_url(user_input)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, str(result))
        self.results_text.config(state=tk.DISABLED)

    def start_scan(self):
        """Start scanning in background thread"""
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress")
            return

        # Get target
        selected_tab = self.notebook.index(self.notebook.select())

        if selected_tab == 0:  # URL
            target = self.url_entry.get().strip()
            if not target:
                messagebox.showerror("Error", "Enter a URL, domain, or IP address")
                return
        elif selected_tab == 1:  # Hash
            target = self.hash_entry.get().strip()
            if not target:
                messagebox.showerror("Error", "Enter a file hash")
                return
        else:  # File
            if not self.selected_file:
                messagebox.showerror("Error", "Select a file to scan")
                return
            target = self.selected_file

        # Check engines
        engines = set()
        if self.vt_enabled.get():
            engines.add("vt")
        if self.ha_enabled.get():
            engines.add("ha")

        use_n8n = self.n8n_enabled.get()
        if not engines and not use_n8n:
            messagebox.showerror(
                "Error", "Select at least one scanning engine or enable n8n workflow"
            )
            return

        # Check API keys
        vt_key = self.vt_key_entry.get().strip()
        ha_key = self.ha_key_entry.get().strip()

        if "vt" in engines and not vt_key:
            messagebox.showerror("Error", "Enter VirusTotal API key")
            return
        if "ha" in engines and not ha_key:
            messagebox.showerror("Error", "Enter Hybrid Analysis API key")
            return

        # Start scan in thread
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        self.progress_label.pack(fill=tk.X, padx=5)
        self.progress.start()

        thread = threading.Thread(
            target=self.run_scan, args=(target, engines, vt_key, ha_key, use_n8n)
        )
        thread.daemon = True
        thread.start()

    def run_scan(self, target, engines, vt_key, ha_key, use_n8n):
        """Run scan (executed in background thread)"""
        try:
            self.latest_n8n_result = None
            result = None

            if engines:
                self.scanner = ThreatScopeScanner(vt_key, ha_key)
                self.root.after(0, self.display_status, "Scanning target...")

                result = self.scanner.scan(target, engines)
                self.current_result = result

                # Save to history
                self.config_manager.add_to_history(result)

            if use_n8n:
                self.root.after(0, self.display_status, "Sending to n8n workflow...")
                try:
                    self.latest_n8n_result = self.scan_url(target)
                except Exception as e:
                    self.latest_n8n_result = {"error": f"n8n Error: {str(e)}"}

            # Display results
            if result:
                self.root.after(0, self.display_result, result)
            else:
                self.root.after(0, self.display_n8n_only_result, target)

        except Exception as e:
            self.root.after(0, self.display_error, str(e))
        finally:
            self.scanning = False
            self.root.after(0, self.scan_complete)

    def display_status(self, message):
        """Display status message"""
        self.progress_label.config(text=f"Status: {message}")

    def display_result(self, result: ScanResult):
        """Display scan result"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)

        # Verdict
        verdict_tag = (
            "danger"
            if result.verdict == "danger"
            else "warning" if result.verdict == "warning" else "safe"
        )
        verdict_text = (
            "⚠ MALICIOUS"
            if result.verdict == "danger"
            else "⚑ SUSPICIOUS" if result.verdict == "warning" else "✓ CLEAN"
        )

        self.results_text.insert(tk.END, verdict_text + "\n", verdict_tag)
        self.results_text.insert(tk.END, "=" * 70 + "\n\n")

        self.results_text.insert(tk.END, "🎯 Target: ", "header")
        self.results_text.insert(tk.END, f"{result.target}\n\n")

        self.results_text.insert(tk.END, "📅 Time: ", "header")
        self.results_text.insert(tk.END, f"{result.timestamp}\n\n")

        self.results_text.insert(tk.END, "-" * 70 + "\n\n")

        # VirusTotal results
        if result.vt:
            self.results_text.insert(tk.END, "🔵 VirusTotal\n", "header")
            if result.vt.error:
                self.results_text.insert(
                    tk.END, f"  ❌ {result.vt.error}\n\n", "danger"
                )
            else:
                self.results_text.insert(tk.END, f"  Malicious:  ", "muted")
                self.results_text.insert(tk.END, f"{result.vt.malicious}\n", "danger")
                self.results_text.insert(tk.END, f"  Suspicious: ", "muted")
                self.results_text.insert(tk.END, f"{result.vt.suspicious}\n", "warning")
                self.results_text.insert(tk.END, f"  Harmless:   ", "muted")
                self.results_text.insert(tk.END, f"{result.vt.harmless}\n", "safe")
                self.results_text.insert(tk.END, f"  Undetected: ", "muted")
                self.results_text.insert(tk.END, f"{result.vt.undetected}\n\n")

                if result.vt.sha256:
                    self.results_text.insert(
                        tk.END, f"  SHA256: {result.vt.sha256[:32]}...\n"
                    )
                if result.vt.file_type:
                    self.results_text.insert(tk.END, f"  Type: {result.vt.file_type}\n")
                if result.vt.detected_by:
                    self.results_text.insert(
                        tk.END,
                        f"  Detected by: {', '.join(result.vt.detected_by[:3])}\n\n",
                    )

        # Hybrid Analysis results
        if result.ha:
            self.results_text.insert(tk.END, "🟠 Hybrid Analysis\n", "header")
            if result.ha.error:
                self.results_text.insert(
                    tk.END, f"  ❌ {result.ha.error}\n\n", "danger"
                )
            else:
                if result.ha.verdict:
                    verdict_tag = (
                        "danger"
                        if result.ha.verdict == "malicious"
                        else "warning" if result.ha.verdict == "suspicious" else "safe"
                    )
                    self.results_text.insert(tk.END, f"  Verdict: ", "muted")
                    self.results_text.insert(
                        tk.END, f"{result.ha.verdict.upper()}\n", verdict_tag
                    )

                if result.ha.threat_score is not None:
                    self.results_text.insert(tk.END, f"  Threat Score: ", "muted")
                    score_tag = (
                        "danger"
                        if result.ha.threat_score >= 75
                        else "warning" if result.ha.threat_score >= 50 else "safe"
                    )
                    self.results_text.insert(
                        tk.END, f"{result.ha.threat_score}/100\n", score_tag
                    )

                if result.ha.malware_family:
                    self.results_text.insert(tk.END, f"  Malware Family: ", "muted")
                    self.results_text.insert(
                        tk.END, f"{result.ha.malware_family}\n", "danger"
                    )

                if result.ha.tags:
                    self.results_text.insert(
                        tk.END, f"  Tags: {', '.join(result.ha.tags[:5])}\n\n"
                    )

        if self.latest_n8n_result is not None:
            self.results_text.insert(tk.END, "🧩 n8n Workflow\n", "header")
            self.results_text.insert(
                tk.END, json.dumps(self.latest_n8n_result, indent=2) + "\n"
            )

        self.results_text.config(state=tk.DISABLED)

    def display_n8n_only_result(self, target: str):
        """Display n8n-only result"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)

        self.results_text.insert(tk.END, "🧩 n8n Workflow Only\n", "header")
        self.results_text.insert(tk.END, "=" * 70 + "\n\n")
        self.results_text.insert(tk.END, "🎯 Target: ", "header")
        self.results_text.insert(tk.END, f"{target}\n\n")
        self.results_text.insert(tk.END, "📅 Time: ", "header")
        self.results_text.insert(tk.END, f"{datetime.now().isoformat()}\n\n")

        if self.latest_n8n_result is not None:
            self.results_text.insert(tk.END, "-" * 70 + "\n\n")
            self.results_text.insert(tk.END, "🧩 n8n Workflow\n", "header")
            self.results_text.insert(
                tk.END, json.dumps(self.latest_n8n_result, indent=2) + "\n"
            )
        else:
            self.results_text.insert(
                tk.END, "No n8n response received.\n", "danger"
            )

        self.results_text.config(state=tk.DISABLED)

    def display_error(self, error):
        """Display error message"""
        messagebox.showerror("Scan Error", f"Error during scan: {error}")

    def scan_complete(self):
        """Called when scan completes"""
        self.progress.stop()
        self.progress.pack_forget()
        self.progress_label.pack_forget()
        self.scan_button.config(state=tk.NORMAL)
        self.progress_label.config(text="")
        self.refresh_history()  # Refresh history after scan  # Refresh history after scan

    def save_results(self):
        """Save results to file"""
        if not self.current_result:
            messagebox.showwarning("Warning", "No results to save")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )

        if filename:
            with open(filename, "w") as f:
                json.dump(self.current_result.to_dict(), f, indent=2)
            messagebox.showinfo("Success", f"Results saved to {filename}")

    def copy_results(self):
        """Copy results to clipboard"""
        if not self.current_result:
            messagebox.showwarning("Warning", "No results to copy")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(self.results_text.get(1.0, tk.END))
        messagebox.showinfo("Success", "Results copied to clipboard")

    def clear_results(self):
        """Clear results"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.current_result = None

    def show_history(self):
        """Show scan history in popup window"""
        history = self.config_manager.load_history()

        if not history:
            messagebox.showinfo("History", "No scan history")
            return

        # Create history window
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("600x400")
        history_window.configure(bg=self.BG_PRIMARY)

        # History text
        history_text = scrolledtext.ScrolledText(
            history_window, bg=self.BG_CARD, fg=self.TEXT_PRIMARY
        )
        history_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        history_text.tag_config("danger", foreground=self.DANGER_RED)
        history_text.tag_config("warning", foreground=self.WARN_YELLOW)
        history_text.tag_config("safe", foreground=self.ACCENT_GREEN)
        history_text.tag_config(
            "muted", foreground=self.TEXT_MUTED, font=("Courier", 9)
        )

        for i, item in enumerate(history[:20], 1):
            verdict = item["verdict"]
            tag = (
                "danger"
                if verdict == "danger"
                else "warning" if verdict == "warning" else "safe"
            )

            emoji = "⚠" if verdict == "danger" else "⚑" if verdict == "warning" else "✓"

            history_text.insert(tk.END, f"{i}. {emoji} ")
            history_text.insert(tk.END, f"{verdict.upper()}", tag)
            history_text.insert(tk.END, f" -  {item['target']}\n")
            history_text.insert(tk.END, f"   {item['timestamp'][:10]}\n\n", "muted")

        history_text.config(state=tk.DISABLED)

        # Clear button
        ttk.Button(
            history_window,
            text="Clear History",
            command=lambda: self.clear_history_confirmed(history_window),
        ).pack(pady=10)

    def clear_history_confirmed(self, window):
        """Clear history with confirmation"""
        if messagebox.askyesno("Clear History", "Are you sure?"):
            self.config_manager.clear_history()
            messagebox.showinfo("Success", "History cleared")
            window.destroy()


def main():
    root = tk.Tk()
    app = ThreatScopeGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
