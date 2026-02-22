"""
Configuration and history management
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class ConfigManager:
    """Manage API keys and scan history"""

    CONFIG_DIR = Path.home() / ".threatscope"
    CONFIG_FILE = CONFIG_DIR / "config.json"
    HISTORY_FILE = CONFIG_DIR / "history.json"

    def __init__(self):
        self.CONFIG_DIR.mkdir(exist_ok=True)

    def get_api_key(self, engine: str) -> Optional[str]:
        """Get API key from config or environment"""
        env_map = {"vt": "VT_API_KEY", "ha": "HA_API_KEY"}
        env_var = env_map.get(engine)

        # Check environment first
        if env_var and env_var in os.environ:
            return os.environ[env_var]

        # Check config file
        config = self._load_config()
        return config.get("keys", {}).get(engine)

    def set_api_key(self, engine: str, key: str) -> None:
        """Save API key to config"""
        config = self._load_config()
        if "keys" not in config:
            config["keys"] = {}
        config["keys"][engine] = key
        self._save_config(config)

    def _load_config(self) -> Dict:
        """Load configuration file"""
        if self.CONFIG_FILE.exists():
            with open(self.CONFIG_FILE) as f:
                return json.load(f)
        return {}

    def _save_config(self, config: Dict) -> None:
        """Save configuration file"""
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)

    def load_history(self) -> List[Dict]:
        """Load scan history"""
        if self.HISTORY_FILE.exists():
            with open(self.HISTORY_FILE) as f:
                return json.load(f)
        return []

    def add_to_history(self, result) -> None:
        """Add scan result to history"""
        history = self.load_history()
        history.insert(0, {
            "target": result.target,
            "type": result.scan_type,
            "verdict": result.verdict,
            "timestamp": result.timestamp
        })
        # Keep last 20 scans
        history = history[:20]
        with open(self.HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)

    def clear_history(self) -> None:
        """Clear all history"""
        if self.HISTORY_FILE.exists():
            self.HISTORY_FILE.unlink()


def load_env_file(path: Optional[Path] = None) -> None:
    """Load simple KEY=VALUE pairs from a .env file without external deps."""
    env_path = path or (Path(__file__).resolve().parent / ".env")
    if not env_path.exists():
        return

    try:
        with open(env_path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        # If the file can't be read, just ignore and continue.
        pass
