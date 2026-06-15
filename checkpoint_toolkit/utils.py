"""Settings persistence (JSON-as-YAML) and logging for the firewall toolkit."""

import json
import logging
import os
import sys

SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "settings.yaml")
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "firewall_tools.log")
DEFAULT_LOG_LEVEL = "INFO"

DEFAULT_SETTINGS = {
    "timeout": 300,
    "page_size": 200,
    "download_dir": "examples",
    "log_level": "INFO",
    "last_server": "",
    "last_username": "",
    "last_port": 443,
    "last_vendor": "auto",
    "last_verify_ssl": False,
    "last_policy_name": "fetched_policy",
    "last_output_dir": "examples",
}


def load_settings():
    """Load settings from the YAML file (JSON format stored as .yaml)."""
    if not os.path.exists(SETTINGS_PATH):
        return dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = dict(DEFAULT_SETTINGS)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULT_SETTINGS)


def save_settings(settings):
    """Save settings to the YAML file."""
    out_dir = os.path.dirname(SETTINGS_PATH)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    return True


def _log_level_name(level_int):
    return logging.getLevelName(level_int)


def setup_logging(level_name="INFO"):
    """Configure logging to file.  Creates log directory if needed."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        filename=LOG_FILE,
        level=level,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )
    return level


def reset_log():
    """Clear the log file."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("")
    logging.info("Log file reset")
