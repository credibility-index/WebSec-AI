"""Load and validate config.yaml for scan profiles and flag patterns."""
import os
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
except ImportError:
    yaml = None

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
DEFAULT_PROFILES = {
    "ctf_quick": {"modules": ["sqli", "xss", "csrf", "ssrf", "network"], "depth": 2, "timeout": 60},
    "ctf_full": {
        "modules": ["sqli", "xss", "csrf", "ssrf", "network", "cors", "host_header", "ssti"],
        "depth": 5,
        "timeout": 300,
    },
    "devsecops": {"modules": ["sqli", "xss", "csrf", "ssrf", "network", "cors", "host_header", "recon"], "depth": 3, "timeout": 120},
}


def load_config() -> Dict[str, Any]:
    """Load config.yaml; return defaults if missing or invalid."""
    out: Dict[str, Any] = {
        "scan_profiles": DEFAULT_PROFILES,
        "flag_patterns": [
            r"flag\{[^}]+\}",
            r"ctf\{[^}]+\}",
            r"CTF\{[^}]+\}",
            r"RACTF\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"Flag\{[^}]+\}",
            r"duckerz\{[^}]+\}",
            r"Duckerz\{[^}]+\}",
            r"HTB\{[^}]+\}",
            r"THM\{[^}]+\}",
            r"picoCTF\{[^}]+\}",
            r"PicoCTF\{[^}]+\}",
            r"SECCON\{[^}]+\}",
            r"0ctf\{[^}]+\}",
            r"HITCON\{[^}]+\}",
            r"key\{[^}]+\}",
            r"KEY\{[^}]+\}",
            r"secret\{[^}]+\}",
            r"SECRET\{[^}]+\}",
            r"pass\{[^}]+\}",
            r"token\{[^}]+\}",
            r"FLAG_[A-Za-z0-9_]{10,50}",
            r"flag_[a-z0-9_]{10,50}",
            r"CTF_[A-Za-z0-9_]{10,50}",
            r"flag\([^)]+\)",
            r"ctf\([^)]+\)",
            r"duckerz\([^)]+\)",
            r"HTB\([^)]+\)",
            r"THM\([^)]+\)",
            r"flag\[[^]]+\]",
            r"ctf\[[^]]+\]",
            r"FLAG\[[^]]+\]",
            r"key\[[^]]+\]",
            r"secret\[[^]]+\]",
            r"flag\<[^>]+\>",
            r"ctf\<[^>]+\>",
            r"FLAG\<[^>]+\>",
            r"[a-zA-Z0-9_]{3,30}\s*[{\[<][^})\]>]+[})\]>]",
            r"FLAG-[A-Za-z0-9_-]{10,60}",
            r"flag-[a-z0-9_-]{10,60}",
            r"CTF-[A-Za-z0-9_-]{10,60}",
            r"[A-Za-z0-9+/]{20,80}={0,2}",
            r"[a-fA-F0-9]{32,64}",
            r"[A-Za-z0-9_]{20,80}",
        ],
        "api": {},
    }
    if yaml and CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data:
                out.update(data)
        except Exception:
            pass
    return out


def get_profile(name: str) -> Dict[str, Any]:
    """Get scan profile by name; fallback to ctf_quick."""
    cfg = load_config()
    profiles = cfg.get("scan_profiles", {})
    return profiles.get(name, profiles.get("ctf_quick", list(profiles.values())[0] if profiles else {}))


def get_flag_patterns() -> List[str]:
    """Return list of regex patterns for flag hunting."""
    cfg = load_config()
    return cfg.get("flag_patterns", [])
