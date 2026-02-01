import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

LOG_PATH = Path(os.environ.get("WEBSECAI_AUDIT_LOG", "audit_log.jsonl"))

def log_event(event_type: str, target: str, meta: Optional[Dict[str, Any]] = None) -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "type": event_type,
            "target": target,
            "meta": meta or {},
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

def log_scan(target: str, profile: str, findings_count: int) -> None:
    log_event("scan", target, {"profile": profile, "findings": findings_count})

def log_export(export_type: str, name: str) -> None:
    log_event("export", name, {"format": export_type})
