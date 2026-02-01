import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_STORE = Path(os.environ.get("WEBSECAI_DATA", ".")) / "flag_tracker.json"

def _load() -> List[Dict[str, Any]]:
    if DEFAULT_STORE.exists():
        try:
            return json.loads(DEFAULT_STORE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []

def _save(data: List[Dict[str, Any]]) -> None:
    DEFAULT_STORE.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_STORE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def add(task_id: str, flag: str, status: str = "pending", note: str = "") -> Dict[str, Any]:
    entry = {"task_id": task_id, "flag": flag, "status": status, "note": note}
    data = _load()
    data.append(entry)
    _save(data)
    return entry

def list_flags(task_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    data = _load()
    if task_id:
        data = [x for x in data if x.get("task_id") == task_id]
    if status:
        data = [x for x in data if x.get("status") == status]
    return data

def update_status(index: int, status: str, note: str = "") -> Optional[Dict[str, Any]]:
    data = _load()
    if 0 <= index < len(data):
        data[index]["status"] = status
        if note:
            data[index]["note"] = note
        _save(data)
        return data[index]
    return None

def export_json() -> str:
    return json.dumps(_load(), indent=2, ensure_ascii=False)

def import_json(text: str) -> int:
    try:
        new_data = json.loads(text)
        if isinstance(new_data, list):
            _save(new_data)
            return len(new_data)
        return 0
    except Exception:
        return 0

def clear() -> int:
    n = len(_load())
    _save([])
    return n
