import os
from typing import Any, Dict, List, Optional

import requests

def ctfd_submit(base_url: str, token: str, challenge_id: int, flag: str) -> Dict[str, Any]:
    base_url = base_url.rstrip("/")
    out: Dict[str, Any] = {"success": False, "message": "", "data": None}
    try:
        r = requests.post(
            f"{base_url}/api/v1/challenges/attempt",
            headers={"Authorization": f"Token {token}", "Content-Type": "application/json"},
            json={"challenge_id": challenge_id, "submission": flag},
            timeout=15,
        )
        data = r.json() if r.text else {}
        out["data"] = data
        if r.status_code == 200:
            out["success"] = data.get("data", {}).get("status") == "correct"
            out["message"] = data.get("data", {}).get("message", data.get("message", ""))
        else:
            out["message"] = data.get("message", r.text[:200])
    except Exception as e:
        out["message"] = str(e)
    return out

def ctfd_challenges(base_url: str, token: str) -> Dict[str, Any]:
    base_url = base_url.rstrip("/")
    out: Dict[str, Any] = {"success": False, "challenges": []}
    try:
        r = requests.get(
            f"{base_url}/api/v1/challenges",
            headers={"Authorization": f"Token {token}"},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            out["success"] = True
            out["challenges"] = data.get("data", [])
    except Exception as e:
        out["message"] = str(e)
    return out

def ctfd_me(base_url: str, token: str) -> Dict[str, Any]:
    base_url = base_url.rstrip("/")
    out: Dict[str, Any] = {"success": False, "user": None}
    try:
        r = requests.get(
            f"{base_url}/api/v1/users/me",
            headers={"Authorization": f"Token {token}"},
            timeout=10,
        )
        if r.status_code == 200:
            out["success"] = True
            out["user"] = r.json().get("data")
    except Exception as e:
        out["message"] = str(e)
    return out
