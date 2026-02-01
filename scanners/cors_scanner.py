import requests
from typing import List


def scan_cors(url: str, timeout: int = 8) -> List[str]:
    issues: List[str] = []
    try:
        base = url.split("?")[0].rstrip("/")
        if not base.startswith("http"):
            return issues

        evil_origin = "https://evil.example.com"
        headers_origin = {"Origin": evil_origin}

        resp = requests.get(url, timeout=timeout, headers=headers_origin, allow_redirects=True)
        acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if acao == evil_origin:
            issues.append("CORS: Origin reflected (attacker origin accepted)")
        if acao == "*" and acac == "true":
            issues.append("CORS: Wildcard (*) with Allow-Credentials (insecure)")
        if acao == "null":
            issues.append("CORS: Access-Control-Allow-Origin: null (can be abused)")
    except requests.RequestException:
        pass
    except Exception:
        pass
    return issues
