import requests
from urllib.parse import urlencode
from typing import List

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{config}}", "Config"),
    ("{{''.__class__}}", "class"),
]

PARAMS = ["q", "query", "search", "name", "template", "t", "input", "data"]

def scan_ssti(url: str, timeout: int = 8) -> List[str]:
    issues: List[str] = []
    base = url.split("?")[0]
    if not base.startswith("http"):
        return issues

    for param in PARAMS:
        for payload, expected in SSTI_PAYLOADS:
            try:
                test_url = f"{base}?{param}={urlencode({param: payload})}"
                resp = requests.get(test_url, timeout=timeout, allow_redirects=False)
                text = (resp.text or "").strip()
                if expected in text and payload not in text:
                    issues.append(f"SSTI: possible template injection (param={param}, payload pattern)")
                    break
            except requests.RequestException:
                pass
            except Exception:
                pass
        if issues:
            break
    return issues
