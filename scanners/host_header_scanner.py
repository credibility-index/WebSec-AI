import requests
from typing import List
from urllib.parse import urlparse


def scan_host_header(url: str, timeout: int = 6) -> List[str]:
    issues: List[str] = []
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        if not host or not url.startswith("http"):
            return issues

        evil_host = "evil.example.com"
        headers_evil = {"Host": evil_host}
        resp_evil = requests.get(url, timeout=timeout, headers=headers_evil, allow_redirects=False)
        if evil_host in (resp_evil.text or ""):
            issues.append("Host Header: Server reflects attacker-controlled Host in response")

        headers_xfh = {"Host": host, "X-Forwarded-Host": evil_host}
        resp_xfh = requests.get(url, timeout=timeout, headers=headers_xfh, allow_redirects=False)
        if resp_xfh.status_code in (301, 302, 307, 308):
            loc = resp_xfh.headers.get("Location", "")
            if evil_host in loc:
                issues.append("Host Header: X-Forwarded-Host used for redirect (cache poisoning risk)")
        if evil_host in (resp_xfh.text or ""):
            issues.append("Host Header: X-Forwarded-Host reflected in body")
    except requests.RequestException:
        pass
    except Exception:
        pass
    return issues
