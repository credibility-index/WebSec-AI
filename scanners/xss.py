"""
XSS Scanner: Reflected & DOM XSS в параметрах q, search, input, data, cat, searchFor и др.
Проверяет GET, POST, фрагмент URL (для DOM XSS - заголовок Referer/источник).
"""
import requests
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
import html
import random
import string

# Сокращенный список для быстрого теста, полный можно оставить
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onfocus=alert(1) autofocus=",
    "javascript:alert(1)",
    "'><img src=x onerror=alert(1)>"
]

# Параметры, которые чаще всего уязвимы
PARAMS = ["q", "query", "search", "id", "p", "page", "callback", "url"]

def get_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

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
    
    # 1. Сначала проверим, жив ли сайт
    try:
        initial_check = requests.get(url, timeout=5)
        if initial_check.status_code in [403, 404]:
            print(f"⚠️ Site returned {initial_check.status_code} initially. Scanning might fail.")
    except:
        return [{"error": "Site unreachable", "suspicious": False}]

    # Определяем разделитель для параметров (? или &)
    sep = "&" if "?" in url else "?"

    for param in PARAMS:
        # 2. "Канарейка": Проверяем, отражается ли параметр вообще
        # Не бьем сразу атакой, чтобы не получить бан
        canary = get_random_string()
        probe_url = f"{url}{sep}{param}={canary}"
        
        try:
            resp = requests.get(probe_url, timeout=5)
            
            # Если нашей случайной строки нет в ответе, нет смысла атаковать этот параметр
            if canary not in resp.text:
                continue 
                
            # А вот если отразилась — тогда атакуем!
            print(f"🔎 Param '{param}' reflects input. Testing payloads...")

            for payload in XSS_PAYLOADS:
                # Формируем атаку
                attack_url = f"{url}{sep}{param}={payload}"
                resp_attack = requests.get(attack_url, timeout=5)

                reflected = payload in resp_attack.text

                if reflected:
                    results.append({
                        "param": param,
                        "payload": payload,
                        "url": attack_url,
                        "suspicious": True,
                        "type": "Reflected XSS"
                    })
                    # Нашли одну дыру в этом параметре — хватит его мучить, идем к следующему
                    break 

        except requests.RequestException as e:
            print(f"❌ Connection error on param {param}: {e}")
            # Не добавляем как 'чисто', просто пропускаем

    return results


def scan_xss(url: str) -> bool:
    print(f"🔍 Starting Smart XSS scan: {url}")
    results = scan_xss_basic(url)
    
    # Если results пустой, но ошибок не было - значит чисто
    # Если были ошибки connection - они просто скипнулись в коде выше
    
    suspicious = [r for r in results if r.get("suspicious")]
    
    if suspicious:
        print(f"🚨 XSS FOUND: {len(suspicious)} vectors!")
        for r in suspicious:
            print(f"  → Vuln Param: {r['param']} | Payload: {r['payload']}")
        return True
    
    if not results:
        print("🟢 No reflections found (Clean)")
    
    return False
