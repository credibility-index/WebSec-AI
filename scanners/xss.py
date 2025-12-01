import requests
from urllib.parse import urlencode

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]


def scan_xss_basic(url: str):
    """
    Простейшая эвристика XSS:
    подставляем несколько payload'ов в типичные параметры (q, search, s)
    и проверяем, отражаются ли они в ответе как есть.
    Возвращает список попыток с флагом подозрительности.
    """
    params_to_try = ["q", "query", "search", "s"]
    results = []

    for param in params_to_try:
        for payload in XSS_PAYLOADS:
            query = urlencode({param: payload})
            test_url = f"{url}?{query}"
            print(f"[*] XSS check: {test_url}")

            try:
                resp = requests.get(test_url, timeout=10)
            except requests.RequestException as exc:
                print(f"[!] Не удалось открыть {test_url}: {exc}")
                results.append({
                    "param": param,
                    "payload": payload,
                    "tested_url": test_url,
                    "error": str(exc),
                    "suspicious": False,
                })
                continue

            reflected = payload in resp.text
            if reflected:
                print(f"[!] Возможная XSS: параметр '{param}', payload '{payload}' отражён в ответе.")
            else:
                print(f"[+] XSS-признаков не найдено для параметра '{param}' и данного payload.")

            results.append({
                "param": param,
                "payload": payload,
                "tested_url": test_url,
                "status_code": resp.status_code,
                "suspicious": reflected,
            })

    return results


def scan_xss(url: str) -> bool:
    """
    Обёртка для WebSecAI:
    возвращает True, если хотя бы один payload отразился в ответе.
    """
    results = scan_xss_basic(url)
    any_suspicious = any(r.get("suspicious") for r in results)

    if any_suspicious:
        print("[!] Итог: обнаружены потенциальные признаки XSS (по эвристике).")
    else:
        print("[+] Итог: явных признаков XSS не найдено.")

    return any_suspicious
