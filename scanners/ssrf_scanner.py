import requests

# Частые SSRF-цели для простых проверок
SSRF_TEST_TARGETS = [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://169.254.169.254",  # метаданные облака
]


def scan_ssrf_basic(url: str):
    """
    Простейшая эвристика SSRF:
    подставляем внутренние URL в типичный параметр (?url= / ?redirect= / ?target=)
    и смотрим, отражается ли внутренний адрес/ответ.
    Возвращает список попыток с флагом подозрительности.
    """
    param_names = ["url", "redirect", "target", "next", "u"]
    results = []

    for param in param_names:
        for test_target in SSRF_TEST_TARGETS:
            test_url = f"{url}?{param}={test_target}"
            print(f"[*] SSRF check: {test_url}")

            try:
                resp = requests.get(test_url, timeout=10)
            except requests.RequestException as exc:
                print(f"[!] Не удалось открыть {test_url}: {exc}")
                results.append({
                    "param": param,
                    "payload": test_target,
                    "tested_url": test_url,
                    "error": str(exc),
                    "suspicious": False,
                })
                continue

            body_lower = resp.text.lower()
            suspicious = (
                "localhost" in body_lower
                or "127.0.0.1" in body_lower
                or "169.254.169.254" in body_lower
                or "internal" in body_lower
            )

            if suspicious:
                print(f"[!] Возможная SSRF-уязвимость: параметр '{param}', payload '{test_target}'")
            else:
                print(f"[+] SSRF-признаков не найдено для параметра '{param}' и payload '{test_target}'.")

            results.append({
                "param": param,
                "payload": test_target,
                "tested_url": test_url,
                "status_code": resp.status_code,
                "suspicious": suspicious,
            })

    return results


def scan_ssrf(url: str) -> bool:
    """
    Обёртка для основного сканера WebSecAI:
    возвращает True, если хотя бы одна попытка выглядит подозрительно.
    """
    results = scan_ssrf_basic(url)
    any_suspicious = any(r.get("suspicious") for r in results)

    if any_suspicious:
        print("[!] Итог: обнаружены потенциальные признаки SSRF (по эвристике).")
    else:
        print("[+] Итог: явных признаков SSRF не найдено.")

    return any_suspicious
