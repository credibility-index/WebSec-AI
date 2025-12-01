import requests

# Частые фрагменты SQL‑ошибок в ответах
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "psql:",
    "syntax error",
    "odbc sql server driver",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "sqlstate[hy000]",
]


def _contains_sql_error(text: str) -> bool:
    """Проверяем, похож ли ответ на типичную SQL‑ошибку."""
    low = text.lower()
    return any(sig in low for sig in SQL_ERROR_SIGNATURES)


def scan_sql_injection_basic(url: str):
    """
    Простейшая эвристика SQLi:
    делает GET с типичным payload и ищет SQL‑ошибки в ответе.
    Возвращает dict с результатами проверки.
    """
    payload = "' OR '1'='1"
    target = f"{url}?id={payload}"

    print(f"[*] SQLi basic check: {target}")

    try:
        resp = requests.get(target, timeout=10)
    except requests.RequestException as exc:
        print(f"[!] Не удалось открыть {target}: {exc}")
        return {
            "vulnerable": False,
            "error": str(exc),
            "tested_url": target,
        }

    is_error_like = _contains_sql_error(resp.text)

    if is_error_like:
        print("[!] Обнаружен возможный SQL Injection (по SQL‑ошибке в ответе).")
    else:
        print("[+] Явных признаков SQL Injection не найдено (по этой эвристике).")

    return {
        "vulnerable": bool(is_error_like),
        "tested_url": target,
        "status_code": resp.status_code,
        "content_length": len(resp.text),
    }


def scan_sql_injection(url: str):
    """
    Обёртка под основной сканер WebSecAI:
    возвращает True/False для быстрой логики
    и печатает человекочитаемый вывод.
    """
    result = scan_sql_injection_basic(url)
    return result.get("vulnerable", False)
