import requests
from bs4 import BeautifulSoup
from lxml import html

CSRF_NAMES = {
    "csrf_token",
    "_token",
    "csrfmiddlewaretoken",
    "__RequestVerificationToken",
}

def _normalize(s: str | None) -> str:
    return (s or "").strip().lower()


def check_csrf_bs4(url: str):
    """
    Эвристическая проверка CSRF с помощью BeautifulSoup.
    Ищем формы без явного CSRF-поля.
    Возвращает список подозрительных форм (index, method, action).
    """
    try:
        resp = requests.get(url, timeout=10)
    except requests.RequestException as exc:
        print(f"[!] Не удалось открыть {url}: {exc}")
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        print("[i] Форм на странице не найдено.")
        return []

    suspicious = []

    for idx, form in enumerate(forms, start=1):
        inputs = form.find_all("input")
        has_csrf = False

        for inp in inputs:
            name = _normalize(inp.get("name"))
            field_id = _normalize(inp.get("id"))
            field_type = _normalize(inp.get("type"))

            if name in {n.lower() for n in CSRF_NAMES}:
                has_csrf = True
                break
            if "csrf" in name or "csrf" in field_id:
                has_csrf = True
                break
            if field_type == "hidden" and "csrf" in name:
                has_csrf = True
                break

        if not has_csrf:
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            print(f"[!] [BS4] Форма #{idx} без явного CSRF-токена (method={method}, action='{action}')")
            suspicious.append({
                "index": idx,
                "method": method,
                "action": action,
                "parser": "bs4",
            })

    if not suspicious:
        print("[+] [BS4] Явных проблем с CSRF-токенами не обнаружено (по эвристике).")

    return suspicious


def check_csrf_lxml(url: str):
    """
    Эвристическая проверка CSRF с помощью lxml.
    Ищем формы без явного CSRF-поля.
    Возвращает список подозрительных форм (index, method, action).
    """
    try:
        resp = requests.get(url, timeout=10)
    except requests.RequestException as exc:
        print(f"[!] Не удалось открыть {url}: {exc}")
        return []

    try:
        tree = html.fromstring(resp.text)
    except Exception as exc:
        print(f"[!] Ошибка парсинга HTML (lxml): {exc}")
        return []

    forms = tree.xpath("//form")
    if not forms:
        print("[i] [lxml] Форм на странице не найдено.")
        return []

    suspicious = []

    for idx, form in enumerate(forms, start=1):
        inputs = form.xpath(".//input")
        has_csrf = False

        for inp in inputs:
            name = _normalize(inp.get("name"))
            field_id = _normalize(inp.get("id"))
            field_type = _normalize(inp.get("type"))

            if name in {n.lower() for n in CSRF_NAMES}:
                has_csrf = True
                break
            if "csrf" in name or "csrf" in field_id:
                has_csrf = True
                break
            if field_type == "hidden" and "csrf" in name:
                has_csrf = True
                break

        if not has_csrf:
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            print(f"[!] [lxml] Форма #{idx} без явного CSRF-токена (method={method}, action='{action}')")
            suspicious.append({
                "index": idx,
                "method": method,
                "action": action,
                "parser": "lxml",
            })

    if not suspicious:
        print("[+] [lxml] Явных проблем с CSRF-токенами не обнаружено (по эвристике).")

    return suspicious


def check_csrf_protection(url: str):
    """
    Обёртка: запускает обе проверки (BS4 + lxml) и объединяет результат.
    """
    print(f"[*] Запуск CSRF-проверки для {url}")
    bs4_result = check_csrf_bs4(url)
    lxml_result = check_csrf_lxml(url)

    # Объединяем результаты (без сложной дедупликации, это PoC)
    combined = bs4_result + lxml_result
    if combined:
        print(f"[!] Итого подозрительных форм: {len(combined)}")
    else:
        print("[+] CSRF-проблем не найдено обеими эвристиками.")

    return combined
