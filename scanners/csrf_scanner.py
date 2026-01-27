import requests
from bs4 import BeautifulSoup
from lxml import html
import re

CSRF_NAMES = {
    "csrf_token",
    "_token",
    "csrfmiddlewaretoken",
    "__RequestVerificationToken",
    "authenticity_token",
    "anti_csrf",
    "token"
}

def _normalize(s: str | None) -> str:
    return (s or "").strip().lower()

def _extract_csrf_from_js(content: str) -> bool:
    """
    Проверяем наличие CSRF в JavaScript-коде страницы
    """
    # Простые регулярные выражения для поиска CSRF в JS
    csrf_patterns = [
        r'csrf(?:token|key|value)\s*[:=]\s*["\']([^"\']+)',
        r'X-CSRF(?:-Token|Token)\s*[:=]\s*["\']([^"\']+)',
        r'antiForgeryToken\s*[:=]\s*["\']([^"\']+)'
    ]
    
    for pattern in csrf_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

def check_csrf_bs4(url: str):
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
        inputs = form.find_all(["input", "textarea", "select"])
        has_csrf = False
        has_js_csrf = False

        # Проверяем CSRF в форме
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

        # Проверяем CSRF в JavaScript
        if not has_csrf:
            has_js_csrf = _extract_csrf_from_js(str(form))

        if not has_csrf and not has_js_csrf:
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            print(f"[!] [BS4] Форма #{idx} без явного CSRF-токена (method={method}, action='{action}')")
            suspicious.append({
                "index": idx,
                "method": method,
                "action": action,
                "parser": "bs4",
                "csrf_in_js": has_js_csrf
            })

    if not suspicious:
        print("[+] [BS4] Явных проблем с CSRF-токенами не обнаружено (по эвристике).")

    return suspicious

def check_csrf_lxml(url: str):
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
        inputs = form.xpath(".//input | .//textarea | .//select")
        has_csrf = False
        has_js_csrf = False

        # Проверяем CSRF в форме
        for inp in inputs:
            name = _normalize(inp.get("name"))
            field_id = _normalize(inp.get("id"))
            field_type = _normalize(inp.get("type"))
            
            # Проверяем наличие токена в атрибутах
            token = inp.get("value")
            if token and "csrf" in token.lower():
                has_csrf = True
                break

            if name in {n.lower() for n in CSRF_NAMES}:
                has_csrf = True
                break
            if "csrf" in name or "csrf" in field_id:
                has_csrf = True
                break
            if field_type == "hidden" and "csrf" in name:
                has_csrf = True
                break

        # Проверяем CSRF в JavaScript
        if not has_csrf:
            form_html = html.tostring(form, encoding='unicode')
            has_js_csrf = _extract_csrf_from_js(form_html)

        if not has_csrf and not has_js_csrf:
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            print(f"[!] [lxml] Форма #{idx} без явного CSRF-токена (method={method}, action='{action}')")
            suspicious.append({
                "index": idx,
                "method": method,
                "action": action,
                "parser": "lxml",
                "csrf_in_js": has_js_csrf
            })

    if not suspicious:
        print("[+] [lxml] Явных проблем с CSRF-токенами не обнаружено (по эвристике).")

    return suspicious

def check_csrf_protection(url: str):
    print(f"[*] Запуск CSRF-проверки для {url}")
    bs4_result = check_csrf_bs4(url)
    lxml_result = check_csrf_lxml(url)

    # Объединяем результаты с дедупликацией
    combined = []
    seen = set()
    
    for result in bs4_result + lxml_result:
        key = (result['index'], result['method'], result['action'])
        if key not in seen:
            seen.add(key)
            combined.append(result)

    if combined:
        print(f"[!] Итого подозрительных форм: {len(combined)}")
    else:
        print("[+] CSRF-проблем не найдено обеими эвристиками.")

    return combined

def _extract_csrf_from_js(content: str) -> bool:
    """
    Расширенная проверка CSRF в JavaScript
    """
    csrf_patterns = [
        r'csrf(?:token|key|value)\s*[:=]\s*["\']([^"\']+)',
        r'X-CSRF(?:-Token|Token)\s*[:=]\s*["\']([^"\']+)',
        r'antiForgeryToken\s*[:=]\s*["\']([^"\']+)',
        r'token\s*[:=]\s*["\']([^"\']+)',  # Общий поиск токенов
        r'securityToken\s*[:=]\s*["\']([^"\']+)',
        r'sessionToken\s*[:=]\s*["\']([^"\']+)',
        r'authToken\s*[:=]\s*["\']([^"\']+)',
        r'requestToken\s*[:=]\s*["\']([^"\']+)',
        r'formToken\s*[:=]\s*["\']([^"\']+)',
        r'validateToken\s*[:=]\s*["\']([^"\']+)'
    ]
    
    # Проверяем наличие CSRF в заголовках AJAX-запросов
    ajax_patterns = [
        r'headers\s*[:=]\s*{[^}]*X-CSRF[^}]*}',
        r'headers\s*[:=]\s*{[^}]*csrf[^}]*}',
        r'beforeSend[^}]*function[^}]*X-CSRF[^}]*'
    ]
    
    # Проверяем наличие CSRF в параметрах AJAX
    data_patterns = [
        r'data\s*[:=]\s*{[^}]*csrf[^}]*}',
        r'data\s*[:=]\s*{[^}]*token[^}]*}',
        r'params\s*[:=]\s*{[^}]*csrf[^}]*}'
    ]
    
    # Проверяем все паттерны
    for pattern in csrf_patterns + ajax_patterns + data_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    
    return False

def check_csrf_protection(url: str):
    print(f"[*] Запуск CSRF-проверки для {url}")
    bs4_result = check_csrf_bs4(url)
    lxml_result = check_csrf_lxml(url)

    # Объединяем результаты с дедупликацией
    combined = []
    seen = set()
    
    for result in bs4_result + lxml_result:
        key = (result['index'], result['method'], result['action'])
        if key not in seen:
            seen.add(key)
            combined.append(result)

    if combined:
        print(f"[!] Итого подозрительных форм: {len(combined)}")
        for form in combined:
            print(f"  → Форма #{form['index']} (method={form['method']}, action={form['action']})")
    else:
        print("[+] CSRF-проблем не найдено обеими эвристиками.")

    return combined

# Дополнительные улучшения:
# 1. Проверка заголовков ответа на наличие CSRF-токена в cookies
# 2. Проверка мета-тегов для CSRF
# 3. Анализ AJAX-запросов на наличие CSRF

def check_csrf_cookies(resp):
    """
    Проверка CSRF-токена в cookies
    """
    for cookie in resp.cookies:
        if "csrf" in cookie.name.lower():
            print(f"[+] Найден CSRF-токен в cookie: {cookie.name}")
            return True
    return False

def check_csrf_meta_tags(soup):
    """
    Проверка мета-тегов на наличие CSRF
    """
    meta_tags = soup.find_all(
        'meta', 
        attrs={
            'name': lambda x: x and 'csrf' in x.lower(),
            'content': True
        }
    )
    
    if meta_tags:
        print("[+] Найден CSRF-токен в мета-тегах:")
        for tag in meta_tags:
            print(f"  → name: {tag['name']}, content: {tag['content']}")
        return True
    return False
def check_csrf_headers(resp):
    """
    Проверка заголовков ответа на наличие CSRF-токена
    """
    for header, value in resp.headers.items():
        if "csrf" in header.lower():
            print(f"[+] Найден CSRF-токен в заголовке: {header}")
            return True
    return False

def check_csrf_protection(url: str):
    try:
        resp = requests.get(url, timeout=10)
    except requests.RequestException as exc:
        print(f"[!] Ошибка при запросе к {url}: {exc}")
        return []

    print(f"[*] Запуск полной CSRF-проверки для {url}")
    
    # Проверка cookies
    if check_csrf_cookies(resp):
        print("[+] CSRF-токен найден в cookies")
    
    # Проверка заголовков
    if check_csrf_headers(resp):
        print("[+] CSRF-токен найден в заголовках")
    
    # Парсинг HTML
    soup = BeautifulSoup(resp.text, "html.parser")
    
    # Проверка мета-тегов
    if check_csrf_meta_tags(soup):
        print("[+] CSRF-токен найден в мета-тегах")
    
    # Проверка форм
    bs4_result = check_csrf_bs4(url)
    lxml_result = check_csrf_lxml(url)

    # Объединяем результаты с дедупликацией
    combined = []
    seen = set()
    
    for result in bs4_result + lxml_result:
        key = (result['index'], result['method'], result['action'])
        if key not in seen:
            seen.add(key)
            combined.append(result)

    if combined:
        print(f"[!] Итого подозрительных форм: {len(combined)}")
        for form in combined:
            print(f"  → Форма #{form['index']} (method={form['method']}, action={form['action']})")
    else:
        print("[+] CSRF-проблем не найдено в формах")

    # Итоговый вывод
    if not (bs4_result or lxml_result) and (check_csrf_cookies(resp) or check_csrf_headers(resp) or check_csrf_meta_tags(soup)):
        print("[+] Полная защита от CSRF обнаружена")
    else:
        print("[!] Возможные проблемы с защитой от CSRF")

    return combined

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Использование: python script.py <URL>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    check_csrf_protection(target_url)

