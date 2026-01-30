import requests
import re
from bs4 import BeautifulSoup
from lxml import html

# Список названий токенов
CSRF_NAMES = {
    "csrf_token", "_token", "csrfmiddlewaretoken", "__RequestVerificationToken",
    "authenticity_token", "anti_csrf", "token", "csrf"
}

def _normalize(s: str | None) -> str:
    return (s or "").strip().lower()

def _extract_csrf_from_js(content: str) -> bool:
    """Ищет CSRF токены в JS коде и AJAX вызовах"""
    patterns = [
        # Присваивание токенов
        r'(?:csrf|token|auth)[^=:]*[:=]\s*["\'][\w-]{10,}["\']',
        # Заголовки AJAX
        r'headers\s*[:=]\s*{[^}]*x-csrf[^}]*}',
        r'meta\[name=["\']csrf-token["\']\]'
    ]
    for p in patterns:
        if re.search(p, content, re.IGNORECASE | re.DOTALL):
            return True
    return False

def check_csrf_cookies(resp) -> bool:
    """Проверяет cookies на наличие csrf токена"""
    for cookie in resp.cookies:
        if "csrf" in cookie.name.lower():
            return True
    return False

def check_csrf_headers(resp) -> bool:
    """Проверяет заголовки ответа"""
    for h in resp.headers:
        if "csrf" in h.lower() or "x-xsrf" in h.lower():
            return True
    return False

def check_csrf_meta(soup) -> bool:
    """Проверяет <meta> теги"""
    meta = soup.find("meta", attrs={"name": re.compile(r"csrf|token", re.I)})
    return bool(meta)

def check_forms(soup, tree) -> list:
    """Проверяет формы на наличие скрытых полей с токенами"""
    suspicious = []
    forms = soup.find_all("form")
    
    for idx, form in enumerate(forms, 1):
        has_token = False
        
        # 1. Проверяем input поля
        for inp in form.find_all("input"):
            name = _normalize(inp.get("name"))
            if any(x in name for x in CSRF_NAMES):
                has_token = True
                break
        
        # 2. Проверяем action формы (если это login/register - критично)
        action = _normalize(form.get("action"))
        is_sensitive = any(x in action for x in ["login", "register", "password", "account", "admin"])
        
        if not has_token and is_sensitive:
            # 3. Последний шанс: ищем в JS внутри формы
            if _extract_csrf_from_js(str(form)):
                has_token = True
            
            if not has_token:
                suspicious.append({
                    "index": idx,
                    "action": action,
                    "method": form.get("method", "GET").upper()
                })
    return suspicious

def check_csrf_protection(url: str) -> bool:
    """
    Главная функция.
    Возвращает True, если найдена УЯЗВИМОСТЬ (т.е. защиты НЕТ).
    """
    print(f"[*] CSRF check: {url}")
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        try:
            tree = html.fromstring(resp.text)
        except: tree = None
        
        # 1. Глобальные проверки (Cookies, Headers, Meta, JS)
        # Если защита реализована глобально (например, в заголовках или куках для SPA),
        # то отдельные формы могут не иметь токенов.
        has_global_protection = (
            check_csrf_cookies(resp) or 
            check_csrf_headers(resp) or 
            check_csrf_meta(soup) or
            _extract_csrf_from_js(resp.text)
        )
        
        if has_global_protection:
            print("  🟢 Global CSRF protection found (Cookies/Meta/JS)")
            return False # Уязвимости нет
            
        # 2. Проверка конкретных форм (если глобальной защиты нет)
        suspicious_forms = check_forms(soup, tree)
        
        if suspicious_forms:
            print(f"  🔴 CSRF Vulnerability: {len(suspicious_forms)} forms without tokens")
            return True # Уязвимость есть!
            
        print("  🟢 No suspicious forms found")
        return False # Уязвимости нет

    except Exception as e:
        print(f"  ⚠️ CSRF check error: {e}")
        return False
