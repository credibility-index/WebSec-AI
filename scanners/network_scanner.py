"""
Web-focused Network Exposure Scanner
Проверяет HTTP/HTTPS-only exposure и утечки конфигурации.
"""

import requests
import socket
from typing import List
from urllib.parse import urlparse

def scan_web_ports(url: str) -> List[str]:
    """
    Проверяет доступность нестандартных веб-портов (8080, 8443, 8888).
    Использует socket, но очень аккуратно.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host: return []
    except: return []
    
    # Порты, которые НЕ должны быть открыты публично, но часто бывают
    test_ports = [8080, 8443, 8000, 8888]
    issues = []
    
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5) # Быстрый таймаут
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                issues.append(f"Non-standard web port {port} is OPEN (potential admin panel/dev server)")
        except:
            pass # Игнорируем ошибки сети (фаервол и т.д.)
    
    return issues

def check_security_headers(url: str) -> List[str]:
    """
    Проверяет утечки версий ПО и отсутствие важных заголовков.
    """
    issues = []
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        
        # 1. Утечка версии сервера (Server: Apache/2.4.41 ...)
        server = headers.get('Server', '')
        if any(char.isdigit() for char in server): # Если есть цифры (версия)
            issues.append(f"Server Version Leak: {server}")
            
        # 2. X-Powered-By (PHP/7.4 ...)
        powered = headers.get('X-Powered-By', '')
        if powered:
            issues.append(f"Technology Leak (X-Powered-By): {powered}")
            
        # 3. Отсутствие HSTS (для HTTPS сайтов)
        if url.startswith('https') and 'Strict-Transport-Security' not in headers:
            issues.append("Missing HSTS Header (SSL Stripping risk)")
            
        # 4. Debug Mode check
        if 'development' in server.lower() or 'debug' in powered.lower():
            issues.append("CRITICAL: Server running in DEBUG/DEV mode!")

    except:
        pass
        
    return issues

def check_internal_access(url: str) -> List[str]:
    """
    Пытается обойти ограничения IP через заголовки (Bypass 403).
    """
    issues = []
    bypass_headers = {
        'X-Forwarded-For': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1'
    }
    
    try:
        # Сначала обычный запрос
        orig_resp = requests.get(url, timeout=5)
        
        # Если доступ закрыт (403), пробуем обойти
        if orig_resp.status_code == 403:
            for name, val in bypass_headers.items():
                try:
                    bypass_resp = requests.get(url, headers={name: val}, timeout=3)
                    if bypass_resp.status_code == 200:
                        issues.append(f"403 Bypass possible via header {name}: {val}")
                        break
                except: pass
    except:
        pass
        
    return issues

def scan_network_segmentation(target_url: str) -> List[str]:
    """WebSecAI wrapper"""
    print(f"🌐 Network scan: {target_url}")
    issues = []
    
    # 1. Порты (аккуратно)
    issues += scan_web_ports(target_url)
    
    # 2. Заголовки и версии
    issues += check_security_headers(target_url)
    
    # 3. Обход 403
    issues += check_internal_access(target_url)
    
    if issues:
        print(f"🟡 Network issues: {len(issues)}")
        for issue in issues:
            print(f"  → {issue}")
    else:
        print("🟢 Network clean")
    
    return issues
