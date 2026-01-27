"""
Web-focused Network Exposure Scanner
Проверяет HTTP/HTTPS-only exposure (без TCP scan)
"""

import requests
import socket
from typing import List
from urllib.parse import urlparse

def scan_web_ports(url: str) -> List[str]:
    """HTTP-only port exposure (80/443/8080)"""
    parsed = urlparse(url)
    host = parsed.hostname
    
    test_ports = [80, 443, 8080, 8443]
    issues = []
    
    for port in test_ports:
        try:
            sock = socket.socket()
            sock.settimeout(2)
            if sock.connect_ex((host, port)) == 0:
                if port not in [80, 443]:
                    issues.append(f"Non-standard HTTP port {port} exposed")
            sock.close()
        except:
            pass
    
    return issues

def check_internal_redirects(url: str) -> List[str]:
    """Internal redirects / X-Powered-By leaks"""
    headers = ['X-Forwarded-For: 127.0.0.1', 'X-Originating-IP: 127.0.0.1']
    issues = []
    
    for hdr in headers:
        try:
            resp = requests.get(url, headers={hdr.split(':')[0]: hdr.split(':',1)[1]}, timeout=5)
            if 'internal' in resp.text.lower() or resp.status_code == 302:
                issues.append("Internal redirect leak via X-Forwarded-For")
        except:
            pass
    
    return issues

def scan_network_segmentation(target_url: str) -> List[str]:
    """WebSecAI wrapper: HTTP-only checks"""
    print(f"🌐 Web exposure scan: {target_url}")
    issues = []
    
    # 1. Non-standard ports
    issues += scan_web_ports(target_url)
    
    # 2. Header leaks
    issues += check_internal_redirects(target_url)
    
    # 3. Server leaks
    try:
        resp = requests.get(target_url, timeout=5)
        server = resp.headers.get('Server', '')
        powered_by = resp.headers.get('X-Powered-By', '')
        if 'development' in server.lower() or 'debug' in powered_by.lower():
            issues.append("Development server exposed (debug mode)")
    except:
        pass
    
    if issues:
        print(f"🟡 Network issues: {len(issues)}")
        for issue in issues:
            print(f"  → {issue}")
    else:
        print("🟢 Web exposure clean")
    
    return issues
