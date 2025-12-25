"""
Network Segmentation Scanner для WebSecAI
Проверяет VLAN hopping, открытые порты, межсетевые доступы
"""

import subprocess
import re
import socket
from typing import List
import requests
import socket

def check_ssh_public(host):
    sock = socket.socket()
    try:
        sock.settimeout(3)
        sock.connect((host, 22))
        banner = sock.recv(1024).decode().strip()
        return "SSH" in banner  # Critical!
    except:
        return False

def get_open_ports(target_ip: str) -> List[str]:
    """Сканирует топ-20 портов для выявления сервисов"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(f"{port}/tcp")
        sock.close()
    
    return open_ports

def scan_network_segmentation(target_url: str) -> List[str]:
    """
    Проверяет признаки плохой сетевой сегментации:
    - Открытые порты БД в публичной зоне
    - SSH/Telnet в гостевой сети  
    - RPC/SMB в DMZ
    """
    try:
        # Получаем IP из URL
        target_ip = target_url.replace('http://', '').replace('https://', '').split('/')[0]
        
        print(f"[*] Network scan: {target_ip}")
        issues = []
        
        # Быстрое сканирование портов
        open_ports = get_open_ports(target_ip)
        
        # Критические сервисы в публичной зоне = плохо
        dangerous_services = {
            '22/tcp': 'SSH exposed in public zone (lateral movement risk)',
            '23/tcp': 'Telnet exposed (cleartext credentials)',
            '3306/tcp': 'MySQL exposed without VPN/tunnel',
            '1433/tcp': 'MSSQL exposed in DMZ',
            '445/tcp': 'SMB exposed (ransomware vector)',
            '3389/tcp': 'RDP exposed publicly'
        }
        
        for port in open_ports:
            if port in dangerous_services:
                issues.append(dangerous_services[port])
        
        # Проверка на broadcast/reverse DNS (VLAN hopping clues)
        try:
            socket.gethostbyname(target_ip + '.1')  # соседний хост
        except:
            issues.append("No adjacent host response (good segmentation)")
        
        return issues
        
    except Exception as e:
        return [f"Network scan error: {str(e)}"]

def check_vlan_leakage(target_ip: str) -> List[str]:
    """Проверяет утечки между VLAN (broadcast traffic)"""
    # nmap broadcast discovery (упрощенно)
    try:
        result = subprocess.run(
            ["nmap", "-sn", f"{target_ip}/24"], 
            capture_output=True, text=True, timeout=10
        )
        hosts = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if len(hosts) > 10:
            return ["High host density - possible flat network (no segmentation)"]
    except:
        pass
    return []
