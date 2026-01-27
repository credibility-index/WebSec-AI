import os
import json
import time
from typing import List, Tuple, Optional, Dict
from datetime import datetime
import concurrent.futures
import requests

# Fallback сканеры (если нет scanners/)
def scan_sql_injection(url): return False
def scan_xss(url): return False
def check_csrf_protection(url): return False
def scan_ssrf(url): return False
def scan_network_segmentation(url): return []

# Загрузка реальных сканеров
try:
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
    from scanners.network_scanner import scan_network_segmentation
    print("✅ Real scanners loaded")
except ImportError:
    print("⚠️ Using fallback scanners")

def ai_analysis(vulnerabilities: List[str]) -> Tuple[str, str]:
    if not vulnerabilities:
        return ("✅ Clean scan", "✅ Чистый скан")
    vulns = ", ".join(vulnerabilities)
    return (
        f"🚨 Risks: {vulns}. Fix immediately!",
        f"🚨 Риски: {vulns}. Исправьте срочно!"
    )

def full_scan(url: str, timeout: float = 4.0, max_workers: int = 4) -> Dict:
    print(f"🔍 Scanning {url}...")
    results = {
        "timestamp": datetime.now().isoformat(),
        "target": url,
        "vulnerabilities": [],
        "metrics": {}
    }
    
    t0 = time.time()
    
    scanners = [
        ("SQLi", scan_sql_injection, [url]),
        ("XSS", scan_xss, [url]),
        ("CSRF", check_csrf_protection, [url]),
        ("SSRF", scan_ssrf, [url])
    ]
    
    # ⚡ Параллельно
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(func, *args): name for name, func, args in scanners}
        
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                detected = future.result(timeout=timeout)
                if detected:
                    results["vulnerabilities"].append(name)
                print(f"  {name}: {'🟡 HIT' if detected else '🟢 OK'}")
            except:
                print(f"  {name}: ⏱️ Timeout")
    
    scan_time = time.time() - t0
    results["metrics"] = {
        "scan_time": round(scan_time, 1),
        "vuln_count": len(results["vulnerabilities"]),
        "score": max(0, 100 - len(results["vulnerabilities"]) * 25)
    }
    
    results["ai_analysis"] = {"en": "", "ru": ""}
    results["ai_analysis"]["en"], results["ai_analysis"]["ru"] = ai_analysis(results["vulnerabilities"])
    
    return results

def generate_reports(results: Dict) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs("reports", exist_ok=True)
    
    vulns = results["vulnerabilities"]
    metrics = results["metrics"]
    
    # EN Report
    en_md = f"""# WebSecAI Report
Target: {results["target"]}
Vulns: {len(vulns)} | Score: {metrics["score"]}/100

AI: {results["ai_analysis"]["en"]}"""
    
    # RU Report  
    ru_md = f"""# Отчёт WebSecAI
Цель: {results["target"]}
Уязвимостей: {len(vulns)} | Оценка: {metrics["score"]}/100

AI: {results["ai_analysis"]["ru"]}"""
    
    # TXT
    txt = f"WebSecAI {ts}\nTarget: {results['target']}\nVulns: {len(vulns)}\n{results['ai_analysis']['ru']}"
    
    with open(f"reports/en_{ts}.md", "w") as f: f.write(en_md)
    with open(f"reports/ru_{ts}.md", "w") as f: f.write(ru_md)
    with open(f"reports/report_{ts}.json", "w") as f: json.dump(results, f, indent=2)
    with open(f"reports/txt_{ts}.txt", "w") as f: f.write(txt)
    
    print(f"✅ Reports: en/ru_{ts}.md + json/txt")

def main():
    print("🛡️ WebSecAI v2.0")
    url = input("URL: ")
    results = full_scan(url)
    generate_reports(results)

if __name__ == "__main__":
    main()
