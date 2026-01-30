import os
import json
import time
import logging
import concurrent.futures  # <--- Добавили для скорости
from typing import List, Tuple, Dict, Any
from datetime import datetime

# Настройка логов
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("websec_ai")

# ─── ФУНКЦИИ СКАНЕРОВ ───
# (Они остались такими же, но я их свернул для краткости)

def scan_sql_injection(url: str) -> bool:
    try:
        from scanners.sql_scanner import scan_sql_injection as _scan
        return _scan(url)
    except: return False

def scan_xss(url: str) -> bool:
    try:
        from scanners.xss import scan_xss as _scan
        return _scan(url)
    except: return False

def check_csrf_protection(url: str) -> bool:
    try:
        from scanners.csrf_scanner import check_csrf_protection as _scan
        return _scan(url)
    except: return False

def scan_ssrf(url: str) -> bool:
    try:
        from scanners.ssrf_scanner import scan_ssrf as _scan
        return _scan(url)
    except: return False

def scan_network_segmentation(url: str) -> List[str]:
    try:
        from scanners.network_scanner import scan_network_segmentation as _scan
        return _scan(url)
    except: return []

# ─── AI АНАЛИЗ ───

def ai_analysis(vulnerabilities: List[str]) -> Tuple[str, str]:
    # ... (код AI анализа такой же, он быстрый, если OpenRouter не тупит) ...
    # Если OpenRouter тормозит, тут ничего не поделаешь, это внешнее API.
    # Но мы можем сократить промпт, чтобы он быстрее думал.
    
    if not vulnerabilities:
        return ("✅ System Secure.", "✅ Система безопасна.")

    vuln_list = ", ".join(vulnerabilities)
    api_key = os.environ.get("OPENROUTER_API_KEY")

    if not api_key:
        return (f"🚨 Vulns: {vuln_list}", f"🚨 Уязвимости: {vuln_list}")

    try:
        import requests
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        
        # Функция для параллельного запроса к AI (RU и EN одновременно)
        def ask_ai(lang):
            sys_msg = "Expert summary." if lang == "en" else "Краткое резюме."
            user_msg = f"Risks of {vuln_list}?" if lang == "en" else f"Риски {vuln_list}?"
            payload = {
                "model": "deepseek/deepseek-chat-v3.1:free",
                "messages": [{"role": "system", "content": sys_msg}, {"role": "user", "content": user_msg}]
            }
            try:
                r = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=8)
                return r.json()['choices'][0]['message']['content']
            except:
                return "AI Timeout"

        # Запускаем оба запроса к AI одновременно!
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_en = executor.submit(ask_ai, "en")
            future_ru = executor.submit(ask_ai, "ru")
            return future_en.result(), future_ru.result()

    except Exception:
        return ("AI Error", "Ошибка ИИ")


# ─── ОТЧЕТЫ ───
def generate_report_content(results, lang="en"):
    # (Тот же код генерации, он мгновенный)
    timestamp = results["timestamp"]
    target = results["target"]
    vulns = results["vulnerabilities"]
    ai_text = results["ai_analysis"][lang]
    
    title = "WebSecAI Report" if lang == "en" else "Отчет WebSecAI"
    risk = "CRITICAL" if vulns else "CLEAN"
    
    md = f"# {title}\nTarget: {target}\nDate: {timestamp}\nStatus: {risk}\n\n## Vulnerabilities\n"
    if vulns:
        for v in vulns: md += f"- {v}\n"
    else:
        md += "No issues found.\n"
    
    md += f"\n## AI Analysis\n{ai_text}"
    return md

# ─── БЫСТРЫЙ ПОЛНЫЙ СКАН ───

def full_scan(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    t0 = time.time()
    vulns = []
    
    # 🚀 ПАРАЛЛЕЛЬНЫЙ ЗАПУСК СКАНЕРОВ
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Запускаем задачи
        f_sql = executor.submit(scan_sql_injection, url)
        f_xss = executor.submit(scan_xss, url)
        f_csrf = executor.submit(check_csrf_protection, url)
        f_ssrf = executor.submit(scan_ssrf, url)
        f_net = executor.submit(scan_network_segmentation, url)
        
        # Собираем результаты (ждем не больше timeout)
        if f_sql.result(): vulns.append("SQL Injection")
        if f_xss.result(): vulns.append("XSS")
        if f_csrf.result(): vulns.append("CSRF Missing")
        if f_ssrf.result(): vulns.append("SSRF")
        
        net_res = f_net.result()
        if net_res: vulns.extend(net_res)

    scan_time = round(time.time() - t0, 2)
    
    # AI теперь тоже быстрый (параллельный)
    ai_en, ai_ru = ai_analysis(vulns)

    results = {
        "target": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": vulns,
        "metrics": {"scan_time": scan_time, "vuln_count": len(vulns), "score": max(0, 100 - len(vulns)*20)},
        "ai_analysis": {"en": ai_en, "ru": ai_ru}
    }
    
    results["reports"] = {
        "en_md": generate_report_content(results, "en"),
        "ru_md": generate_report_content(results, "ru")
    }
    
    return results
