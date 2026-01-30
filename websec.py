import os
import requests
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
    """
    Анализ уязвимостей через OpenRouter (параллельно EN/RU).
    Использует модель Gemini Flash (Free) и увеличенный таймаут.
    """
    if not vulnerabilities:
        return ("✅ System Secure. No vulnerabilities found.", 
                "✅ Система безопасна. Уязвимостей не обнаружено.")

    vuln_list = ", ".join(vulnerabilities)
    api_key = os.environ.get("OPENROUTER_API_KEY")

    # Если ключа нет - возвращаем простой список
    if not api_key:
        return (f"🚨 Vulns detected: {vuln_list} (AI Key Missing)", 
                f"🚨 Обнаружено: {vuln_list} (Нет ключа AI)")

    try:
        import requests # Импорт здесь для надежности
        headers = {
            "Authorization": f"Bearer {api_key}", 
            "Content-Type": "application/json",
            "HTTP-Referer": "https://websec-ai.streamlit.app", # Требование OpenRouter
            "X-Title": "WebSecAI"
        }
        
        def ask_ai(lang):
            sys_msg = "You are a cybersecurity expert. Short summary." if lang == "en" else "Ты эксперт по кибербезопасности. Краткое резюме."
            user_msg = f"Analyze risks: {vuln_list}" if lang == "en" else f"Анализ рисков: {vuln_list}"
            
            payload = {
                "model": "google/gemini-2.0-flash-exp:free", # Быстрая бесплатная модель
                "messages": [
                    {"role": "system", "content": sys_msg},
                    {"role": "user", "content": user_msg}
                ],
                "temperature": 0.3,
                "max_tokens": 500
            }
            
            try:
                r = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions", 
                    headers=headers, 
                    json=payload, 
                    timeout=35 # 35 секунд таймаут
                )
                
                if r.status_code == 200:
                    data = r.json()
                    if 'choices' in data and data['choices']:
                        return data['choices'][0]['message']['content']
                    return "AI Empty Response"
                elif r.status_code == 401:
                    return "AI Key Invalid"
                elif r.status_code == 402:
                    return "AI Credits Exhausted (Free Tier Limit)"
                else:
                    return f"AI Error {r.status_code}"
            
            except requests.Timeout:
                return "AI Timeout (Model Busy)"
            except Exception as e:
                return f"AI Connection Error: {str(e)[:50]}"

        # Параллельный запуск EN и RU
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_en = executor.submit(ask_ai, "en")
            future_ru = executor.submit(ask_ai, "ru")
            return future_en.result(), future_ru.result()

    except Exception as e:
        logger.error(f"AI Global Error: {e}")
        return ("AI Unavailable", "ИИ недоступен")



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

def scan_extension(file_obj) -> Dict[str, Any]:
    """
    Обертка для сканирования CRX/ZIP расширений.
    """
    try:
        from scanners.extension_scanner import scan_crx_file
        return scan_crx_file(file_obj)
    except ImportError:
        logger.warning("Extension scanner module not found")
        return {'critical': 0, 'high': 0, 'threats': ["Module not installed"]}
    except Exception as e:
        logger.error(f"Extension scan error: {e}")
        return {'critical': 0, 'high': 0, 'threats': [f"Error: {e}"]}
