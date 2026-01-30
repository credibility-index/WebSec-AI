import os
import json
import time
import logging
import requests
import concurrent.futures
from typing import List, Tuple, Dict, Any
from datetime import datetime

# Настройка логов
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("websec_ai")

# ─── ФУНКЦИИ СКАНЕРОВ ───
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

# ─── AI АНАЛИЗ (Исправлено, без reasoning) ───
def ai_analysis(vulnerabilities: List[str]) -> Tuple[str, str]:
    """
    Анализ уязвимостей через OpenRouter с резервным каналом.
    Основная: Upstage Solar Pro 3 (Free)
    Резерв: Meta Llama 3 8B (Free)
    """
    if not vulnerabilities:
        return ("✅ System Secure. No vulnerabilities found.", 
                "✅ Система безопасна. Уязвимостей не обнаружено.")

    vuln_list = ", ".join(vulnerabilities)
    api_key = os.environ.get("OPENROUTER_API_KEY")

    if not api_key:
        return (f"🚨 Vulns detected: {vuln_list} (AI Key Missing)", 
                f"🚨 Обнаружено: {vuln_list} (Нет ключа AI)")

    try:
        headers = {
            "Authorization": f"Bearer {api_key}", 
            "Content-Type": "application/json",
            "HTTP-Referer": "https://websec-ai.streamlit.app",
            "X-Title": "WebSecAI"
        }
        
        def ask_ai(lang):
            sys_msg = "You are a cybersecurity expert. Short professional summary." if lang == "en" else "Ты эксперт по кибербезопасности. Краткое профессиональное резюме."
            user_msg = f"Analyze risks for: {vuln_list}" if lang == "en" else f"Анализ рисков для: {vuln_list}"
            
            # Список моделей для перебора (основная -> резервная)
            models = ["upstage/solar-pro-3:free", "meta-llama/llama-3-8b-instruct:free"]
            
            for model in models:
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": sys_msg},
                        {"role": "user", "content": user_msg}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 800
                }
                
                try:
                    r = requests.post(
                        "https://openrouter.ai/api/v1/chat/completions", 
                        headers=headers, 
                        json=payload, 
                        timeout=35 
                    )
                    
                    if r.status_code == 200:
                        data = r.json()
                        if 'choices' in data and data['choices']:
                            return data['choices'][0]['message']['content']
                    
                    # Если ошибка 404/500 - пробуем следующую модель
                    logger.warning(f"AI Model {model} failed: {r.status_code}")
                    continue 

                except requests.Timeout:
                    logger.warning(f"AI Model {model} timed out")
                    continue
                except Exception as e:
                    logger.error(f"AI Error: {e}")
                    continue
            
            return "AI Unavailable (All models failed)"

        # Параллельный запуск
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_en = executor.submit(ask_ai, "en")
            future_ru = executor.submit(ask_ai, "ru")
            return future_en.result(), future_ru.result()

    except Exception as e:
        logger.error(f"AI Global Error: {e}")
        return ("AI Unavailable", "ИИ недоступен")


# ─── ОТЧЕТЫ ───
def generate_report_content(results, lang="en"):
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
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_sql = executor.submit(scan_sql_injection, url)
        f_xss = executor.submit(scan_xss, url)
        f_csrf = executor.submit(check_csrf_protection, url)
        f_ssrf = executor.submit(scan_ssrf, url)
        f_net = executor.submit(scan_network_segmentation, url)
        
        if f_sql.result(): vulns.append("SQL Injection")
        if f_xss.result(): vulns.append("XSS")
        if f_csrf.result(): vulns.append("CSRF Missing")
        if f_ssrf.result(): vulns.append("SSRF")
        
        net_res = f_net.result()
        if net_res: vulns.extend(net_res)

    scan_time = round(time.time() - t0, 2)
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
    try:
        from scanners.extension_scanner import scan_crx_file
        return scan_crx_file(file_obj)
    except ImportError:
        logger.warning("Extension scanner module not found")
        return {'critical': 0, 'high': 0, 'threats': ["Module not installed"]}
    except Exception as e:
        logger.error(f"Extension scan error: {e}")
        return {'critical': 0, 'high': 0, 'threats': [f"Error: {e}"]}

if __name__ == "__main__":
    print("WebSecAI Core Module Loaded")
