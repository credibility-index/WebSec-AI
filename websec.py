import os
import json
import time
import logging
from typing import List, Tuple, Dict, Any
from datetime import datetime

# Настройка логов
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("websec_ai")

# ─── ФУНКЦИИ СКАНЕРОВ (Импорты внутри для безопасности) ───

def scan_sql_injection(url: str) -> bool:
    try:
        from scanners.sql_scanner import scan_sql_injection as _scan
        return _scan(url)
    except ImportError:
        logger.warning("SQL scanner module not found")
        return False
    except Exception as e:
        logger.error(f"SQL scan error: {e}")
        return False

def scan_xss(url: str) -> bool:
    try:
        from scanners.xss import scan_xss as _scan
        return _scan(url)
    except ImportError:
        logger.warning("XSS scanner module not found")
        return False
    except Exception as e:
        logger.error(f"XSS scan error: {e}")
        return False

def check_csrf_protection(url: str) -> bool:
    try:
        from scanners.csrf_scanner import check_csrf_protection as _scan
        return _scan(url)
    except ImportError:
        logger.warning("CSRF scanner module not found")
        return False
    except Exception as e:
        logger.error(f"CSRF scan error: {e}")
        return False

def scan_ssrf(url: str) -> bool:
    try:
        from scanners.ssrf_scanner import scan_ssrf as _scan
        return _scan(url)
    except ImportError:
        logger.warning("SSRF scanner module not found")
        return False
    except Exception as e:
        logger.error(f"SSRF scan error: {e}")
        return False

def scan_network_segmentation(url: str) -> List[str]:
    try:
        from scanners.network_scanner import scan_network_segmentation as _scan
        return _scan(url)
    except ImportError:
        logger.warning("Network scanner module not found")
        return []
    except Exception as e:
        logger.error(f"Network scan error: {e}")
        return []

# ─── AI АНАЛИЗ (OpenRouter) ───

def ai_analysis(vulnerabilities: List[str]) -> Tuple[str, str]:
    if not vulnerabilities:
        return (
            "✅ System appears secure based on automated scans. No critical vulnerabilities detected.",
            "✅ Система выглядит безопасной по результатам автоматического сканирования. Критических уязвимостей не найдено."
        )

    vuln_list = ", ".join(vulnerabilities)
    api_key = os.environ.get("OPENROUTER_API_KEY")

    if not api_key:
        return (
            f"🚨 Detected Vulnerabilities: {vuln_list}. Please verify manually and patch immediately.",
            f"🚨 Обнаружены уязвимости: {vuln_list}. Пожалуйста, проверьте вручную и немедленно исправьте."
        )

    try:
        import requests
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://websec-ai.streamlit.app",
            "X-Title": "WebSecAI"
        }
        
        # Запрос для EN
        payload_en = {
            "model": "deepseek/deepseek-chat-v3.1:free",
            "messages": [
                {"role": "system", "content": "You are a senior security engineer. Provide a concise technical summary of risks and remediation steps."},
                {"role": "user", "content": f"Analyze these web vulnerabilities: {vuln_list}. Return 3-4 sentences."}
            ]
        }
        resp_en = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload_en, timeout=10)
        en_text = resp_en.json()['choices'][0]['message']['content'] if resp_en.status_code == 200 else f"API Error: {resp_en.status_code}"

        # Запрос для RU
        payload_ru = {
            "model": "deepseek/deepseek-chat-v3.1:free",
            "messages": [
                {"role": "system", "content": "Ты эксперт по кибербезопасности. Дай краткое техническое резюме рисков и шагов по исправлению."},
                {"role": "user", "content": f"Проанализируй эти веб-уязвимости: {vuln_list}. Максимум 3-4 предложения на русском."}
            ]
        }
        resp_ru = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload_ru, timeout=10)
        ru_text = resp_ru.json()['choices'][0]['message']['content'] if resp_ru.status_code == 200 else f"API Error: {resp_ru.status_code}"

        return en_text, ru_text

    except Exception as e:
        logger.error(f"AI Analysis error: {e}")
        return (f"⚠️ AI Error: {vuln_list}", f"⚠️ Ошибка ИИ: {vuln_list}")


# ─── ГЕНЕРАЦИЯ ОТЧЕТОВ ───

def generate_report_content(results: Dict[str, Any], lang: str = "en") -> str:
    """Генерирует Markdown контент для отчета"""
    
    timestamp = results["timestamp"]
    target = results["target"]
    score = results["metrics"]["score"]
    vulns = results["vulnerabilities"]
    ai_text = results["ai_analysis"][lang]
    
    if lang == "ru":
        title = "🛡️ WebSecAI: Отчет о Безопасности"
        scan_summary = "Сводка Сканирования"
        target_lbl = "Цель"
        date_lbl = "Дата"
        score_lbl = "Оценка Безопасности"
        vuln_found_lbl = "Обнаруженные Уязвимости"
        no_vuln_lbl = "✅ Критических уязвимостей не найдено."
        ai_lbl = "🧠 Анализ ИИ (Рекомендации)"
        footer = "Сгенерировано WebSecAI Suite 2026"
        status_risk = "КРИТИЧЕСКИЙ РИСК" if score < 50 else "ТРЕБУЕТ ВНИМАНИЯ" if score < 80 else "БЕЗОПАСНО"
    else:
        title = "🛡️ WebSecAI: Security Audit Report"
        scan_summary = "Scan Summary"
        target_lbl = "Target"
        date_lbl = "Date"
        score_lbl = "Security Score"
        vuln_found_lbl = "Detected Vulnerabilities"
        no_vuln_lbl = "✅ No critical vulnerabilities detected."
        ai_lbl = "🧠 AI Analysis & Remediation"
        footer = "Generated by WebSecAI Suite 2026"
        status_risk = "CRITICAL RISK" if score < 50 else "NEEDS ATTENTION" if score < 80 else "SECURE"

    # Формируем Markdown
    md = f"""# {title}

## {scan_summary}
- **{target_lbl}:** `{target}`
- **{date_lbl}:** {timestamp}
- **{score_lbl}:** {score}/100 ({status_risk})

---

## {vuln_found_lbl}
"""
    
    if vulns:
        for v in vulns:
            md += f"- 🔴 **{v}**\n"
    else:
        md += f"{no_vuln_lbl}\n"

    md += f"""
---

## {ai_lbl}
{ai_text}

---
*{footer}*
"""
    return md


# ─── ФУНКЦИЯ ПОЛНОГО СКАНА ───

def full_scan(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    t0 = time.time()
    vulns = []
    
    if scan_sql_injection(url): vulns.append("SQL Injection")
    if scan_xss(url): vulns.append("XSS")
    if check_csrf_protection(url): vulns.append("CSRF Missing")
    if scan_ssrf(url): vulns.append("SSRF")
    
    net_issues = scan_network_segmentation(url)
    if net_issues: vulns.extend(net_issues)

    scan_time = round(time.time() - t0, 2)
    ai_en, ai_ru = ai_analysis(vulns)

    results = {
        "target": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": vulns,
        "metrics": {
            "scan_time": scan_time,
            "vuln_count": len(vulns),
            "score": max(0, 100 - len(vulns) * 20)
        },
        "ai_analysis": {
            "en": ai_en,
            "ru": ai_ru
        }
    }
    
    # Генерируем тексты отчетов сразу, чтобы app.py их просто взял
    results["reports"] = {
        "en_md": generate_report_content(results, "en"),
        "ru_md": generate_report_content(results, "ru")
    }
    
    return results

if __name__ == "__main__":
    print("Testing WebSec Report Gen...")
    r = full_scan("http://testphp.vulnweb.com")
    print(r["reports"]["en_md"])
