import os
import json
import time
from typing import List, Tuple, Optional, Dict
from datetime import datetime
from openai import OpenAI

# Импорты сканеров с graceful fallback
try:
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
    from scanners.network_scanner import scan_network_segmentation
except ImportError as e:
    print(f"⚠️ Ошибка импорта сканеров: {e}")

# ── OpenRouter Client ────────────────────────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

client: Optional[OpenAI] = None
if OPENROUTER_API_KEY:
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=OPENROUTER_API_KEY,
        default_headers={
            "HTTP-Referer": "https://github.com/credibility-index/WebSec-AI",
            "X-Title": "WebSecAI Suite v2.0",
        },
    )

def ai_analysis(vulnerabilities: List[str]) -> Tuple[str, str]:
    """
    Генерирует bilingual AI-отчёты для Streamlit/CLI.
    """
    if not vulnerabilities:
        safe_en = "✅ No critical vulnerabilities detected. Consider advanced scanning."
        safe_ru = "✅ Критических уязвимостей не найдено. Рекомендуем глубокий аудит."
        return safe_en, safe_ru

    if not client:
        fallback_en = "[AI] OpenRouter API key missing. Enable for smart prioritization."
        fallback_ru = "[AI] Ключ OpenRouter отсутствует. Включите для AI-приоритизации."
        return fallback_en, fallback_ru

    vulns_str = ", ".join(vulnerabilities)
    
    base_prompt = f"""
You are an OWASP Top 10 expert penetration tester.

**Detected:** {vulns_str}

Provide:
1. Risk ranking (CRITICAL/HIGH/MEDIUM)
2. 3-step immediate fix
3. CVSS v4.0 score estimate

Format: Markdown bullets. Max 120 words.
"""

    try:
        # English analysis
        resp_en = client.chat.completions.create(
            model="gpt-3.5-turbo",  # Используем стабильную модель
            messages=[{"role": "user", "content": base_prompt}],
            temperature=0.1,
        )
        ai_en = resp_en.choices[0].message.content.strip()

        # Russian translation
        ru_prompt = f"""
Переведи профессиональный security-отчёт на русский язык.
Сохрани термины: OWASP, SQLi, XSS, CSRF, SSRF, CVSS.
Формат: Markdown bullets.

ОРИГИНАЛ:
{ai_en}
"""
        resp_ru = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": ru_prompt}],
            temperature=0.1,
        )
        ai_ru = resp_ru.choices[0].message.content.strip()
        
        return ai_en, ai_ru

    except Exception as e:
        error_en = f"[AI ERROR] OpenRouter failed: {str(e)[:100]}"
        error_ru = f"[AI ОШИБКА] OpenRouter недоступен: {str(e)[:100]}"
        return error_en, error_ru

def full_scan(url: str) -> Dict:
    """
    Выполняет полное сканирование целевого URL.
    """
    print(f"🔍 Scanning {url}...")
    results = {
        "timestamp": datetime.now().isoformat(),
        "target": url,
        "vulnerabilities": [],
        "metrics": {},
        "ai_analysis": {"en": "", "ru": ""}
    }
    
    t0 = time.time()
    try:
        # Последовательное сканирование
        scans = [
            ("SQL Injection", scan_sql_injection(url)),
            ("XSS", scan_xss(url)),
            ("CSRF", check_csrf_protection(url)),
            ("SSRF", scan_ssrf(url))
        ]
        
        for name, detected in scans:
            status = '🟡 DETECTED' if detected else '🟢 CLEAN'
            print(f"  {name}: {status}")
            if detected:
                results["vulnerabilities"].append(name)
        
        # Сетевой сканер
        net_issues = scan_network_segmentation(url)
        if net_issues:
            results["vulnerabilities"].extend([f"Network: {issue}" for issue in net_issues])
            print(f"  Network: {' | '.join([f'🟡 {issue}' for issue in net_issues])}")
        else:
            print("  Network: 🟢 OK")
        
# Метрики сканирования
        results["metrics"] = {
            "scan_time": round(time.time() - t0, 2),
            "vuln_count": len(results["vulnerabilities"]),
            "security_score": max(0, 100 - len(results["vulnerabilities"]) * 20)
        }
        
        # AI-анализ
        print("🤖 AI Analysis...")
        results["ai_analysis"]["en"], results["ai_analysis"]["ru"] = ai_analysis(
            results["vulnerabilities"]
        )
        
    except Exception as e:
        print(f"💥 Ошибка при сканировании: {str(e)}")
        results["error"] = str(e)
    
    return results

def generate_reports(results: Dict) -> None:
    """
    Генерирует отчёты в форматах MD и JSON
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    vulns = results["vulnerabilities"]
    
    # Markdown отчёт на английском
    report_en = f"""# WebSecAI Professional Report 🔒

## 🎯 Target Information
**URL:** {results["target"]}
**Timestamp:** {results["timestamp"]}

## 📊 Executive Summary
- **Vulnerabilities Found:** {len(vulns)}
- **Security Score:** {results["metrics"]["security_score"]}/100
- **Scan Duration:** {results["metrics"]["scan_time"]} seconds

## 🚨 Findings
{"\n".join([f"- **{v}**" for v in vulns]) or "✅ No vulnerabilities detected"}

## 🤖 AI Analysis
{results["ai_analysis"]["en"]}

---
Generated by WebSecAI v2.0
"""
    
    # Markdown отчёт на русском
    report_ru = f"""# Отчёт WebSecAI 🔒

## 🎯 Информация о цели
**URL:** {results["target"]}
**Время сканирования:** {results["timestamp"]}

## 📊 Сводная информация
- **Найденных уязвимостей:** {len(vulns)}
- **Оценка безопасности:** {results["metrics"]["security_score"]}/100
- **Длительность сканирования:** {results["metrics"]["scan_time"]} секунд

## 🚨 Результаты
{"\n".join([f"- **{v}**" for v in vulns]) or "✅ Уязвимости не обнаружены"}

## 🤖 AI-анализ
{results["ai_analysis"]["ru"]}

---
Сгенерировано WebSecAI v2.0
"""
    
    # Создаём директорию для отчётов, если её нет
    os.makedirs("reports", exist_ok=True)
    
    try:
        # Сохраняем отчёты
        with open(f"reports/websec_report_en_{ts}.md", "w", encoding="utf-8") as f:
            f.write(report_en)
            
        with open(f"reports/websec_report_ru_{ts}.md", "w", encoding="utf-8") as f:
            f.write(report_ru)
            
        # JSON экспорт
        with open(f"reports/websec_full_{ts}.json", "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
            
        print(f"✅ Отчёты успешно сохранены:")
        print(f"   📄 reports/websec_report_en_{ts}.md")
        print(f"   📄 reports/websec_report_ru_{ts}.md")
        print(f"   📊 reports/websec_full_{ts}.json")
        
    except Exception as e:
        print(f"⚠️ Ошибка при сохранении отчётов: {str(e)}")

def main():
    """
    Основная точка входа для CLI
    """
    print("\n=== 🛡️ WebSecAI Suite v2.0 ===")
    print("GitHub: credibility-index/WebSec-AI")
    print("-" * 50)
    
    try:
        target = input("🎯 Введите URL для сканирования: ").strip()
        
        if not target.startswith(('http://', 'https://')):
            print("❌ URL должен начинаться с http:// или https://")
            return
            
        results = full_scan(target)
        print("\n" + "="*50)
        print("📊 ИТОГИ СКАНИРОВАНИЯ")
        print(f"Цель: {results['target']}")
        print(f"Уязвимостей: {len(results['vulnerabilities'])}")
        print(f"Оценка безопасности: {results['metrics']['security_score']}/100")
        
        generate_reports(results)
        
    except KeyboardInterrupt:
        print("\n👋 Сканирование прервано пользователем")
        except Exception as e:
        print(f"💥 Произошла ошибка: {str(e)}")
        
def scan_crypto_wallet(address: str) -> bool:
    """
    Проверка криптокошелька на риски (демо-функция)
    """
    # Список подозрительных паттернов
    invalid_patterns = [
        '0x0*',        # Burn address (Ethereum)
        'bc1q0*',      # Burn address (Bitcoin)
        '0x111*',      # Подозрительный паттерн
        'bc1q111*'
    ]
    
    return any(pattern in address for pattern in invalid_patterns)

if __name__ == "__main__":
    try:
        # Проверка наличия необходимых директорий
        os.makedirs("scanners", exist_ok=True)
        os.makedirs("reports", exist_ok=True)
        
        # Запуск основного функционала
        main()
        
    except FileNotFoundError as fnf:
        print(f"⚠️ Ошибка: Не найдены необходимые файлы - {str(fnf)}")
        print("Убедитесь, что все сканеры находятся в директории scanners/")
        
    except Exception as e:
        print(f"💥 Критическая ошибка: {str(e)}")
        print("Для получения помощи обратитесь к документации или создайте issue на GitHub")
