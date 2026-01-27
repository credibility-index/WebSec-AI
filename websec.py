import os
import json
from typing import List, Tuple, Optional
from datetime import datetime
from openai import OpenAI

# Импорты сканеров с graceful fallback
from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf
from scanners.network_scanner import scan_network_segmentation

# ── OpenRouter Client (совместимо с app.py) ───────────────────────────────────
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
    
    Args:
        vulnerabilities: List of detected issues ["SQLi", "CSRF", ...]
    
    Returns:
        Tuple (english_report, russian_report)
    """
    if not vulnerabilities:
        safe_en = "✅ No critical vulnerabilities detected. Consider advanced scanning."
        safe_ru = "✅ Критических уязвимостей не найдено. Рекомендуем глубокий аудит."
        return safe_en, safe_ru

    # Fallback без API
    if not client:
        fallback_en = "[AI] OpenRouter API key missing. Enable for smart prioritization."
        fallback_ru = "[AI] Ключ OpenRouter отсутствует. Включите для AI-приоритизации."
        return fallback_en, fallback_ru

    vulns_str = ", ".join(vulnerabilities)
    
    # 🆕 Улучшенный промпт для точности
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
            model="arcee-ai/trinity-mini:free",  # Free tier
            messages=[{"role": "user", "content": base_prompt}],
            temperature=0.1,  # Consistent output
        )
        ai_en = resp_en.choices[0].message.content.strip()

        # Russian translation (separate call for accuracy)
        ru_prompt = f"""
Переведи профессиональный security-отчёт на русский язык.
Сохрани термины: OWASP, SQLi, XSS, CSRF, SSRF, CVSS.
Формат: Markdown bullets.

ОРИГИНАЛ:
{ai_en}
"""
        resp_ru = client.chat.completions.create(
            model="arcee-ai/trinity-mini:free",
            messages=[{"role": "user", "content": ru_prompt}],
            temperature=0.1,
        )
        ai_ru = resp_ru.choices[0].message.content.strip()
        
        return ai_en, ai_ru

    except Exception as e:
        error_en = f"[AI ERROR] OpenRouter failed: {str(e)[:100]}"
        error_ru = f"[AI ОШИБКА] OpenRouter недоступен: {str(e)[:100]}"
        return error_en, error_ru

def full_scan(url: str) -> dict:
    """
    CLI + API версия полного сканирования.
    
    Returns:
        Dict с результатами + AI-отчётами для JSON/MD экспорта
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
    
    # Sequential scans (параллельность в будущем)
    scans = [
        ("SQL Injection", scan_sql_injection(url)),
        ("XSS", scan_xss(url)),
        ("CSRF", check_csrf_protection(url)),
        ("SSRF", scan_ssrf(url)),
    ]
    
    for name, detected in scans:
        print(f"  {name}: {'🟡 DETECTED' if detected else '🟢 CLEAN'}")
        if detected:
            results["vulnerabilities"].append(name)
    
    # Network scan
    net_issues = scan_network_segmentation(url)
    if net_issues:
        results["vulnerabilities"].extend([f"Network: {issue}" for issue in net_issues])
        print(f"  Network: {'🟡 '.join(net_issues)}")
    else:
        print("  Network: 🟢 OK")
    
    # Metrics
    results["metrics"] = {
        "scan_time": round(time.time() - t0, 2),
        "vuln_count": len(results["vulnerabilities"]),
        "security_score": max(0, 100 - len(results["vulnerabilities"]) * 20)
    }
    
    # AI Analysis
    print("🤖 AI Analysis...")
    results["ai_analysis"]["en"], results["ai_analysis"]["ru"] = ai_analysis(
        results["vulnerabilities"]
    )
    
    return results

def generate_reports(results: dict) -> None:
    """Генерирует MD + JSON отчёты (совместимо с app.py)"""
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    vulns = results["vulnerabilities"]
    
    # Markdown EN
    report_en = f"""# WebSecAI Professional Report 🔒

## 📍 Target
**URL:** {results["target"]}

## 📊 Executive Summary
- **Vulnerabilities:** {len(vulns)}
- **Security Score:** {results["metrics"]["security_score"]}/100
- **Scan Time:** {results["metrics"]["scan_time"]}s

## 🚨 Findings
{chr(10).join(f'- **{v}**' for v in vulns) or '✅ No issues detected'}

## 🤖 AI Analysis (EN)
{results["ai_analysis"]["en"]}

---
*Generated by WebSecAI v2.0 | {results["timestamp"]}*
"""
    
    # Markdown RU  
    report_ru = f"""# Отчёт WebSecAI 🔒

## 📍 Цель
**URL:** {results["target"]}

## 📊 Краткая сводка
- **Уязвимостей:** {len(vulns)}
- **Оценка безопасности:** {results["metrics"]["security_score"]}/100
- **Время сканирования:** {results["metrics"]["scan_time"]}с

## 🚨 Результаты
{chr(10).join(f'- **{v}**' for v in vulns) or '✅ Проблем не выявлено'}

## 🤖 AI-анализ (RU)
{results["ai_analysis"]["ru"]}

---
*WebSecAI v2.0 | {results["timestamp"]}*
"""
    
    # Save files
    with open(f"websec_report_en_{ts}.md", "w", encoding="utf-8") as f:
        f.write(report_en)
    with open(f"websec_report_ru_{ts}.md", "w", encoding="utf-8") as f:
        f.write(report_ru)
    
    # JSON export
    with open(f"websec_full_{ts}.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"✅ Reports saved:")
    print(f"   📄 websec_report_en_{ts}.md")
    print(f"   📄 websec_report_ru_{ts}.md") 
    print(f"   📊 websec_full_{ts}.json")

def main():
    """CLI entrypoint"""
    print("=== 🛡️ WebSecAI Suite v2.0 ===")
    print("GitHub: credibility-index/WebSec-AI")
    print("-" * 50)
    
    target = input("🎯 Enter target URL: ").strip()
    if not target.startswith(('http://', 'https://')):
        print("❌ URL must start with http:// or https://")
        return
    
    try:
        results = full_scan(target)
        print("\n" + "="*50)
        print("📊 SUMMARY")
        print(f"Target: {results['target']}")
        print(f"Vulns: {len(results['vulnerabilities'])}")
        print(f"Score: {results['metrics']['security_score']}/100")
        
        generate_reports(results)
        
    except KeyboardInterrupt:
        print("\n👋 Scan interrupted")
    except Exception as e:
        print(f"💥 Error: {e}")
def scan_crypto_wallet(address: str) -> bool:
    """Простая проверка крипто-кошелька (заглушка)"""
    # TODO: Etherscan API + blacklist
    if not address.startswith(('0x', 'bc1', '1', '3')):
        return True  # Invalid format = risk
    return False  # Demo clean

if __name__ == "__main__":
    main()
