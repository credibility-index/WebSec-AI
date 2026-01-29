import os
import json
import time
import logging
import concurrent.futures
import requests
from typing import List, Tuple, Optional, Dict
from datetime import datetime

# Настройка логов
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("websec_ai")

# Fallback сканеры
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

# Конфигурация LLM
AI_CONFIG = {
    "model": "deepseek/deepseek-chat-v3.1:free",  # или qwen/qwen-3:free, mistralai/mistral-7b-instruct:free
    "max_tokens": 200,
    "temperature": 0.3,
    "max_retries": 2,
    "timeout": 30,
}

def ai_analysis(vulnerabilities: List[str]) -> Tuple[str, str]:
    if not vulnerabilities:
        return ("✅ Clean scan", "✅ Чистая проверка")

    vuln_list = ", ".join(vulnerabilities)
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        logger.warning("OPENROUTER_API_KEY not set, using fallback")
        return (
            f"🚨 Risks: {vuln_list}. Fix immediately!",
            f"🚨 Риски: {vuln_list}. Срочно исправьте!"
        )

    for attempt in range(AI_CONFIG["max_retries"] + 1):
        try:
            from openrouter import OpenRouter
            client = OpenRouter(api_key=api_key)

            # EN: анализ
            response = client.chat.send(
                model=AI_CONFIG["model"],
                messages=[
                    {"role": "system", "content": "You are a security engineer. Analyze web vulnerabilities and return one short paragraph with impact level and concrete remediation advice."},
                    {"role": "user", "content": f"Analyze detected vulnerabilities: {vuln_list}. Output only: 1–2 sentences starting with '🚨 Risks detected'."}
                ],
                max_tokens=AI_CONFIG["max_tokens"],
                temperature=AI_CONFIG["temperature"],
                timeout=AI_CONFIG["timeout"]
            )
            en_text = (response.choices[0].message.content or "").strip()
            if not en_text:
                en_text = f"🚨 Risks: {vuln_list}. Fix immediately!"

            # RU: анализ
            response = client.chat.send(
                model=AI_CONFIG["model"],
                messages=[
                    {"role": "system", "content": "Вы — эксперт в ИБ. Проанализируйте веб‑уязвимости и дайте краткую оценку риска и рекомендации по исправлению."},
                    {"role": "user", "content": f"Уязвимости: {vuln_list}. Сформулируйте 1–2 предложения, начинающихся с «🚨 Риски найдены»."}
                ],
                max_tokens=AI_CONFIG["max_tokens"],
                temperature=AI_CONFIG["temperature"],
                timeout=AI_CONFIG["timeout"]
            )
            ru_text = (response.choices[0].message.content or "").strip()
            if not ru_text:
                ru_text = f"🚨 Риски: {vuln_list}. Срочно исправьте!"

            return (en_text, ru_text)

        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} failed: {e}")
            if attempt < AI_CONFIG["max_retries"]:
                time.sleep(2 ** attempt)
            else:
                logger.error("All OpenRouter attempts failed, using fallback")
                return (
                    f"⚠️ Could not contact AI; detected: {vuln_list}. Check manually.",
                    f"⚠️ Не удалось подключиться к ИИ; обнаружены: {vuln_list}. Проверьте вручную."
                )

    # Fallback на всякий случай
    return (
        f"⚠️ LLM error: {vuln_list}. Check manually.",
        f"⚠️ Ошибка ИИ: {vuln_list}. Проверьте вручную."
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(func, *args): name for name, func, args in scanners}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                detected = future.result(timeout=timeout)
                if detected:
                    results["vulnerabilities"].append(name)
                print(f"  {name}: {'🟡 HIT' if detected else '🟢 OK'}")
            except Exception as e:
                print(f"  {name}: ⏱️ Timeout (or error: {e})")

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

    en_md = f"""# WebSecAI Report
Target: {results["target"]}
Vulns: {len(vulns)} | Score: {metrics["score"]}/100

AI: {results["ai_analysis"]["en"]}"""

    ru_md = f"""# Отчёт WebSecAI
Цель: {results["target"]}
Уязвимостей: {len(vulns)} | Оценка: {metrics["score"]}/100

AI: {results["ai_analysis"]["ru"]}"""

    txt = f"WebSecAI {ts}\nTarget: {results['target']}\nVulns: {len(vulns)}\n{results['ai_analysis']['ru']}"

    with open(f"reports/en_{ts}.md", "w", encoding="utf-8") as f:
        f.write(en_md)
    with open(f"reports/ru_{ts}.md", "w", encoding="utf-8") as f:
        f.write(ru_md)
    with open(f"reports/report_{ts}.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    with open(f"reports/txt_{ts}.txt", "w", encoding="utf-8") as f:
        f.write(txt)

    print(f"✅ Reports: en/ru_{ts}.md + json/txt")

def main():
    print("🛡️ WebSecAI v2.0")
    url = input("URL: ")
    results = full_scan(url)
    generate_reports(results)

if __name__ == "__main__":
    main()
