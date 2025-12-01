import os
from openai import OpenAI

from scanners.sql_scanner import scan_sql_injection
from scanners.xss_scanner import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf

# Клиент OpenRouter (ключ должен быть в переменной окружения OPENROUTER_API_KEY)
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
)


def ai_analysis(vulnerabilities: list[str]) -> None:
    """
    AI-анализ уязвимостей через OpenRouter (LLM).
    Берёт список типов уязвимостей и даёт краткий приоритизированный вывод.
    """
    print("\n=== AI Analysis Report ===")

    if not vulnerabilities:
        print("[AI] Существенных уязвимостей не обнаружено (по текущим проверкам).")
        return

    vulns_str = ", ".join(vulnerabilities)
    prompt = (
        "You are a senior web penetration tester. "
        f"Detected vulnerabilities: {vulns_str}. "
        "Prioritize them by risk and give short remediation advice. "
        "Answer in concise English, max 5 bullet points."
    )

    try:
        resp = client.chat.completions.create(
            model="meta-llama/llama-3.1-8b-instruct:free",
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.choices[0].message.content.strip()
        print(text)
    except Exception as exc:
        print(f"[AI] Ошибка при обращении к OpenRouter: {exc}")


def main():
    print("=== WebSecAI: AI-Powered Web Application Vulnerability Scanner ===")
    target_url = input("Enter the target URL: ").strip()
    if not target_url:
        print("[!] Пустой URL, выход.")
        return

    vulnerabilities: list[str] = []

    # SQL Injection
    print("\nScanning for SQL Injection...")
    if scan_sql_injection(target_url):
        vulnerabilities.append("SQL Injection")

    # XSS
    print("\nScanning for XSS...")
    if scan_xss(target_url):
        vulnerabilities.append("XSS")

    # CSRF
    print("\nScanning for CSRF...")
    csrf_result = check_csrf_protection(target_url)
    if csrf_result:
        vulnerabilities.append("CSRF")

    # SSRF
    print("\nScanning for SSRF...")
    if scan_ssrf(target_url):
        vulnerabilities.append("SSRF")

    # AI-оценка
    print("\nRunning AI Analysis...")
    ai_analysis(vulnerabilities)

    # Краткий итог
    print("\n=== Summary ===")
    if vulnerabilities:
        print("Detected vulnerabilities:", ", ".join(vulnerabilities))
    else:
        print("No vulnerabilities detected by current checks.")

    # Генерация отчетов
    print("\nGenerating reports...")

    report_en = f"""
# WebSecAI Scan Report (EN)

## Target
- URL: {target_url}

## Summary
- Detected vulnerabilities: {", ".join(vulnerabilities) if vulnerabilities else "None"}

## Details
- SQL Injection: {"detected" if "SQL Injection" in vulnerabilities else "not detected"}
- XSS: {"detected" if "XSS" in vulnerabilities else "not detected"}
- CSRF: {"detected" if "CSRF" in vulnerabilities else "not detected"}
- SSRF: {"detected" if "SSRF" in vulnerabilities else "not detected"}

## AI Analysis
(See console output for AI Analysis Report.)
""".strip() + "\n"

    report_ru = f"""
# Отчёт WebSecAI (RU)

## Цель
- URL: {target_url}

## Сводка
- Обнаруженные уязвимости: {", ".join(vulnerabilities) if vulnerabilities else "нет"}

## Детали
- SQL Injection: {"обнаружен" if "SQL Injection" in vulnerabilities else "не обнаружен"}
- XSS: {"обнаружен" if "XSS" in vulnerabilities else "не обнаружен"}
- CSRF: {"обнаружен" if "CSRF" in vulnerabilities else "не обнаружен"}
- SSRF: {"обнаружен" if "SSRF" in vulnerabilities else "не обнаружен"}

## AI-анализ
(Подробный AI Analysis Report см. в выводе консоли.)
""".strip() + "\n"

    with open("report_en.md", "w", encoding="utf-8") as f:
        f.write(report_en)
    with open("report_ru.md", "w", encoding="utf-8") as f:
        f.write(report_ru)

    print("Reports saved as report_en.md and report_ru.md")


if __name__ == "__main__":
    main()
