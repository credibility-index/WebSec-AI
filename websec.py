import os
from openai import OpenAI

from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf
from scanners.network_scanner import scan_network_segmentation


# Инициализация клиента OpenRouter с обязательным HTTP-Referer для идентификации приложения
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
    default_headers={
        "HTTP-Referer": "https://github.com/credibility-index/websec-ai",  
        "X-Title": "WebSecAI Scanner"
    }
)


def ai_analysis(vulnerabilities: list[str]) -> tuple[str, str]:
    """
    Возвращает два текста:
    - ai_report_en: анализ на английском
    - ai_report_ru: тот же анализ, переведённый на русский
    """
    if not vulnerabilities:
        en = "[AI] No significant vulnerabilities detected based on current checks."
        ru = "[AI] Существенных уязвимостей не обнаружено по текущим проверкам."
        return en, ru

    vulns_str = ", ".join(vulnerabilities)
    base_prompt = (
        "You are a senior web penetration tester specialized in OWASP Top 10 vulnerabilities. "
        f"Detected vulnerabilities: {vulns_str}. "
        "Prioritize them by risk and give short remediation advice. "
        "Answer in concise English, max 5 bullet points."
    )

    try:
        resp_en = client.chat.completions.create(
            model="arcee-ai/trinity-mini:free",
            messages=[{"role": "user", "content": base_prompt}],
        )
        ai_report_en = resp_en.choices[0].message.content.strip()

        resp_ru = client.chat.completions.create(
            model="arcee-ai/trinity-mini:free",
            messages=[{
                "role": "user",
                "content": (
                    "Translate the following security analysis into Russian, "
                    "keep it concise and in bullet points:\n\n"
                    f"{ai_report_en}"
                ),
            }],
        )
        ai_report_ru = resp_ru.choices[0].message.content.strip()
        return ai_report_en, ai_report_ru

    except Exception as exc:
        msg = f"[AI] Ошибка при обращении к OpenRouter: {exc}"
        return msg, msg

def main():
    print("=== WebSecAI: AI-Powered Web Application Vulnerability Scanner ===")
    target_url = input("Enter the target URL: ").strip()
    if not target_url:
        print("[!] Пустой URL, выход.")
        return

    vulnerabilities: list[str] = []

    print("\nScanning for SQL Injection...")
    if scan_sql_injection(target_url):
        vulnerabilities.append("SQL Injection")

    print("\nScanning for XSS...")
    if scan_xss(target_url):
        vulnerabilities.append("XSS")

    print("\nScanning for CSRF...")
    # Предполагается, что функция возвращает True, если уязвимость обнаружена (то есть защита отсутствует)
    if check_csrf_protection(target_url):
        vulnerabilities.append("CSRF")

    print("\nScanning for SSRF...")
    if scan_ssrf(target_url):
        vulnerabilities.append("SSRF")

    print("\nRunning AI Analysis...")
    ai_report = ai_analysis(vulnerabilities)
    print("\n=== AI Analysis Report ===")
    print(ai_report)
    print("\nScanning Network Segmentation...")
net_issues = scan_network_segmentation(target_url)
if net_issues:
    vulnerabilities.extend([f"Network: {issue}" for issue in net_issues])
    print("[!] Network segmentation issues found:", ", ".join(net_issues))
else:
    print("[+] Network segmentation looks OK")
    
    print("\n=== Summary ===")
    if vulnerabilities:
        print("Detected vulnerabilities:", ", ".join(vulnerabilities))
    else:
        print("No vulnerabilities detected by current checks.")

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
{ai_report}
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
{ai_report}
""".strip() + "\n"

    with open("report_en.md", "w", encoding="utf-8") as f:
        f.write(report_en)
    with open("report_ru.md", "w", encoding="utf-8") as f:
        f.write(report_ru)

    print("Reports saved as report_en.md and report_ru.md")


if __name__ == "__main__":
    main()

