from scanners.sql_scanner import scan_sql_injection
from scanners.xss_scanner import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf


def ai_analysis(vulnerabilities: list[str]) -> None:
    """
    Простая AI-имитация: расставляем приоритеты по типу уязвимости.
    Позже сюда можно подключить LLM.
    """
    print("\n=== AI Analysis Report ===")
    if not vulnerabilities:
        print("[AI] Существенных уязвимостей не обнаружено (по текущим проверкам).")
        return

    for vuln in vulnerabilities:
        if vuln == "SQL Injection":
            print("[AI] SQL Injection: CRITICAL. Возможен доступ к БД, требуется немедленное исправление.")
        elif vuln == "XSS":
            print("[AI] XSS: HIGH. Риск кражи сессий и атак на пользователей.")
        elif vuln == "CSRF":
            print("[AI] CSRF: MEDIUM. Проверьте критичные формы (аутентификация, переводы, изменение данных).")
        elif vuln == "SSRF":
            print("[AI] SSRF: HIGH. Возможен доступ к внутренним сервисам и метаданным облака.")
        else:
            print(f"[AI] {vuln}: обнаружено, требуется дополнительный анализ.")


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
