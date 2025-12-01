from sql_scanner import scan_sql_injection
from xss_scanner import scan_xss
from csrf_scanner import check_csrf_protection
from ssrf_scanner import scan_ssrf


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


if __name__ == "__main__":
    main()
