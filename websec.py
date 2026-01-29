import os
from typing import Tuple, Dict, Any
from openrouter import OpenRouter
from openrouter.sdk.models import Message
import logging

# Настраиваем логи (чтобы не замусоривать CLI)
logging.getLogger("openrouter").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

def ai_analysis(vulnerabilities: list[str]) -> Tuple[str, str]:
    """
    Отправляет найденные уязвимости в OpenRouter и генерирует:
    - краткий анализ на английском (для отчёта)
    - перевод/анализ на русском (для русского отчёта)
    """
    if not vulnerabilities:
        return ("✅ Clean scan", "✅ Чистая проверка")

    # API-ключ берётся из переменной окружения (OPENROUTER_API_KEY)
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        logging.warning("OPENROUTER_API_KEY not found, fallback to simple template")
        vulns = ", ".join(vulnerabilities)
        return (
            f"🚨 Risks: {vulns}. Fix immediately!",
            f"🚨 Риски: {vulns}. Срочно исправьте!"
        )

    # Какие уязвимости нашли
    vuln_list = ", ".join(vulnerabilities)

    # Конфигурация клиента
    try:
        client = OpenRouter(
            api_key=api_key,
            # Можно добавить HTTP-Referer / X-Title для аналитики
            # default_headers={
            #     "HTTP-Referer": "https://your-websecai.com",
            #     "X-Title": "WebSecAI Security Scanner"
            # }
        )
    except Exception as e:
        logging.warning(f"Failed to init OpenRouter: {e}, fallback to simple template")
        vulns = ", ".join(vulnerabilities)
        return (
            f"🚨 Risks: {vulns}. Fix immediately!",
            f"🚨 Риски: {vulns}. Срочно исправьте!"
        )

    # EN: анализ на английском
    try:
        response = client.chat.send(
            model="openai/gpt-4o",  # или любая другая модель, например "anthropic/claude-3-sonnet"
            messages=[
                Message(
                    role="system",
                    content="You are a security engineer. You analyze a list of detected web vulnerabilities and return a short, clear impact assessment and remediation advice."
                ),
                Message(
                    role="user",
                    content=f"Analyze these detected web vulnerabilities: {vuln_list}. "
                            "Output only: one short paragraph (1–2 sentences) with impact level and concrete next steps to fix. "
                            "Start with '🚨 Risks detected'."
                )
            ],
            max_tokens=200,
            temperature=0.5
        )
        en_text = response.choices[0].message.content.strip()
    except Exception as e:
        logging.warning(f"OpenRouter english analysis failed: {e}")
        en_text = f"🚨 Risks: {vuln_list}. Fix immediately!"

    # RU: перевод на русский + краткий отчёт
    try:
        response = client.chat.send(
            model="openai/gpt-4o",
            messages=[
                Message(
                    role="system",
                    content="Вы — эксперт по безопасности. Вы анализируете список найденных уязвимостей веб-приложения и даёте краткую оценку риска и рекомендации по устранению."
                ),
                Message(
                    role="user",
                    content=f"Проанализируйте уязвимости: {vuln_list}. "
                            f"Сформулируйте краткий анализ рисков и конкретные шаги по исправлению. "
                            f"Напишите очень кратко, 1–2 предложения. Начните с «🚨 Риски найдены»."
                )
            ],
            max_tokens=200,
            temperature=0.5
        )
        ru_text = response.choices[0].message.content.strip()
    except Exception as e:
        logging.warning(f"OpenRouter russian analysis failed: {e}")
        # Если русский не сработал, но английский есть — можно хотя бы скопировать + пометить
        ru_text = "🚨 Риски найдены. Некоторые уязвимости требуют немедленного исправления."

    return (en_text, ru_text)
