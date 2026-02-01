"""
Валидация ввода, лимиты запросов и безопасные сообщения для пользователя.
Внутренние детали ошибок не показываются.
"""
import re
import time
from typing import Optional

MAX_URL_LEN = 2048
MAX_DOMAIN_LEN = 253
MAX_PATH_LEN = 512
MAX_TEXT_LEN = 50_000
MAX_FILE_SIZE_MB = 50
RATE_LIMIT_SCAN_PER_MIN = 5
RATE_LIMIT_AI_PER_MIN = 15


def validate_url(value: Optional[str]) -> tuple[bool, str]:
    """Проверка URL. Возвращает (ok, message)."""
    if not value or not isinstance(value, str):
        return False, "Укажите URL."
    s = value.strip()
    if len(s) > MAX_URL_LEN:
        return False, "URL слишком длинный."
    if not (s.startswith("http://") or s.startswith("https://")):
        return False, "Допустимы только протоколы http и https."
    if "\n" in s or "\r" in s:
        return False, "Недопустимые символы в URL."
    return True, ""


def validate_domain(value: Optional[str]) -> tuple[bool, str]:
    """Проверка домена или IP."""
    if not value or not isinstance(value, str):
        return False, "Укажите домен или IP."
    s = value.strip().split("/")[0].split(":")[0]
    if len(s) > MAX_DOMAIN_LEN:
        return False, "Слишком длинное значение."
    if "\n" in s or " " in s:
        return False, "Недопустимые символы."
    return True, ""


def sanitize_path(value: Optional[str]) -> str:
    """Безопасный путь для сканирования: без выхода за пределы."""
    if not value or not isinstance(value, str):
        return "."
    s = value.strip()
    if len(s) > MAX_PATH_LEN:
        return "."
    if ".." in s or s.startswith("/") or "\0" in s:
        return "."
    return s or "."


def sanitize_text(value: Optional[str], max_len: int = MAX_TEXT_LEN) -> str:
    """Обрезка текста до допустимой длины."""
    if value is None:
        return ""
    s = str(value).strip()
    return s[:max_len] if len(s) > max_len else s


def safe_error_message(exc: Optional[Exception]) -> str:
    """Сообщение для пользователя без внутренних деталей."""
    return "Сервис временно недоступен. Повторите попытку позже."


def check_rate_limit(key: str, limit: int, window_sec: int = 60) -> tuple[bool, str]:
    """
    Проверка лимита запросов по ключу (в session_state).
    Возвращает (allowed, message).
    """
    import streamlit as st
    state_key = f"_rate_{key}"
    now = time.time()
    if state_key not in st.session_state:
        st.session_state[state_key] = []
    times = st.session_state[state_key]
    times = [t for t in times if now - t < window_sec]
    if len(times) >= limit:
        return False, "Слишком много запросов. Подождите минуту."
    times.append(now)
    st.session_state[state_key] = times[-limit * 2:]
    return True, ""
