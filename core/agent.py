"""AI-агент: выполнение действий по запросу пользователя (скан, поиск флагов, разведка)."""
import re
from typing import Any, Dict, List, Optional, Tuple


AGENT_SYSTEM = """Ты — только анализатор WebSecAI. Твоя единственная задача: выполнять три типа анализа.

Разрешённые действия (в конце ответа — ровно одна строка с командой, без кавычек):
- Скан сайта: SCAN:http://url
- Поиск флагов: FLAGS:http://url
- Разведка по домену: RECON:domain.com

Правила:
1. Отвечай только на запросы про скан, поиск флагов или разведку. Кратко подтверди и добавь команду.
2. На любые другие запросы (код, объяснения, общение) отвечай одной фразой: "Я выполняю только анализ: скан (SCAN:url), поиск флагов (FLAGS:url), разведку (RECON:домен). Укажите URL или домен."
3. Не генерируй код. Не давай советы. Не веди диалог. Только команда для анализа.
4. Если URL или домен не указан — ответь: "Укажите URL (например http://site.com) или домен (например example.com)."
5. Не придумывай URL и домены."""


def _is_analysis_request(msg: str) -> bool:
    """Запрос явно про скан, флаги или разведку (есть URL/домен или ключевые слова)."""
    msg = (msg or "").strip().lower()
    if re.search(r"https?://[^\s]+", msg, re.I):
        return True
    if re.search(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", msg):
        return True
    keywords = ("скан", "просканируй", "сканируй", "флаги", "найди флаг", "разведк", "домен", "recon", "scan", "flags")
    return any(k in msg for k in keywords)


def _extract_command(text: str) -> Optional[Tuple[str, str]]:
    """Ищет в тексте SCAN:url, FLAGS:url, RECON:domain. Возвращает (action, value) или None."""
    text = text.strip()
    m = re.search(r"\bSCAN:\s*(https?://[^\s]+)", text, re.I)
    if m:
        return ("scan", m.group(1).rstrip(".,"))
    m = re.search(r"\bFLAGS:\s*(https?://[^\s]+)", text, re.I)
    if m:
        return ("flags", m.group(1).rstrip(".,"))
    m = re.search(r"\bRECON:\s*(https?://[^\s]+)", text, re.I)
    if m:
        url = m.group(1).rstrip(".,")
        domain = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        return ("recon", domain) if domain else None
    m = re.search(r"\bRECON:\s*([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})", text, re.I)
    if m:
        return ("recon", m.group(1).rstrip(".,"))
    return None


def _looks_like_real_flag(s: str) -> bool:
    """Только реальные флаги CTF. Отсекает пути, идентификаторы, мусор."""
    if not s or len(s) < 12:
        return False
    s = s.strip()
    if "/" in s or "uploads" in s.lower() or s.startswith("com/"):
        return False
    if re.match(r"^[a-fA-F0-9]{8,16}$", s):
        return False
    if re.match(r"^[A-Z][A-Z0-9_]{10,60}$", s) and "_" in s:
        return False
    if "{" in s or "}" in s or s.startswith(("FLAG", "CTF", "HTB", "THM", "flag{", "ctf{")):
        return True
    if re.match(r"^[A-Za-z0-9+/=]{28,80}$", s) and "=" in s:
        return True
    if re.match(r"^[a-fA-F0-9]{32,64}$", s):
        return True
    if re.search(r"[a-z][A-Z]|[A-Z][a-z]", s) and re.match(r"^[a-zA-Z_]+$", s):
        return False
    return False


def run_agent_action(action: str, value: str) -> str:
    """Выполняет действие и возвращает краткий текстовый результат."""
    if action == "scan":
        try:
            import websec
            r = websec.ctf_scan(value, profile="ctf_quick", find_flags=True)
            vulns = r.get("vulnerabilities", [])
            flags = r.get("flags", [])
            score = r.get("metrics", {}).get("score", 0)
            report = r.get("report", [])
            lines = [
                f"**Отчёт по скану:** {value}",
                f"Оценка: {score}/100. Время: {r.get('metrics', {}).get('scan_time', 0)} с.",
                "",
                "**Что проверено:**",
            ]
            for i, item in enumerate(report, 1):
                name = item.get("name", item.get("id", ""))
                desc = item.get("description", "")
                res = item.get("result_text", item.get("result", ""))
                lines.append(f"{i}. **{name}** — {desc} Результат: {res}.")
            lines.append("")
            lines.append("**Уязвимости:** " + (", ".join(vulns) or "не найдено") + ".")
            flag_strs = [f.get("flag", str(f)) for f in flags if _looks_like_real_flag(str(f.get("flag", "")))]
            if flag_strs:
                lines.append("**Флаги:** " + ", ".join(flag_strs[:10]))
            return "\n".join(lines)
        except Exception as e:
            return f"Ошибка скана: {e}"

    if action == "flags":
        try:
            from modules.flag_hunter import hunt_flags
            found = hunt_flags(value, max_pages=10, check_robots_sitemap_git=True)
            if not found:
                return "Флаги не найдены."
            flag_strs = [f.get("flag", str(f)) for f in found if _looks_like_real_flag(str(f.get("flag", "")))]
            if not flag_strs:
                return "Подходящих флагов не найдено."
            return "Найдено флагов: " + str(len(flag_strs)) + "\n" + "\n".join(flag_strs[:15])
        except Exception as e:
            return f"Ошибка: {e}"

    if action == "recon":
        try:
            from modules.recon import recon_domain
            r = recon_domain(value, subdomain_limit=30, include_wayback=True)
            subs = r.get("subdomains", [])[:20]
            tech = r.get("technologies", [])
            return f"Поддомены: {', '.join(subs) or 'нет'}. Технологии: {', '.join(tech) or 'не определено'}."
        except Exception as e:
            return f"Ошибка: {e}"

    return "Неизвестное действие."


REFUSAL_MSG = "Я выполняю только анализ: скан (SCAN:url), поиск флагов (FLAGS:url), разведку (RECON:домен). Укажите URL или домен."


def agent_turn(user_message: str, history: List[Dict[str, str]]) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Отправляет сообщение в AI, при необходимости выполняет команду из ответа.
    На запросы не про анализ — сразу отказ без вызова модели.
    """
    import os
    from core.ai_engine import _call_openrouter
    api_key = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
    if not api_key:
        return "Введите API-ключ OpenRouter в боковой панели.", None, None

    if not _is_analysis_request(user_message):
        return REFUSAL_MSG, None, REFUSAL_MSG

    parts = []
    for h in history[-10:]:
        if h["role"] == "user":
            parts.append("Пользователь: " + h["content"])
        else:
            parts.append("Ассистент: " + h["content"])
    parts.append("Пользователь: " + user_message)
    prompt = "\n\n".join(parts)
    reply = _call_openrouter(AGENT_SYSTEM, prompt, max_tokens=1024)
    if not reply:
        return "Нет ответа от AI. Проверьте ключ и модель.", None, None

    cmd = _extract_command(reply)
    action_result = None
    if cmd:
        action, value = cmd
        action_result = run_agent_action(action, value)
        reply = reply.strip() + "\n\n[Выполнено]\n" + action_result

    return reply, action_result, reply
