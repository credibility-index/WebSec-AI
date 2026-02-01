"""AI-агент «Аналитик уязвимостей»: скан, аналитика на основе сервисов WebSecAI."""
import re
from typing import Any, Dict, List, Optional, Tuple


AGENT_SYSTEM = """Ты — аналитик уязвимостей WebSecAI. Твоя задача: выполнять анализ и предоставлять аналитику данных, используя сервисы платформы.

Разрешённые действия (в конце ответа — ровно одна строка с командой, без кавычек):
- Полный аудит + аналитика: ANALYZE:http://url   — сканирование (SQLi, XSS, CSRF, SSRF, Network) и AI-аналитика уязвимостей
- Быстрый скан: SCAN:http://url   — скан с поиском флагов (CTF)
- Поиск флагов: FLAGS:http://url
- Разведка: RECON:domain.com

Правила:
1. Для запросов «проанализируй», «аналитика», «аудит», «оцени безопасность» — используй ANALYZE:url.
2. Для «просканируй», «сканируй», «проверь» — SCAN или ANALYZE в зависимости от контекста.
3. Отвечай кратко, подтверждай действие и добавляй команду.
4. Если URL не указан — ответь: «Укажите URL (например http://site.com) или домен.»
5. Не придумывай URL и домены."""


def _is_analysis_request(msg: str) -> bool:
    """Запрос про анализ, скан, флаги или разведку."""
    msg = (msg or "").strip().lower()
    if re.search(r"https?://[^\s]+", msg, re.I):
        return True
    if re.search(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", msg):
        return True
    keywords = (
        "скан", "просканируй", "сканируй", "флаги", "найди флаг",
        "разведк", "домен", "анализ", "аналитик", "проанализируй",
        "аудит", "оцени", "проверь", "recon", "scan", "flags", "analyze"
    )
    return any(k in msg for k in keywords)


def _extract_command(text: str) -> Optional[Tuple[str, str]]:
    """Ищет ANALYZE:url, SCAN:url, FLAGS:url, RECON:domain."""
    text = text.strip()
    # ANALYZE — приоритет для аналитики
    m = re.search(r"\bANALYZE:\s*(https?://[^\s]+)", text, re.I)
    if m:
        return ("analyze", m.group(1).rstrip(".,"))
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
    """Только реальные флаги CTF."""
    if not s or len(s) < 12:
        return False
    s = s.strip()
    if "/" in s or "uploads" in s.lower() or s.startswith("com/"):
        return False
    if re.match(r"^[a-fA-F0-9]{8,16}$", s):
        return False
    if "{" in s or "}" in s or s.startswith(("FLAG", "CTF", "HTB", "THM", "flag{", "ctf{")):
        return True
    if re.match(r"^[A-Za-z0-9+/=]{28,80}$", s) and "=" in s:
        return True
    if re.match(r"^[a-fA-F0-9]{32,64}$", s):
        return True
    return False


def _run_analyze(url: str) -> str:
    """Полный аудит + AI-аналитика на основе сервисов WebSecAI."""
    import os
    try:
        import websec
        r = websec.full_scan(url, timeout=5.0)
        vulns = r.get("vulnerabilities", [])
        metrics = r.get("metrics", {})
        ai_en = r.get("ai_analysis", {}).get("en", "")
        ai_ru = r.get("ai_analysis", {}).get("ru", "")

        lines = [
            "## Аналитика уязвимостей",
            "",
            f"**Цель:** {r.get('target', url)}",
            f"**Оценка безопасности:** {metrics.get('score', 0)}/100",
            f"**Время скана:** {metrics.get('scan_time', 0)} с",
            f"**Найдено уязвимостей:** {metrics.get('vuln_count', 0)}",
            "",
            "### Результаты сканирования",
        ]
        if vulns:
            for v in vulns:
                lines.append(f"- {v}")
        else:
            lines.append("- Уязвимостей не обнаружено")

        lines.extend([
            "",
            "### AI-анализ (EN)",
            ai_en or "—",
            "",
            "### AI-анализ (RU)",
            ai_ru or "—",
        ])

        # Доп. аналитика через AI, если есть уязвимости
        if vulns and (os.environ.get("OPENROUTER_API_KEY") or "").strip():
            try:
                from core.ai_engine import _call_openrouter
                ctx = "Уязвимости: " + ", ".join(vulns) + f". Оценка: {metrics.get('score')}/100. Цель: {url}"
                extra = _call_openrouter(
                    "Ты — эксперт по кибербезопасности. Дай краткие рекомендации по исправлению (3–5 пунктов).",
                    ctx,
                    max_tokens=400,
                )
                if extra:
                    lines.extend(["", "### Рекомендации по исправлению", extra])
            except Exception:
                pass

        return "\n".join(lines)
    except Exception as e:
        return f"Ошибка аналитики: {e}"


def run_agent_action(action: str, value: str) -> str:
    """Выполняет действие и возвращает результат."""
    import os

    if action == "analyze":
        return _run_analyze(value)

    if action == "scan":
        try:
            import websec
            r = websec.ctf_scan(value, profile="ctf_quick", find_flags=True)
        except Exception:
            try:
                import websec
                r = websec.full_scan(value, timeout=5.0)
            except Exception as e:
                return f"Ошибка скана: {e}"

        vulns = r.get("vulnerabilities", [])
        flags = r.get("flags", [])
        score = r.get("metrics", {}).get("score", 0)
        report = r.get("report", [])
        lines = [
            f"**Отчёт по скану:** {value}",
            f"Оценка: {score}/100. Время: {r.get('metrics', {}).get('scan_time', 0)} с.",
            "",
            "**Уязвимости:** " + (", ".join(vulns) or "не найдено") + ".",
        ]
        if report:
            lines.append("")
            lines.append("**Проверки:**")
            for i, item in enumerate(report[:10], 1):
                name = item.get("name", item.get("id", str(i)))
                res = item.get("result_text", item.get("result", ""))
                lines.append(f"{i}. {name} — {res}")
        flag_strs = [f.get("flag", str(f)) for f in flags if _looks_like_real_flag(str(f.get("flag", "")))]
        if flag_strs:
            lines.append("")
            lines.append("**Флаги:** " + ", ".join(flag_strs[:10]))
        return "\n".join(lines)

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


REFUSAL_MSG = (
    "Я — аналитик уязвимостей. Выполняю: полный аудит (ANALYZE:url), скан (SCAN:url), "
    "поиск флагов (FLAGS:url), разведку (RECON:домен). Укажите URL или домен."
)


def agent_turn(user_message: str, history: List[Dict[str, str]]) -> Tuple[str, Optional[str], Optional[str]]:
    """Один ход агента: AI → извлечение команды → выполнение → ответ."""
    import os
    from core.ai_engine import _call_openrouter

    api_key = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
    if not api_key:
        return "Введите API-ключ OpenRouter в боковой панели.", None, None

    if not _is_analysis_request(user_message):
        return REFUSAL_MSG, None, REFUSAL_MSG

    parts = []
    for h in history[-10:]:
        role = "Пользователь" if h["role"] == "user" else "Ассистент"
        parts.append(f"{role}: {h['content']}")
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
        reply = reply.strip() + "\n\n---\n\n**Результат (сервисы WebSecAI)**\n\n" + action_result

    return reply, action_result, reply
