"""Вкладка «AI Агент»: чат с выполнением сканов по запросу."""

import streamlit as st
from ui.security import safe_error_message, check_rate_limit, RATE_LIMIT_AI_PER_MIN


def render(tab) -> None:
    with tab:
        st.subheader("AI Агент")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("""
Напишите запрос на русском. Агент выполнит действие и выведет результат.

**Примеры:** «просканируй http://example.com», «найди флаги на http://site.com», «разведка по домену example.com».

**Формат команд (агент подставляет сам):**
- Скан: `SCAN:http://url`
- Поиск флагов: `FLAGS:http://url`
- Разведка: `RECON:domain.com`

Укажите ключ OpenRouter в боковой панели.
            """)
        if "agent_messages" not in st.session_state:
            st.session_state.agent_messages = []
        for msg in st.session_state.agent_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
        prompt = st.chat_input("Введите запрос...")
        if prompt:
            allowed, rate_msg = check_rate_limit("agent", RATE_LIMIT_AI_PER_MIN)
            if not allowed:
                st.warning(rate_msg)
            else:
                st.session_state.agent_messages.append({"role": "user", "content": prompt})
                with st.spinner("Ожидание ответа..."):
                    try:
                        from core.agent import agent_turn
                        reply, _, _ = agent_turn(prompt, st.session_state.agent_messages[:-1])
                    except Exception:
                        reply = safe_error_message(None)
                st.session_state.agent_messages.append({"role": "assistant", "content": reply})
                st.rerun()
        if st.session_state.agent_messages and st.button("Очистить историю", key="agent_clear"):
            st.session_state.agent_messages = []
            st.rerun()
