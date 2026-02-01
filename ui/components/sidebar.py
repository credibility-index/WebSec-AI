"""Боковая панель: настройки и контакты."""

import os
import streamlit as st


def render() -> None:
    with st.sidebar:
        st.markdown("## 🛡️ **WebSecAI**")
        st.caption("v3.6 | CTF и DevSecOps")
        st.info("Поиск уязвимостей, флагов и разведка с поддержкой анализа.")
        st.markdown("---")
        st.markdown("### 🤖 OpenRouter")
        with st.expander("Ключ и модель", expanded=True):
            or_key = st.text_input("API-ключ OpenRouter", type="password", key="or_key", help="Без ключа анализ и подсказки недоступны.")
            if or_key:
                os.environ["OPENROUTER_API_KEY"] = or_key
                st.success("Ключ применён — используется для всех запросов.")
            else:
                st.caption("Введите ключ, чтобы включить анализ и подсказки.")
            try:
                from core.ai_engine import OPENROUTER_MODELS, OPENROUTER_MODEL_LABELS
                def _model_label(mid):
                    return OPENROUTER_MODEL_LABELS.get(mid) or mid.split("/")[-1].split(":")[0]
                model_choice = st.selectbox(
                    "Модель",
                    OPENROUTER_MODELS,
                    index=0,
                    format_func=_model_label,
                    key="or_model",
                )
                if model_choice:
                    os.environ["OPENROUTER_MODEL"] = model_choice
            except Exception:
                pass
            if st.button("Проверить подключение", key="or_check"):
                if not (os.environ.get("OPENROUTER_API_KEY") or "").strip():
                    st.warning("Сначала введите ключ.")
                else:
                    try:
                        from core.ai_engine import _call_openrouter
                        r = _call_openrouter("Ты помощник. Ответь одним словом: ОК.", "Проверка связи.", max_tokens=128)
                        if r and str(r).strip():
                            st.success("Подключение успешно. Ключ принят.")
                        else:
                            st.error("Нет ответа от API. Проверьте ключ и модель на openrouter.ai.")
                    except Exception:
                        st.error("Сервис временно недоступен. Проверьте ключ и сеть.")
        st.markdown("---")
        st.markdown("### 📞 Контакты")
        st.markdown("[**t.me/nothetal**](https://t.me/nothetal)")
        st.markdown("[**t.me/fakedesyncc**](https://t.me/fakedesyncc)")
        st.markdown("[GitHub · WebSec-AI](https://github.com/credibility-index/WebSec-AI)")
        st.caption("Pro: по запросу — контакты выше.")
