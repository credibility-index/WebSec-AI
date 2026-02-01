"""Вкладки: Расширения, Достоверность, AI-изображения, Крипто."""

import os
import json
import re
import streamlit as st
from ui.security import safe_error_message, sanitize_text


def render_extensions(tab) -> None:
    with tab:
        st.subheader("Сканер расширений")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Загрузите файл расширения (.crx или .zip). Сканирование — статический анализ: дрейнеры, кейлоггеры, подозрительные API.")
        uploaded_file = st.file_uploader("Файл расширения", type=["crx", "zip"])
        if uploaded_file and st.button("Сканировать расширение", type="primary"):
            with st.spinner("Анализ кода..."):
                try:
                    import websec
                    results = websec.scan_extension(uploaded_file)
                    col_crit, col_high, col_safe = st.columns(3)
                    col_crit.metric("Критичные угрозы", results['critical'], delta_color="inverse")
                    col_high.metric("Высокий риск", results['high'], delta_color="inverse")
                    if results['critical'] > 0:
                        col_safe.metric("Вердикт", "ОПАСНО", "⛔")
                        st.error("Обнаружен опасный код.")
                    elif results['high'] > 0:
                        col_safe.metric("Вердикт", "ПОДОЗРИТЕЛЬНО", "⚠️")
                        st.warning("Обнаружен подозрительный код.")
                    else:
                        col_safe.metric("Вердикт", "БЕЗОПАСНО", "✅")
                        st.success("Чисто.")
                    if results['threats']:
                        with st.expander("Обнаруженные угрозы", expanded=True):
                            for t in results['threats']:
                                if "CRITICAL" in t or "🚨" in t:
                                    st.error(t)
                                elif "HIGH" in t:
                                    st.warning(t)
                                else:
                                    st.write(t)
                except Exception:
                    st.error(safe_error_message(None))


def render_fake(tab) -> None:
    with tab:
        st.subheader("Оценка достоверности текста")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Вставьте текст новости. Нажмите «Оценить достоверность» — оценка по шкале 1–10 и краткое объяснение. Укажите ключ API в боковой панели.")
        news_text = st.text_area("Текст новости", height=200, key="fake_news_text")
        if st.button("Оценить достоверность", type="primary", key="fake_btn"):
            if not news_text or not news_text.strip():
                st.warning("Введите текст.")
            elif not (os.environ.get("OPENROUTER_API_KEY") or "").strip():
                st.warning("Укажите ключ API в боковой панели.")
            else:
                with st.spinner("Анализ..."):
                    try:
                        from core.ai_engine import _call_openrouter
                        sample = sanitize_text(news_text.strip(), 2000)
                        sys_msg = "Ты эксперт по факт-чекингу. Отвечай кратко: оценка от 1 до 10 (1 — явная ложь, 10 — высокая достоверность), затем 1–2 предложения объяснения."
                        user_msg = f"Оцени достоверность следующего текста и объясни:\n\n{sample}"
                        out = _call_openrouter(sys_msg, user_msg, max_tokens=256)
                        if out:
                            st.success("Результат анализа")
                            st.info(out)
                        else:
                            st.warning("Сервис временно недоступен.")
                    except Exception:
                        st.error(safe_error_message(None))


def render_img(tab) -> None:
    with tab:
        st.subheader("Детекция изображений")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Загрузите изображение (JPG/PNG). Нажмите «Проверить» — будет определён признак синтетики или реального фото.")
        uploaded = st.file_uploader("Изображение", type=["jpg", "png", "jpeg"], key="ai_img_upload")
        if uploaded and st.button("Проверить", key="ai_img_btn"):
            with st.spinner("Загрузка и анализ..."):
                try:
                    import tempfile
                    from transformers import pipeline
                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                        tmp.write(uploaded.getvalue())
                        path = tmp.name
                    try:
                        pipe = pipeline("image-classification", model="dima806/deepfake_vs_real_image_detection", top_k=2)
                        result = pipe(path)
                        label = (result[0] or {}).get("label", "")
                        score = (result[0] or {}).get("score", 0)
                        st.metric("Вердикт", "Синтетика" if "fake" in label.lower() or "ai" in label.lower() else "Реальное фото")
                        st.caption(f"Уверенность: {score:.2f}")
                        if result:
                            st.json(result)
                    finally:
                        try:
                            os.unlink(path)
                        except Exception:
                            pass
                except ImportError:
                    st.warning("Модуль анализа изображений недоступен.")
                except Exception:
                    st.error(safe_error_message(None))


def render_crypto(tab) -> None:
    with tab:
        st.subheader("Криптокошелёк")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("При необходимости укажите ETHERSCAN_API_KEY. Вставьте адрес кошелька или текст с адресом ETH/BTC. Сканирование — оценка риска, баланс, транзакции.")
        with st.expander("Ключ API"):
            eth_key = st.text_input("ETHERSCAN_API_KEY", type="password", key="etherscan_key")
            if eth_key:
                os.environ["ETHERSCAN_API_KEY"] = eth_key
        wallet_input = st.text_area("Адрес кошелька или текст", height=120, key="wallet_input")
        if st.button("Сканировать кошелёк", type="primary", key="wallet_btn"):
            if not wallet_input or not wallet_input.strip():
                st.warning("Введите адрес или текст.")
            else:
                try:
                    from scanners.crypto_scanner import validate_wallet
                    m = re.search(r'(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{39,59})', wallet_input.strip())
                    if not m:
                        st.error("Не найден корректный адрес ETH/BTC.")
                    else:
                        addr = m.group()
                        r = validate_wallet(addr)
                        c1, c2, c3 = st.columns(3)
                        c1.metric("Риск", f"{r['score']}/100")
                        c2.metric("Баланс (ETH)", f"{r.get('balance_eth', 0):.4f}")
                        c3.metric("Транзакции", r.get('tx_count', 0))
                        colors = {"LOW": "🟢", "HIGH": "🟡", "CRITICAL": "🔴", "INVALID": "⚪"}
                        st.markdown(f"### {colors.get(r['risk'], '⚪')} **{r['risk']}**")
                        if r.get('reason'):
                            st.warning(" | ".join(r['reason']))
                        st.download_button("Скачать JSON", json.dumps(r, indent=2), f"wallet_{addr[:8]}.json", key="wallet_dl")
                except Exception:
                    st.error(safe_error_message(None))
