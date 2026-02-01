"""Вкладки: Флаги CTF, CTF Hub, CTF Скан, Поиск флагов."""

import streamlit as st
from ui.security import validate_url, safe_error_message, check_rate_limit, RATE_LIMIT_SCAN_PER_MIN


def render_ctf_tracker(tab) -> None:
    with tab:
        st.subheader("Трекер флагов CTF")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Список — просмотр флагов. Добавить — сохранить флаг. Экспорт/Импорт — JSON. CTFd — отправить флаг на платформу.")
        from modules.flag_tracker import list_flags, add, export_json, import_json
        act = st.radio("Действие", ["Список", "Добавить", "Экспорт", "Импорт"], key="tracker_act")
        if act == "Список":
            task_id = st.text_input("Фильтр по ID задачи", key="tracker_task")
            data = list_flags(task_id=task_id or None)
            st.metric("Флагов", len(data))
            if data:
                st.dataframe(data)
        elif act == "Добавить":
            t = st.text_input("ID задачи", "default", key="tracker_add_task")
            f = st.text_input("Флаг", key="tracker_add_flag")
            if st.button("Добавить флаг") and f:
                add(t, f)
                st.success("Добавлено.")
        elif act == "Экспорт":
            st.download_button("Скачать JSON", export_json(), "flags.json", key="tracker_export")
        elif act == "Импорт":
            uploaded = st.file_uploader("Файл JSON", type=["json"], key="tracker_import_file")
            if uploaded and st.button("Импорт"):
                try:
                    n = import_json(uploaded.read().decode())
                    st.success(f"Импортировано записей: {n}")
                except Exception:
                    st.error(safe_error_message(None))
        st.markdown("#### CTFd")
        ctfd_url = st.text_input("URL CTFd", key="ctfd_url")
        ctfd_token = st.text_input("Токен", type="password", key="ctfd_token")
        ctfd_cid = st.number_input("ID задания", min_value=0, key="ctfd_cid")
        ctfd_flag = st.text_input("Флаг", key="ctfd_flag")
        if st.button("Отправить в CTFd") and ctfd_url and ctfd_token and ctfd_flag:
            ok, msg = validate_url(ctfd_url)
            if not ok:
                st.error(msg)
            else:
                try:
                    from modules.ctfd_client import ctfd_submit
                    r = ctfd_submit(ctfd_url, ctfd_token, int(ctfd_cid), ctfd_flag)
                    if r.get("success"):
                        st.success(r.get("message", "Принято."))
                    else:
                        st.error(r.get("message", "Ошибка отправки."))
                except Exception:
                    st.error(safe_error_message(None))


def render_ctf_hub(tab) -> None:
    with tab:
        st.subheader("CTF Hub")
        from modules.ctf_tools import suggested_tools, all_categories, decode_misc, forensics_file, reverse_info, pwn_binary_info
        from modules.payload_generator import payloads_all
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Выберите категорию: Web, Pwn, Crypto, Forensics, Reverse, Misc. Используйте инструменты и быстрые ссылки.")
        cat = st.selectbox("Категория", all_categories(), format_func=lambda x: x.capitalize(), key="ctf_hub_cat")
        info = suggested_tools(cat)
        st.caption(info.get("description", ""))
        if info.get("external"):
            st.caption("Внешние инструменты: " + ", ".join(info["external"]))
        st.divider()
        if cat == "web":
            w1, w2, w3 = st.columns(3)
            with w1:
                st.markdown("[**CTF Скан**](?tab=ctf)")
            with w2:
                st.markdown("[**Поиск флагов**](?tab=flags)")
            with w3:
                st.markdown("[**Эксплойт**](?tab=exploit)")
            web_payload_type = st.selectbox("Тип payload", ["sqli", "xss"], key="ctf_hub_web_payload")
            web_payloads = payloads_all().get(web_payload_type, [])
            st.text_area("Payloads", "\n".join(web_payloads[:15]), height=180, key="ctf_hub_web_area")
        elif cat == "pwn":
            pwn_file = st.file_uploader("Бинарник", type=["bin", "elf", "so", "out", "exe"], key="ctf_hub_pwn_file")
            if pwn_file and st.button("Анализ бинарника", key="ctf_hub_pwn_btn"):
                try:
                    r = pwn_binary_info(pwn_file.read())
                    st.json({"magic": r["magic"], "arch": r.get("arch") or "—", "entropy": r["entropy"], "elf": r.get("elf", {})})
                    if r.get("checksec"):
                        st.code(r["checksec"], language="text")
                    if r.get("strings"):
                        with st.expander("Strings"):
                            st.text("\n".join(r["strings"][:60]))
                except Exception:
                    st.error(safe_error_message(None))
        elif cat == "misc":
            misc_text = st.text_area("Текст", key="misc_decode_text", height=100)
            misc_enc = st.selectbox("Кодировка", ["base64", "base64url", "hex", "rot13", "url", "url_encode", "binary", "reverse"], key="misc_enc")
            if st.button("Декодировать / Кодировать", key="misc_btn") and misc_text:
                r = decode_misc(misc_text.strip(), misc_enc)
                if r.get("success"):
                    st.code(r["decoded"])
                else:
                    st.error(r.get("error", "Ошибка"))
        elif cat == "crypto":
            crypto_input = st.text_area("JWT или хеш", key="crypto_hub_input", height=80)
            if st.button("Анализ", key="crypto_hub_btn") and crypto_input:
                try:
                    from modules.crypto_analyzer import analyze_jwt, analyze_hashes_in_text, try_decode
                    jwt_r = analyze_jwt(crypto_input.strip())
                    if jwt_r.get("valid"):
                        st.json({"header": jwt_r.get("header"), "payload": jwt_r.get("payload"), "vulns": jwt_r.get("vulnerabilities")})
                    else:
                        hashes = analyze_hashes_in_text(crypto_input)
                        dec = try_decode(crypto_input[:500])
                        if hashes:
                            st.json(hashes)
                        if dec:
                            st.json(dec)
                except Exception:
                    st.error(safe_error_message(None))
        elif cat in ("forensics", "reverse"):
            uploaded = st.file_uploader("Файл", key="ctf_hub_file")
            if uploaded and st.button("Анализ файла", key="ctf_hub_file_btn"):
                raw = uploaded.read()
                if cat == "forensics":
                    r = forensics_file(raw)
                    st.json({"magic": r["magic"], "size": r["size"], "exif_keys": list(r["exif"].keys())})
                    if r.get("strings"):
                        with st.expander("Strings"):
                            st.text("\n".join(r["strings"][:80]))
                else:
                    r = reverse_info(raw)
                    st.json({"magic": r["magic"], "entropy": r["entropy"]})
                    if r.get("strings"):
                        with st.expander("Strings"):
                            st.text("\n".join(r["strings"][:80]))


def render_ctf_scan(tab) -> None:
    with tab:
        st.subheader("CTF Скан")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Введите целевой URL, выберите профиль (ctf_quick/full/devsecops), при необходимости включите поиск флагов и авто-эксплойт.")
        col_url, col_prof = st.columns([2, 1])
        ctf_url = col_url.text_input("Целевой URL", "http://testphp.vulnweb.com", key="ctf_url")
        ctf_profile = col_prof.selectbox("Профиль", ["ctf_quick", "ctf_full", "devsecops"], key="ctf_profile")
        find_flags = st.checkbox("Искать флаги", value=True, key="find_flags")
        auto_exploit = st.checkbox("Авто-эксплойт", value=False, key="auto_exploit")
        if st.button("Запустить CTF Скан", type="primary", key="ctf_btn"):
            ok, msg = validate_url(ctf_url)
            if not ok:
                st.error(msg)
            else:
                allowed, rate_msg = check_rate_limit("ctf_scan", RATE_LIMIT_SCAN_PER_MIN)
                if not allowed:
                    st.warning(rate_msg)
                else:
                    with st.spinner("Сканирование..."):
                        try:
                            import websec
                            result = websec.ctf_scan(ctf_url, profile=ctf_profile, find_flags=find_flags)
                            if auto_exploit and result.get("vulnerabilities"):
                                from core.exploiter import run_exploit
                                exploits = []
                                for v in result["vulnerabilities"]:
                                    if isinstance(v, str) and "CSRF" not in v:
                                        ex = run_exploit(v, ctf_url)
                                        exploits.append(ex)
                                result["exploits"] = exploits
                            st.session_state["ctf_result"] = result
                            try:
                                from core.audit_log import log_scan
                                log_scan(ctf_url, ctf_profile, result.get("metrics", {}).get("vuln_count", 0))
                            except Exception:
                                pass
                            try:
                                from core.webhook import webhook_scan_complete
                                webhook_scan_complete(result)
                            except Exception:
                                pass
                        except Exception:
                            st.error(safe_error_message(None))
        if st.session_state.get("ctf_result"):
            r = st.session_state["ctf_result"]
            m1, m2, m3 = st.columns(3)
            m1.metric("Оценка", r.get("metrics", {}).get("score", 0), "/100")
            m2.metric("Уязвимости", r.get("metrics", {}).get("vuln_count", 0), "")
            m3.metric("Флаги", len(r.get("flags", [])), "")
            if r.get("vulnerabilities"):
                st.error("Уязвимости: " + ", ".join(r["vulnerabilities"]))
            if r.get("flags"):
                with st.expander("Найденные флаги", expanded=True):
                    for f in r["flags"]:
                        st.code(f.get("flag", f), language=None)
                        st.caption(f.get("location", ""))
            if r.get("ai_analysis"):
                st.markdown("#### Анализ")
                st.info(r["ai_analysis"].get("en", ""))


def render_flags(tab) -> None:
    with tab:
        st.subheader("Поиск флагов")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Введите URL цели, укажите макс. страниц. Запуск обходит страницы и ищет флаги в HTML, JS, cookies, заголовках.")
        fh_url = st.text_input("URL", "http://testphp.vulnweb.com", key="fh_url")
        fh_max = st.slider("Макс. страниц", 5, 50, 15, key="fh_max")
        if st.button("Искать флаги", key="fh_btn"):
            ok, msg = validate_url(fh_url)
            if not ok:
                st.error(msg)
            else:
                allowed, rate_msg = check_rate_limit("flag_hunt", RATE_LIMIT_SCAN_PER_MIN)
                if not allowed:
                    st.warning(rate_msg)
                else:
                    with st.spinner("Поиск..."):
                        try:
                            from modules.flag_hunter import hunt_flags
                            found = hunt_flags(fh_url, max_pages=fh_max)
                            st.session_state["fh_found"] = found
                        except Exception:
                            st.error(safe_error_message(None))
        if st.session_state.get("fh_found") is not None:
            found = st.session_state["fh_found"]
            st.metric("Найдено флагов", len(found))
            for item in found:
                st.code(item.get("flag", ""), language=None)
                st.caption(item.get("location", "") + " | " + item.get("method", ""))
