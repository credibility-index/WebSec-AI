"""Вкладка OSINT."""

import os
import streamlit as st
from ui.security import validate_domain, safe_error_message


def render(tab) -> None:
    with tab:
        st.subheader("OSINT")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Введите домен или IP. При необходимости укажите ключи Shodan/Censys. Запустите OSINT — результат: DNS, WHOIS, Wayback, Shodan, Censys.")
        with st.expander("Ключи API (опционально)"):
            shodan_key = st.text_input("SHODAN_API_KEY", type="password", key="shodan_osint")
            if shodan_key:
                os.environ["SHODAN_API_KEY"] = shodan_key
            censys_id = st.text_input("CENSYS_API_ID", key="censys_id")
            censys_secret = st.text_input("CENSYS_API_SECRET", type="password", key="censys_secret")
            if censys_id:
                os.environ["CENSYS_API_ID"] = censys_id
            if censys_secret:
                os.environ["CENSYS_API_SECRET"] = censys_secret
        osint_target = st.text_input("Домен или IP", "example.com", key="osint_target")
        include_shodan = st.checkbox("Включить Shodan", value=True, key="osint_shodan")
        if st.button("Запустить OSINT", key="osint_btn"):
            ok, msg = validate_domain(osint_target)
            if not ok:
                st.warning(msg)
            else:
                with st.spinner("Выполняется..."):
                    try:
                        from modules.osint import osint_run
                        data = osint_run(osint_target.strip(), include_shodan=include_shodan)
                        st.session_state["osint_result"] = data
                    except Exception:
                        st.error(safe_error_message(None))
        if st.session_state.get("osint_result"):
            d = st.session_state["osint_result"]
            if d.get("dns") and d["dns"].get("domain"):
                st.markdown("#### DNS")
                st.json({k: v for k, v in d["dns"].items() if v})
            if d.get("whois") and d["whois"].get("raw"):
                with st.expander("WHOIS"):
                    st.text(d["whois"]["raw"][:3000])
            if d.get("wayback") and d["wayback"].get("urls"):
                st.markdown("#### Wayback (образец)")
                st.json(d["wayback"]["urls"][:20])
            if d.get("hackertarget") and (d["hackertarget"].get("dns") or d["hackertarget"].get("whois")):
                with st.expander("HackerTarget"):
                    if d["hackertarget"].get("dns"):
                        st.text(d["hackertarget"]["dns"][:2000])
                    if d["hackertarget"].get("whois"):
                        st.text(d["hackertarget"]["whois"][:2000])
            if d.get("shodan") and d["shodan"].get("available") and d["shodan"].get("data"):
                with st.expander("Shodan"):
                    st.json(d["shodan"]["data"])
            if d.get("censys") and d["censys"].get("available") and d["censys"].get("results"):
                with st.expander("Censys"):
                    st.json(d["censys"]["results"][:10])
