"""Вкладка DevSecOps."""

import streamlit as st
from ui.security import sanitize_path, safe_error_message


def render(tab) -> None:
    with tab:
        st.subheader("DevSecOps")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("""
1. Путь — каталог для сканирования (например `.` или путь к репозиторию).
2. Тип скана: secrets, deps, sast, container, iac.
3. Для container укажите путь к Dockerfile.
4. Запустите скан и просмотрите результаты; Compliance — чеклисты OWASP/CIS.
            """)
        dev_path = sanitize_path(st.text_input("Путь", ".", key="devsecops_path"))
        dev_sub = st.selectbox("Тип скана", ["secrets", "deps", "sast", "container", "iac"], key="devsecops_sub")
        dockerfile_path = sanitize_path(st.text_input("Путь к Dockerfile", "Dockerfile", key="dockerfile_path"))
        if st.button("Запустить скан DevSecOps", key="devsecops_btn"):
            try:
                if dev_sub == "secrets":
                    from modules.secrets_scan import scan_path as secrets_scan_path
                    r = secrets_scan_path(dev_path)
                    st.metric("Находки", r.get("count", 0))
                    if r.get("findings"):
                        st.json(r["findings"][:50])
                elif dev_sub == "deps":
                    from modules.dependency_scan import dependency_scan
                    r = dependency_scan(dev_path)
                    st.json(r)
                elif dev_sub == "sast":
                    from modules.sast import sast_scan
                    r = sast_scan(dev_path)
                    st.metric("Находки", r.get("count", 0))
                    if r.get("findings"):
                        st.dataframe(r["findings"][:100])
                elif dev_sub == "container":
                    from modules.container_scan import container_scan
                    r = container_scan(dockerfile_path)
                    st.json(r)
                elif dev_sub == "iac":
                    from modules.iac_scan import iac_scan
                    r = iac_scan(dev_path)
                    st.metric("Находки", r.get("count", 0))
                    if r.get("findings"):
                        st.json(r["findings"])
            except Exception:
                st.error(safe_error_message(None))
        st.markdown("#### Compliance")
        framework = st.selectbox("Framework", ["owasp", "cis"], key="compliance_fw")
        if st.button("Показать чеклист", key="compliance_btn"):
            try:
                from modules.compliance import compliance_list
                items = compliance_list(framework)
                st.dataframe(items)
            except Exception:
                st.error(safe_error_message(None))
