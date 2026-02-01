"""Вкладки: Payloads, Стеганография, База знаний, Экспорт."""

import os
import json
import streamlit as st
from ui.security import safe_error_message


def render_payloads(tab) -> None:
    with tab:
        st.subheader("Payloads")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Выберите тип (sqli, xss, lfi, rce), скопируйте payloads и используйте во вкладке Эксплойт или CTF Hub.")
        from modules.payload_generator import payloads_all
        kind = st.selectbox("Тип", ["sqli", "xss", "lfi", "rce"], key="payload_kind")
        payloads = payloads_all().get(kind, [])
        st.text_area("Payloads", "\n".join(payloads), height=300, key="payloads_area")


def render_stegano(tab) -> None:
    with tab:
        st.subheader("Стеганография")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Загрузите изображение (PNG, JPG, BMP, GIF). Анализ: exiftool, zsteg, steghide.")
        img_file = st.file_uploader("Изображение", type=["png", "jpg", "jpeg", "bmp", "gif"], key="stegano_file")
        if img_file:
            suffix = os.path.splitext(img_file.name or "")[1] or ".png"
            with st.spinner("Анализ..."):
                try:
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        tmp.write(img_file.read())
                        path = tmp.name
                    try:
                        from modules.stegano import stegano_run
                        r = stegano_run(path)
                        if r.get("exiftool", {}).get("parsed"):
                            st.json(r["exiftool"]["parsed"])
                        if r.get("zsteg", {}).get("findings"):
                            st.write("zsteg:", r["zsteg"]["findings"])
                        if r.get("steghide", {}).get("raw"):
                            st.text(r["steghide"]["raw"][:500])
                    finally:
                        try:
                            os.unlink(path)
                        except Exception:
                            pass
                except Exception:
                    st.error(safe_error_message(None))


def render_kb(tab) -> None:
    with tab:
        st.subheader("База знаний")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("OWASP ASVS и CIS — справочники при аудите и DevSecOps.")
        try:
            from modules.compliance import get_owasp_asvs, get_cis
            st.markdown("**OWASP ASVS**")
            st.dataframe(get_owasp_asvs())
            st.markdown("**CIS**")
            st.dataframe(get_cis())
        except Exception:
            st.error(safe_error_message(None))


def render_export(tab) -> None:
    with tab:
        st.subheader("Экспорт")
        with st.expander("Как пользоваться", expanded=False):
            st.markdown("Кнопки появятся после выполнения скана: CTF, OSINT, веб-аудит или трекер флагов.")
        if st.session_state.get("ctf_result"):
            r = st.session_state["ctf_result"]
            st.download_button("Скачать последний CTF-скан (JSON)", json.dumps(r, indent=2), "ctf_scan.json", key="export_ctf")
            try:
                from reports.report_generator import html_report, pdf_report
                html = html_report(r)
                st.download_button("Скачать отчёт HTML", html, "security_report.html", mime="text/html", key="export_html")
                pdf_bytes = pdf_report(r)
                if pdf_bytes:
                    st.download_button("Скачать отчёт PDF", pdf_bytes, "security_report.pdf", mime="application/pdf", key="export_pdf")
            except Exception:
                pass
        if st.session_state.get("osint_result"):
            st.download_button("Скачать последний OSINT", json.dumps(st.session_state["osint_result"], indent=2, default=str), "osint.json", key="export_osint")
        if st.session_state.get("scan_results"):
            res = st.session_state["scan_results"]
            st.download_button("Скачать последний веб-аудит (JSON)", json.dumps(res, indent=2), "web_audit.json", key="export_audit")
            try:
                from reports.report_generator import html_report, pdf_report
                st.download_button("Скачать веб-аудит HTML", html_report(res), "web_audit_report.html", mime="text/html", key="export_audit_html")
                pdf_bytes = pdf_report(res)
                if pdf_bytes:
                    st.download_button("Скачать веб-аудит PDF", pdf_bytes, "web_audit_report.pdf", mime="application/pdf", key="export_audit_pdf")
            except Exception:
                pass
        from modules.flag_tracker import export_json as flags_export
        st.download_button("Экспорт трекера флагов", flags_export(), "flag_tracker.json", key="export_flags")
