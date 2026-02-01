"""Точка входа UI: конфигурация страницы, сайдбар, вкладки, футер."""

import streamlit as st

from ui.config import TAB_KEYS, TAB_LABELS, TAB_NAMES
from ui.components.sidebar import render as render_sidebar
from ui.components.footer import render as render_footer
from ui.views.dashboard import render as render_dashboard
from ui.views.devsecops import render as render_devsecops
from ui.views.ctf import (
    render_ctf_tracker,
    render_ctf_hub,
    render_ctf_scan,
    render_flags,
)
from ui.views.tools import (
    render_payloads,
    render_stegano,
    render_kb,
    render_export,
)
from ui.views.osint import render as render_osint
from ui.views.recon_exploit_web import (
    render_recon,
    render_exploit,
    render_web_security,
)
from ui.views.extensions_fake_img_crypto import (
    render_extensions,
    render_fake,
    render_img,
    render_crypto,
)
from ui.views.agent import render as render_agent


def _inject_footer_css() -> None:
    st.markdown("""
<style>
.footer-bar { position: fixed; bottom: 0; left: 0; right: 0; background: #f8fafc; border-top: 1px solid #e2e8f0;
  padding: 0.6rem 1rem; text-align: center; font-size: 0.9rem; color: #64748b; z-index: 999; }
.footer-bar a { color: #0ea5e9; margin: 0 0.25rem; text-decoration: none; }
.footer-bar a:hover { text-decoration: underline; }
[data-testid="stAppViewContainer"] { padding-bottom: 4.5rem; }
</style>
""", unsafe_allow_html=True)


def run() -> None:
    st.set_page_config(
        page_title="WebSecAI",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _inject_footer_css()

    qp = st.query_params
    if "tab" in qp and qp["tab"] in TAB_KEYS:
        idx = TAB_KEYS.index(qp["tab"])
        st.session_state["goto_tab"] = TAB_NAMES[idx]

    if st.session_state.get("goto_tab"):
        st.info(f"Перейдите на вкладку **{st.session_state['goto_tab']}** выше.")
        del st.session_state["goto_tab"]

    render_sidebar()

    st.title("🛡️ WebSecAI")
    st.markdown("*Аудит веб-безопасности, поиск флагов CTF, разведка и DevSecOps*")

    tabs = st.tabs(TAB_LABELS)
    if len(tabs) != len(TAB_KEYS):
        st.error("Ошибка конфигурации вкладок.")
        return

    render_dashboard(tabs[0])
    render_devsecops(tabs[1])
    render_ctf_tracker(tabs[2])
    render_payloads(tabs[3])
    render_stegano(tabs[4])
    render_kb(tabs[5])
    render_export(tabs[6])
    render_osint(tabs[7])
    render_ctf_hub(tabs[8])
    render_ctf_scan(tabs[9])
    render_flags(tabs[10])
    render_recon(tabs[11])
    render_exploit(tabs[12])
    render_web_security(tabs[13])
    render_extensions(tabs[14])
    render_fake(tabs[15])
    render_img(tabs[16])
    render_crypto(tabs[17])
    render_agent(tabs[18])

    render_footer()
