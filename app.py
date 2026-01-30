import streamlit as st
import os
import json
import time
from datetime import datetime
from PIL import Image

# Настройка страницы
st.set_page_config(page_title="🛡️ WebSecAI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.title("🛡️ **WebSecAI Suite v3.3**")
st.markdown("*Full Security Suite • OWASP • FakeNews • **Extensions** • AI Images*")

# ── SIDEBAR ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔑 **Configuration**")
    or_key = st.text_input("OpenRouter Key", type="password")
    if or_key: os.environ["OPENROUTER_API_KEY"] = or_key
    
    gc_key = st.text_input("GigaChat Key", type="password")
    if gc_key: st.secrets["GIGACHAT_API_KEY"] = gc_key
    
    st.markdown("---")
    st.caption("👨‍💻 Moscow Cybersecurity Lab 2026")

# ── TABS (Обновленный список) ─────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔒 Web Security", 
    "📰 FakeNews", 
    "🧩 Extensions",  # <--- НОВЫЙ ТАБ
    "🖼️ AI Images", 
    "₿ Crypto", 
    "📊 Dashboard"
])

# ════════════════ TAB 1: WEB SECURITY ════════════════
with tab1:
    # (Код Web Security без изменений, оставляем как есть)
    st.subheader("🎯 OWASP Top 10 Scanner")
    col_url, col_to = st.columns([3, 1])
    target_url = col_url.text_input("Target URL", "http://testphp.vulnweb.com")
    timeout = col_to.slider("Timeout", 3, 15, 5)
    
    st.divider()
    
    # Кнопки быстрых сканеров
    c1, c2, c3, c4, c5 = st.columns(5)
    def run_single(name, func_name):
        if not target_url: return st.warning("Enter URL!")
        with st.spinner(f"Loading {name}..."):
            try:
                import websec
                func = getattr(websec, func_name)
                res = func(target_url)
                if res: st.error(f"🔴 {name}: DETECTED")
                else: st.success(f"🟢 {name}: Clean")
            except: st.error("Error loading module")

    if c1.button("🔍 SQLi"): run_single("SQLi", "scan_sql_injection")
    if c2.button("🔍 XSS"): run_single("XSS", "scan_xss")
    if c3.button("🔍 CSRF"): run_single("CSRF", "check_csrf_protection")
    if c4.button("🔍 SSRF"): run_single("SSRF", "scan_ssrf")
    if c5.button("🌐 Network"): run_single("Network", "scan_network_segmentation")

    st.divider()
    
    # Full Scan
    if st.button("🚀 LAUNCH FULL AUDIT", type="primary", use_container_width=True):
        if target_url:
            with st.spinner("Analyzing..."):
                import websec
                st.session_state.res = websec.full_scan(target_url, timeout)
    
    if "res" in st.session_state:
        res = st.session_state.res
        m1, m2, m3 = st.columns(3)
        m1.metric("Score", f"{res['metrics']['score']}/100")
        m2.metric("Vulns", res['metrics']['vuln_count'])
        m3.metric("Time", f"{res['metrics']['scan_time']}s")
        
        if res['vulnerabilities']: st.error(f"🚨 Issues: {', '.join(res['vulnerabilities'])}")
        else: st.success("✅ Secure")
        
        with st.expander("Report (RU)", expanded=True): st.info(res['ai_analysis']['ru'])
        
        if 'reports' in res:
            st.download_button("📄 RU Report", res['reports']['ru_md'], "report.md")

# ════════════════ TAB 2: FAKENEWS ════════════════
with tab2:
    st.subheader("📰 FakeNews Detector")
    news_text = st.text_area("Paste news text...", height=200)
    if st.button("🤖 Analyze Credibility"):
         st.info("GigaChat module loading...")

# ════════════════ TAB 3: EXTENSIONS (НОВОЕ!) ════════════════
with tab3:
    st.subheader("🧩 Browser Extension Scanner (.crx / .zip)")
    st.markdown("Analyze extensions for **Crypto Drainers**, **Keyloggers**, and **Seed Phrase Leaks**.")
    
    uploaded_file = st.file_uploader("Upload extension file", type=["crx", "zip"])
    
    if uploaded_file and st.button("🛡️ Scan Extension", type="primary"):
        with st.spinner("Unpacking and analyzing code signatures..."):
            try:
                import websec
                # Запускаем сканер
                results = websec.scan_extension(uploaded_file)
                
                # Метрики
                col_crit, col_high, col_safe = st.columns(3)
                col_crit.metric("Critical Threats", results['critical'], delta_color="inverse")
                col_high.metric("High Risks", results['high'], delta_color="inverse")
                
                # Вердикт
                if results['critical'] > 0:
                    st.error("🚨 MALICIOUS EXTENSION DETECTED! (Wallet Drainer / Keylogger)")
                    col_safe.metric("Verdict", "MALICIOUS", "⛔")
                elif results['high'] > 0:
                    st.warning("⚠️ Suspicious Code Found")
                    col_safe.metric("Verdict", "SUSPICIOUS", "⚠️")
                else:
                    st.success("✅ No obvious threats found")
                    col_safe.metric("Verdict", "SAFE", "✅")
                
                # Детали угроз
                if results['threats']:
                    st.markdown("### 🕵️ Detected Signatures:")
                    for threat in results['threats']:
                        if "CRITICAL" in threat or "🚨" in threat:
                            st.error(threat)
                        elif "HIGH" in threat:
                            st.warning(threat)
                        else:
                            st.info(threat)
                            
            except Exception as e:
                st.error(f"❌ Scan error: {e}")

# ════════════════ TAB 4: AI IMAGES ════════════════
with tab4:
    st.subheader("🖼️ AI Image Detector")
    st.file_uploader("Upload Image", type=["jpg", "png"])

# ════════════════ TAB 5: CRYPTO ════════════════
with tab5:
    st.subheader("₿ Crypto Wallet Scanner")
    st.info("Feature coming soon")

# ════════════════ TAB 6: DASHBOARD ════════════════
with tab6:
    st.markdown("### 📊 System Dashboard")
    st.success("All systems operational.")

# ── FOOTER ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("<div style='text-align: center; color: gray;'>© 2026 WebSecAI</div>", unsafe_allow_html=True)
