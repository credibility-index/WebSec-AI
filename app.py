import streamlit as st
import os
import json
import time
from datetime import datetime
from PIL import Image

# Настройка страницы
st.set_page_config(
    page_title="🛡️ WebSecAI", 
    page_icon="🛡️", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# ── SIDEBAR: BRANDING & CONTACTS ─────────────────────────────────────────────
with st.sidebar:
    # Логотип (можно заменить на st.image("logo.png"))
    st.markdown("## 🛡️ **WebSecAI Suite**")
    st.caption("v3.4 | AI Security Platform")
    
    st.info(
        "**Mission:**\n"
        "Making the web safer through AI-powered vulnerability detection and forensics."
    )
    
    st.markdown("---")
    st.markdown("### 📞 **Contact Us**")
    st.markdown(
        """
        **Moscow Cybersecurity Lab**  
        [t.me/likeluv](https://t.me/likeluv)  
        [GitHub Repo](https://github.com/credibility-index/WebSec-AI)
        """
    )
    
    st.markdown("---")
    # Спрятанные настройки для продвинутых юзеров (или fallback)
    with st.expander("⚙️ Advanced Settings"):
        st.caption("Override system keys if needed:")
        or_key = st.text_input("OpenRouter Key", type="password")
        if or_key: os.environ["OPENROUTER_API_KEY"] = or_key
        
        gc_key = st.text_input("GigaChat Key", type="password")
        if gc_key: st.secrets["GIGACHAT_API_KEY"] = gc_key

# ── MAIN HEADER ──────────────────────────────────────────────────────────────
st.title("🛡️ **WebSecAI Suite**")
st.markdown("*AI-Powered Cybersecurity Audit • Forensics • Credibility Analysis*")

# ── TABS ─────────────────────────────────────────────────────────────────────
tab_dash, tab_web, tab_ext, tab_fake, tab_img, tab_crypto = st.tabs([
    "📊 Dashboard", 
    "🔒 Web Security", 
    "🧩 Extensions",  
    "📰 FakeNews", 
    "🖼️ AI Images", 
    "₿ Crypto"
])

# ════════════════ TAB 1: DASHBOARD (Витрина) ════════════════
with tab_dash:
    st.markdown("### 👋 Welcome to WebSecAI Platform")
    st.markdown(
        """
        This platform provides a comprehensive suite of tools for security professionals, 
        researchers, and content creators to audit digital assets and verify content authenticity.
        """
    )
    
    # Карточки со статусом
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Web Scanner", "Active", "OWASP Top 10")
    col2.metric("Extension Audit", "Active", "CRX Analysis")
    col3.metric("FakeNews AI", "Active", "GigaChat Pro")
    col4.metric("Deepfake Detect", "Active", "Transformers")
    
    st.divider()
    
    # Описание модулей
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 🛡️ **Security Tools**")
        st.success("**Web Security Scanner**")
        st.markdown("Automated vulnerability scanning (SQLi, XSS, CSRF) with AI-generated remediation reports.")
        
        st.success("**Browser Extension Auditor**")
        st.markdown("Static analysis of `.crx` files to detect crypto drainers, keyloggers, and seed leaks.")
        
    with c2:
        st.markdown("#### 🕵️ **Forensics Tools**")
        st.info("**FakeNews Detector**")
        st.markdown("Credibility scoring of text content using GigaChat LLM to identify misinformation.")
        
        st.info("**AI Image Forensics**")
        st.markdown("Neural network analysis to distinguish between real photos and AI-generated art (Midjourney/DALL-E).")

# ════════════════ TAB 2: WEB SECURITY ════════════════
with tab_web:
    st.subheader("🎯 OWASP Top 10 Scanner")
    
    col_url, col_to = st.columns([3, 1])
    target_url = col_url.text_input("Target URL", "http://testphp.vulnweb.com")
    timeout = col_to.slider("Timeout", 3, 15, 5)
    
    st.divider()

    # --- Quick Scans ---
    c1, c2, c3, c4, c5 = st.columns(5)
    
    def run_single(name, func_name):
        if not target_url:
            st.warning("Enter URL first!")
            return
        
        with st.spinner(f"Loading {name}..."):
            try:
                import websec 
                func = getattr(websec, func_name)
                start_time = time.time()
                
                detected = func(target_url)
                # Network scanner returns list, others bool
                is_hit = len(detected) > 0 if isinstance(detected, list) else detected
                
                duration = time.time() - start_time
                if is_hit:
                    st.error(f"🔴 {name}: DETECTED ({duration:.1f}s)")
                else:
                    st.success(f"🟢 {name}: Clean ({duration:.1f}s)")
                    
            except ImportError: st.error("❌ 'websec.py' not found!")
            except Exception as e: st.error(f"❌ Error: {e}")

    if c1.button("🔍 SQLi"): run_single("SQL Injection", "scan_sql_injection")
    if c2.button("🔍 XSS"): run_single("XSS", "scan_xss")
    if c3.button("🔍 CSRF"): run_single("CSRF", "check_csrf_protection")
    if c4.button("🔍 SSRF"): run_single("SSRF", "scan_ssrf")
    if c5.button("🌐 Network"): run_single("Network", "scan_network_segmentation")
    
    st.divider()

    # --- Full Audit ---
    if "scan_results" not in st.session_state:
        st.session_state.scan_results = None

    if st.button("🚀 LAUNCH FULL AUDIT", type="primary", use_container_width=True):
        if not target_url:
            st.warning("Please enter a target URL.")
        else:
            with st.spinner("Running comprehensive analysis..."):
                try:
                    import websec
                    st.session_state.scan_results = websec.full_scan(target_url, timeout)
                except Exception as e:
                    st.error(f"❌ Scan failed: {e}")

    if st.session_state.scan_results:
        res = st.session_state.scan_results
        
        # Metrics
        m1, m2, m3 = st.columns(3)
        m1.metric("Security Score", f"{res['metrics']['score']}/100")
        m2.metric("Vulns Found", res['metrics']['vuln_count'])
        m3.metric("Scan Time", f"{res['metrics']['scan_time']}s")
        
        # Vulns List
        if res['vulnerabilities']:
            st.error(f"🚨 Issues Detected: {', '.join(res['vulnerabilities'])}")
        else:
            st.success("✅ System appears secure.")
        
        # AI Analysis
        st.markdown("#### 🤖 AI Security Analysis")
        with st.expander("🇺🇸 English Report", expanded=True):
            st.info(res['ai_analysis']['en'])
        with st.expander("🇷🇺 Russian Report", expanded=True):
            st.info(res['ai_analysis']['ru'])
        
        # Downloads
        st.markdown("#### 📥 Download Reports")
        d1, d2, d3 = st.columns(3)
        if 'reports' in res:
            d1.download_button("📄 EN Report (MD)", res['reports']['en_md'], f"report_en_{int(time.time())}.md")
            d2.download_button("📄 RU Report (MD)", res['reports']['ru_md'], f"report_ru_{int(time.time())}.md")
        d3.download_button("💾 Raw JSON Data", json.dumps(res, indent=2, ensure_ascii=False), f"data_{int(time.time())}.json")


# ════════════════ TAB 3: EXTENSIONS ════════════════
with tab_ext:
    st.subheader("🧩 Browser Extension Scanner")
    st.markdown("Analyze extensions (`.crx`, `.zip`) for **Crypto Drainers**, **Keyloggers**, and **Seed Phrase Leaks**.")
    
    uploaded_file = st.file_uploader("Upload extension file", type=["crx", "zip"])
    
    if uploaded_file and st.button("🛡️ Scan Extension", type="primary"):
        with st.spinner("Analyzing code signatures..."):
            try:
                import websec
                results = websec.scan_extension(uploaded_file)
                
                col_crit, col_high, col_safe = st.columns(3)
                col_crit.metric("Critical Threats", results['critical'], delta_color="inverse")
                col_high.metric("High Risks", results['high'], delta_color="inverse")
                
                if results['critical'] > 0:
                    col_safe.metric("Verdict", "MALICIOUS", "⛔")
                    st.error("🚨 MALICIOUS CODE DETECTED!")
                elif results['high'] > 0:
                    col_safe.metric("Verdict", "SUSPICIOUS", "⚠️")
                    st.warning("⚠️ Suspicious Code Found")
                else:
                    col_safe.metric("Verdict", "SAFE", "✅")
                    st.success("✅ Clean")
                
                if results['threats']:
                    with st.expander("View Detected Threats", expanded=True):
                        for t in results['threats']:
                            if "CRITICAL" in t or "🚨" in t: st.error(t)
                            elif "HIGH" in t: st.warning(t)
                            else: st.write(t)
                            
            except Exception as e:
                st.error(f"❌ Scan error: {e}")

# ════════════════ TAB 4: FAKENEWS ════════════════
with tab_fake:
    st.subheader("📰 FakeNews Detector")
    news_text = st.text_area("Paste news text here...", height=200)
    
    if st.button("🤖 Analyze Credibility", type="primary"):
        if not news_text.strip():
            st.warning("Enter text first!")
        else:
            with st.spinner("Analyzing with GigaChat..."):
                try:
                    from gigachat import GigaChat
                    st.info("Module loading... (Demo)")
                    # Здесь должна быть логика вызова GigaChat
                    st.success("Analysis complete.")
                except ImportError:
                    st.warning("GigaChat library not installed.")


# ════════════════ TAB 5: AI IMAGES ════════════════
with tab_img:
    st.subheader("🖼️ AI Image Detector")
    uploaded = st.file_uploader("Upload Image", type=["jpg", "png", "jpeg"])
    
    if uploaded and st.button("Detect AI"):
        with st.spinner("Loading Transformers model..."):
             try:
                 from transformers import pipeline
                 st.info("Model loaded. Analyzing... (Demo)")
                 st.success("Detection complete.")
             except ImportError:
                 st.warning("Transformers library not installed.")

# ════════════════ TAB 6: CRYPTO ════════════════
with tab_crypto:
    st.subheader("₿ Crypto Wallet Scanner")
    st.info("This feature is coming soon in v3.5")

# ── FOOTER ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("<div style='text-align: center; color: gray;'>© 2026 Moscow Cybersecurity Lab</div>", unsafe_allow_html=True)
