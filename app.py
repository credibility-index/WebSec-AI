import streamlit as st
import os
import json
import time
from datetime import datetime
from PIL import Image

# Настройка страницы
st.set_page_config(page_title="🛡️ WebSecAI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.title("🛡️ **WebSecAI Suite v3.1**")
st.markdown("*Full Security Suite • OWASP • FakeNews • AI Images*")

# ── SIDEBAR: API Keys ─────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔑 **Configuration**")
    
    # OpenRouter
    or_key = st.text_input("OpenRouter Key", type="password", help="For AI Vulnerability Analysis")
    if or_key:
        os.environ["OPENROUTER_API_KEY"] = or_key
    
    # GigaChat
    gc_key = st.text_input("GigaChat Key", type="password", help="For FakeNews Detection")
    if gc_key:
        st.secrets["GIGACHAT_API_KEY"] = gc_key # Используем secrets для GigaChat
    
    st.info("ℹ️ Modules are loaded on demand.")
    st.markdown("---")
    st.caption("👨‍💻 Moscow Cybersecurity Lab 2026")

# ── TABS ───────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔒 Web Security", "📰 FakeNews", "🖼️ AI Images", 
    "₿ Crypto", "📊 Dashboard"
])

# ════════════════ TAB 1: WEB SECURITY (OwASP) ════════════════
with tab1:
    st.subheader("🎯 OWASP Top 10 Scanner")
    
    col_url, col_to = st.columns([3, 1])
    target_url = col_url.text_input("Target URL", "http://testphp.vulnweb.com")
    timeout = col_to.slider("Timeout", 3, 15, 5)
    
    st.divider()

    # --- Individual Scanners ---
    st.markdown("#### ⚡ Quick Scans")
    c1, c2, c3, c4, c5 = st.columns(5)
    
    # Функция-обертка для запуска
    def run_single_scan(name, scan_type):
        if not target_url:
            st.warning("Enter URL first!")
            return
        
        with st.spinner(f"Loading {name}..."):
            try:
                import websec # ЛЕНИВЫЙ ИМПОРТ ЗДЕСЬ
                
                start_time = time.time()
                detected = False
                
                if scan_type == "SQLi":
                    detected = websec.scan_sql_injection(target_url)
                elif scan_type == "XSS":
                    detected = websec.scan_xss(target_url)
                elif scan_type == "CSRF":
                    detected = websec.check_csrf_protection(target_url)
                elif scan_type == "SSRF":
                    detected = websec.scan_ssrf(target_url)
                elif scan_type == "Network":
                    res = websec.scan_network_segmentation(target_url)
                    detected = len(res) > 0
                
                duration = time.time() - start_time
                
                if detected:
                    st.error(f"🔴 {name}: DETECTED ({duration:.1f}s)")
                else:
                    st.success(f"🟢 {name}: Clean ({duration:.1f}s)")
                    
            except ImportError:
                st.error("❌ 'websec.py' not found!")
            except Exception as e:
                st.error(f"❌ Error: {e}")

    if c1.button("🔍 SQLi"): run_single_scan("SQL Injection", "SQLi")
    if c2.button("🔍 XSS"): run_single_scan("XSS", "XSS")
    if c3.button("🔍 CSRF"): run_single_scan("CSRF", "CSRF")
    if c4.button("🔍 SSRF"): run_single_scan("SSRF", "SSRF")
    if c5.button("🌐 Network"): run_single_scan("Network", "Network")
    
    st.divider()

    # --- Full Scan ---
    if st.button("🚀 LAUNCH FULL AUDIT", type="primary", use_container_width=True):
        if not target_url:
            st.warning("Please enter a target URL.")
        else:
            with st.spinner("Running comprehensive analysis..."):
                try:
                    import websec
                    results = websec.full_scan(target_url, timeout)
                    
                    # Метрики
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Security Score", f"{results['metrics']['score']}/100")
                    m2.metric("Vulns Found", results['metrics']['vuln_count'])
                    m3.metric("Scan Time", f"{results['metrics']['scan_time']}s")
                    
                    # Список уязвимостей
                    if results['vulnerabilities']:
                        st.error(f"🚨 Issues Detected: {', '.join(results['vulnerabilities'])}")
                    else:
                        st.success("✅ System appears secure.")
                    
                    # AI Анализ
                    st.markdown("#### 🤖 AI Security Analysis")
                    with st.expander("🇺🇸 English Report", expanded=True):
                        st.info(results['ai_analysis']['en'])
                    with st.expander("🇷🇺 Russian Report", expanded=True):
                        st.info(results['ai_analysis']['ru'])
                    
                    # Скачивание отчетов (НОВОЕ!)
                    st.markdown("#### 📥 Download Professional Reports")
                    d1, d2, d3 = st.columns(3)
                    
                    # Проверяем, есть ли готовые отчеты в results (из нового websec.py)
                    if 'reports' in results:
                        d1.download_button("📄 English Report (MD)", results['reports']['en_md'], f"report_en_{int(time.time())}.md")
                        d2.download_button("📄 Russian Report (MD)", results['reports']['ru_md'], f"report_ru_{int(time.time())}.md")
                    
                    d3.download_button("💾 Raw JSON Data", json.dumps(results, indent=2, ensure_ascii=False), f"data_{int(time.time())}.json")
                    
                except ImportError:
                    st.error("❌ Critical: 'websec.py' module not found.")
                except Exception as e:
                    st.error(f"❌ Scan failed: {e}")


# ════════════════ TAB 2: FAKENEWS ════════════════
with tab2:
    st.subheader("📰 FakeNews Detector")
    news_text = st.text_area("Paste news text here...", height=200)
    
    if st.button("🤖 Analyze Credibility", type="primary"):
        if not news_text.strip():
            st.warning("Enter text first!")
        else:
            with st.spinner("Analyzing with GigaChat..."):
                # Тут можно вызвать функцию из websec, если она там есть, или заглушку
                # Для примера - ленивая заглушка, т.к. логика GigaChat пока не перенесена в websec.py
                try:
                    from gigachat import GigaChat
                    st.info("GigaChat module loading...")
                    # ... logic ...
                    st.success("Analysis complete (Demo)")
                except ImportError:
                    st.warning("GigaChat library not installed. Install via `pip install gigachat`")


# ════════════════ TAB 3: AI IMAGES ════════════════
with tab3:
    st.subheader("🖼️ AI Image Detector")
    uploaded = st.file_uploader("Upload Image", type=["jpg", "png", "jpeg"])
    
    if uploaded and st.button("Detect AI"):
        with st.spinner("Loading Transformers model..."):
             try:
                 from transformers import pipeline
                 image = Image.open(uploaded)
                 st.info("Model loaded. Analyzing...")
                 # ... logic ...
                 st.success("Detection complete (Demo)")
             except ImportError:
                 st.warning("Transformers library not installed.")

# ════════════════ TAB 4: CRYPTO ════════════════
with tab4:
    st.subheader("₿ Crypto Wallet Scanner")
    st.info("Feature coming in v3.2")

# ════════════════ TAB 5: DASHBOARD ════════════════
with tab5:
    st.markdown("""
    ### 📊 System Dashboard
    
    **Active Modules:**
    - ✅ **WebSec Core:** Lazy Loaded
    - ✅ **AI Reports:** OpenRouter Integration
    - ⏳ **FakeNews:** GigaChat (Pending)
    - ⏳ **AI Images:** Transformers (Pending)
    
    **Performance:**
    - Startup Time: < 1s (Lazy Loading)
    - Memory Usage: Optimized
    """)

# ── FOOTER ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("<div style='text-align: center; color: gray;'>© 2026 WebSecAI • Ethical Hacking Tool</div>", unsafe_allow_html=True)
