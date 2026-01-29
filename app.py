import streamlit as st
import os
import time
import json
import re
from datetime import datetime
from PIL import Image

# ✅ Ленивая загрузка websec
try:
    from websec import full_scan, scan_single, scan_sql_injection, scan_xss, check_csrf_protection, scan_ssrf, scan_network_segmentation, ai_analysis
    st.success("✅ WebSecAI modules loaded (lazy)")
except ImportError as e:
    st.warning(f"⚠️ WebSecAI unavailable: {e}")
    st.info("🔧 pip install -r requirements.txt && python websec.py")

# Глобальное кэширование
@st.cache_resource
def load_gigachat():
    try:
        from gigachat import GigaChat
        return GigaChat(credentials=st.secrets["GIGACHAT_API_KEY"], verify_ssl_certs=False)
    except:
        return None

@st.cache_resource
def load_ai_detector():
    try:
        from transformers import pipeline
        return pipeline("image-classification", model="umm-maybe/AI-image-detector")
    except:
        return None

st.set_page_config(page_title="🛡️ WebSecAI", page_icon="🛡️", layout="wide")

st.title("🛡️ **WebSecAI Suite v2.1**")
st.markdown("*OWASP Top 10 • FakeNews • AI Images • Lazy Scanners*")

# ── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔑 **API Keys**")
    openrouter_key = st.text_input("OpenRouter API", type="password")
    if openrouter_key:
        os.environ["OPENROUTER_API_KEY"] = openrouter_key
    
    st.markdown("### 🚀 **Status**")
    st.markdown("""
    ✅ Lazy scanners: SQLi, XSS, CSRF, SSRF, Network  
    ✅ OpenRouter AI analysis
    ✅ Individual buttons
    """)
    
    if st.button("🧪 Test WebSec"):
        try:
            detected = scan_sql_injection("test")
            st.success("✅ WebSec OK!")
        except:
            st.error("❌ WebSec not ready")

# ── TABS ─────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔒 Web Security", "📰 FakeNews", "🖼️ AI Images", "₿ Crypto", "ℹ️ Dashboard"])

# TAB 1: WEB SECURITY ✅
with tab1:
    st.markdown("### 🔗 **OWASP Scanner** *Lazy Loading* ⚡")
    
    col_url, col_timeout = st.columns([3, 1])
    url = col_url.text_input("🎯 Target:", placeholder="https://testphp.vulnweb.com/listproducts.php?cat=1")
    timeout_sec = col_timeout.slider("⏱️ Timeout", 3, 10, 5)
    
    col_full, col_single = st.columns(2)
    
    # Полный скан
    if col_full.button("🚀 **Full Scan**", type="primary", use_container_width=True) and url:
        with st.spinner("🔍 Full scanning..."):
            try:
                results = full_scan(url, timeout=float(timeout_sec))
                show_results(results)
            except Exception as e:
                st.error(f"❌ Full scan error: {e}")
    
    # Кнопки по отдельности
    st.markdown("### 📱 **Individual Scanners**")
    cols1 = st.columns(3)
    with cols1[0]:
        if st.button("🔍 **SQLi**"): 
            detected = scan_single(url or "test", "SQLi", scan_sql_injection)
            st.balloons()
    
    with cols1[1]:
        if st.button("🔍 **XSS**"): 
            detected = scan_single(url or "test", "XSS", scan_xss)
            st.balloons()
    
    with cols1[2]:
        if st.button("🔍 **CSRF**"): 
            detected = scan_single(url or "test", "CSRF", check_csrf_protection)
            st.balloons()
    
    cols2 = st.columns(2)
    with cols2[0]:
        if st.button("🔍 **SSRF**"): 
            detected = scan_single(url or "test", "SSRF", scan_ssrf)
            st.balloons()
    
    with cols2[1]:
        if st.button("🌐 **Network**"): 
            detected = scan_single(url or "test", "Network", scan_network_segmentation)
            st.balloons()

def show_results(results):
    """Показ результатов"""
    st.success("✅ Scan complete!")
    vulns = results["vulnerabilities"]
    metrics = results["metrics"]
    
    # Метрики
    col1, col2, col3 = st.columns(3)
    col1.metric("⏱️ Time", f"{metrics['scan_time']}s")
    col2.metric("🚨 Vulns", len(vulns))
    col3.metric("🛡️ Score", metrics["score"])
    
    # Статус
    st.markdown("### 📋 **Results**")
    for vuln in ["SQLi", "XSS", "CSRF", "SSRF", "Network"]:
        status = "🔴 HIT" if vuln in vulns else "🟢 OK"
        st.markdown(f"**{vuln}:** {status}")
    
    # AI
    st.markdown("### 🤖 **AI Analysis**")
    col_en, col_ru = st.columns(2)
    with col_en:
        st.info(results["ai_analysis"]["en"])
    with col_ru:
        st.info(results["ai_analysis"]["ru"])
    
    # Reports
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    try:
        st.download_button("📄 EN", open(f"reports/en_{ts}.md").read(), f"en_{ts}.md")
        st.download_button("📄 RU", open(f"reports/ru_{ts}.md").read(), f"ru_{ts}.md")
    except:
        st.info("📁 Check ./reports/")
    st.download_button("📊 JSON", json.dumps(results, indent=2, ensure_ascii=False), f"websec_{ts}.json")

# TAB 2: FAKENEWS ✅
with tab2:
    st.markdown("### 📰 **FakeNews Detector**")
    news_text = st.text_area("📝 News text:", height=250)
    
    if st.button("🚀 **Analyze**", type="primary") and news_text.strip():
        gigachat = load_gigachat()
        if gigachat:
            with st.spinner("🤖 Analyzing..."):
                try:
                    from gigachat.models import Chat
                    prompt = f"Analyze credibility of: {news_text[:1500]}\nReply JSON only."
                    chat = Chat(messages=[{"role": "user", "content": prompt}])
                    response = gigachat.chat(chat)
                    st.json(response.choices[0].message.content)
                except Exception as e:
                    st.error(f"❌ {e}")
        else:
            st.warning("❌ GigaChat key missing")

# TAB 3: AI IMAGES ✅
with tab3:
    st.markdown("### 🖼️ **AI Image Detector**")
    uploaded = st.file_uploader("Upload image")
    
    if uploaded:
        image = Image.open(uploaded)
        st.image(image, use_column_width=True)
        
        if st.button("🤖 **Detect AI**"):
            detector = load_ai_detector()
            if detector:
                with st.spinner("Analyzing..."):
                    results = detector(image)
                    ai_prob = max([r['score'] for r in results if 'fake' in r['label'].lower()] or [0.5])
                    st.metric("🤖 AI Probability", f"{ai_prob:.1%}")
                    st.json(results)
            else:
                st.error("Install transformers")

# TAB 4: CRYPTO ✅
with tab4:
    st.markdown("### ₿ **Crypto Scanner**")
    st.info("🔄 Coming soon...")

# TAB 5: DASHBOARD ✅
with tab5:
    st.markdown("""
    # 🛡️ **WebSecAI v2.1** ✅ READY!
    
    **✅ Features:**
    • 5 Lazy OWASP scanners
    • OpenRouter AI analysis  
    • Individual buttons
    • Auto-reports EN/RU/JSON
    
    **🎯 Launch:**
    ```
    export OPENROUTER_API_KEY="sk-or-..."
    streamlit run app.py
    ```
    """)
