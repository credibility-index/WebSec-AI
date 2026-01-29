import streamlit as st
import os
import importlib
import json
import re
from datetime import datetime
from PIL import Image

st.set_page_config(page_title="🛡️ WebSecAI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.title("🛡️ **WebSecAI Suite v3.0** *Full Lazy Loading*")

# ── SIDEBAR: API Keys ─────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔑 **API Configuration**")
    
    # OpenRouter
    or_key = st.text_input("🔓 OpenRouter", type="password", help="Для AI анализа уязвимостей")
    if or_key:
        os.environ["OPENROUTER_API_KEY"] = or_key
    
    # GigaChat
    gc_key = st.text_input("🤖 GigaChat", type="password", help="secrets.toml или здесь")
    if gc_key:
        st.secrets["GIGACHAT_API_KEY"] = gc_key
    
    st.markdown("---")
    st.caption("👨‍💻 Moscow Cybersecurity 2026")

# ── TABS: Полный функционал ────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔒 Web Security", "📰 FakeNews", "🖼️ AI Images", 
    "₿ Crypto", "📊 Dashboard"
])

# ════════════════ TAB 1: WEB SECURITY (Lazy) ════════════════
with tab1:
    st.markdown("### 🎯 **OWASP Top 10** *Lazy Scanners*")
    
    col_url, col_timeout = st.columns([4, 1])
    url = col_url.text_input("Target:", "https://testphp.vulnweb.com")
    timeout = col_timeout.slider("Timeout", 3, 15, 5)
    
    # Кнопки сканеров
    st.markdown("### 🔍 **Scanners**")
    cols = st.columns(3)
    
    with cols[0]:
        if st.button("🔍 SQLi"): lazy_scan("SQLi", url)
    with cols[1]:
        if st.button("🔍 XSS"): lazy_scan("XSS", url)
    with cols[2]:
        if st.button("🔍 CSRF"): lazy_scan("CSRF", url)
    
    cols2 = st.columns(2)
    with cols2[0]:
        if st.button("🔍 SSRF"): lazy_scan("SSRF", url)
    with cols2[1]:
        if st.button("🌐 Network"): lazy_scan("Network", url)
    
    if st.button("🚀 FULL SCAN", type="primary"):
        lazy_full_scan(url, timeout)

# ════════════════ TAB 2: FAKENEWS (GigaChat) ════════════════
with tab2:
    st.markdown("### 📰 **FakeNews Detector**")
    news_text = st.text_area("📝 News text:", height=250)
    
    if st.button("🤖 ANALYZE CREDIBILITY", type="primary"):
        if news_text.strip():
            lazy_fakenews(news_text)
        else:
            st.warning("📝 Enter text!")

# ════════════════ TAB 3: AI IMAGES ════════════════
with tab3:
    st.markdown("### 🖼️ **AI Image Detector**")
    uploaded = st.file_uploader("📁 Upload image", type=['png','jpg','jpeg'])
    
    if uploaded:
        image = Image.open(uploaded)
        st.image(image, caption="Uploaded", use_column_width=True)
        
        if st.button("🤖 DETECT AI", type="primary"):
            lazy_ai_image(image)

# ════════════════ TAB 4: CRYPTO ════════════════
with tab4:
    st.markdown("### ₿ **Crypto Risk Scanner**")
    wallet = st.text_area("Wallet address:", height=100)
    
    if st.button("🔍 SCAN WALLET", type="primary"):
        if wallet.strip():
            st.info("🔄 Crypto scanner coming soon...")
        else:
            st.warning("Enter wallet!")

# ════════════════ TAB 5: DASHBOARD ════════════════
with tab5:
    st.markdown("""
    # 📊 **WebSecAI v3.0** 
    
    **Web Security:**
    • 5 OWASP scanners
    • OpenRouter AI analysis
    • Auto-reports EN/RU/JSON
    
    **FakeNews:**
    • GigaChat Pro credibility
    • JSON structured output
    
    **AI Images:**
    • Transformers detector
    • Midjourney/DALL-E/Real
    
    **🔄 Lazy Loading:**
    ```
    websec.py     → Click to load
    gigachat      → Click to load  
    transformers  → Click to load
    ```
    """)

# ── LAZY FUNCTIONS (загружаются по требованию) ────────────────────────────────
def lazy_scan(scanner_type: str, url: str):
    """Запуск сканера"""
    with st.spinner(f"Loading {scanner_type}..."):
        try:
            import websec
            if scanner_type == "SQLi":
                result = websec.scan_single(url, "SQLi", websec.scan_sql_injection)
            elif scanner_type == "XSS":
                result = websec.scan_single(url, "XSS", websec.scan_xss)
            elif scanner_type == "CSRF":
                result = websec.scan_single(url, "CSRF", websec.check_csrf_protection)
            elif scanner_type == "SSRF":
                result = websec.scan_single(url, "SSRF", websec.scan_ssrf)
            elif scanner_type == "Network":
                result = websec.scan_single(url, "Network", websec.scan_network_segmentation)
            
            st.success("🟢 OK" if not result else f"🟡 HIT {scanner_type}!")
            st.balloons()
            
        except Exception as e:
            st.error(f"❌ {scanner_type}: {e}")

def lazy_full_scan(url: str, timeout: float):
    """Полный скан"""
    with st.spinner("🔍 Full scan loading all scanners..."):
        try:
            import websec
            results = websec.full_scan(url, timeout=timeout)
            
            # Results
            st.success("✅ Full scan OK!")
            vulns = results["vulnerabilities"]
            metrics = results["metrics"]
            
            c1, c2, c3 = st.columns(3)
            c1.metric("⏱️", f"{metrics['scan_time']}s")
            c2.metric("🚨", len(vulns))
            c3.metric("🛡️", metrics["score"])
            
            st.markdown("### 📋 **Status**")
            for vuln in vulns:
                st.error(f"🔴 {vuln}")
            if not vulns:
                st.success("🟢 Clean!")
            
            st.markdown("### 🤖 **AI**")
            st.info(results["ai_analysis"]["ru"])
            
            ts = datetime.now().strftime("%Y%m%d_%H%M")
            st.download_button("📊 JSON", 
                             json.dumps(results, indent=2, ensure_ascii=False),
                             f"fullscan_{ts}.json")
                             
        except Exception as e:
            st.error(f"❌ Full scan: {e}")

def lazy_fakenews(text: str):
    """FakeNews анализ"""
    with st.spinner("🤖 GigaChat loading..."):
        try:
            from gigachat import GigaChat
            from gigachat.models import Chat
            
            gc = GigaChat(credentials=st.secrets.get("GIGACHAT_API_KEY") or "demo")
            prompt = f"Analyze credibility: {text[:1500]}\nJSON only."
            
            chat = Chat(messages=[{"role": "user", "content": prompt}])
            response = gc.chat(chat)
            
            result = response.choices[0].message.content
            st.json(result)
            
        except Exception as e:
            st.error(f"❌ FakeNews: {e}")

def lazy_ai_image(image):
    """AI image detector"""
    with st.spinner("🤖 Transformers loading..."):
        try:
            from transformers import pipeline
            detector = pipeline("image-classification", model="umm-maybe/AI-image-detector")
            results = detector(image)
            
            ai_prob = max([r['score'] for r in results if 'fake' in r['label'].lower()] or [0.5])
            st.metric("🤖 AI Prob", f"{ai_prob:.1%}")
            st.json(results[:3])
            
        except Exception as e:
            st.error(f"❌ AI Image: {e}")

# ── END ───────────────────────────────────────────────────────────────────────
st.markdown("*© WebSecAI 2026*")
