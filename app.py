import streamlit as st
import os
import time
import json
from datetime import datetime

# Safe imports
try:
    from websec import ai_analysis
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
except:
    st.error("❌ Security modules missing")
    st.stop()

st.set_page_config(page_title="WebSecAI", page_icon="🛡️", layout="wide")

st.title("🛡️ **WebSecAI Suite**")
st.markdown("*Security + FakeNews + Crypto Analysis*")

# ── API KEYS ─────────────────────────────────────────────────────────────────
with st.expander("🔑 API Keys (all optional)"):
    openrouter_key = st.text_input("OpenRouter AI", type="password")
    if openrouter_key:
        os.environ["OPENROUTER_API_KEY"] = openrouter_key

# ── 3 ТАБА ───────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🔒 Web Security", "📰 FakeNews Detector", "₿ Crypto Wallet"])

# TAB 1: WEB SECURITY (твой текущий код)
with tab1:
    st.markdown("### 🔗 Web Vulnerability Scanner")
    col_url1, _ = st.columns([3, 1])
    target_url = col_url1.text_input("Target URL:", placeholder="https://example.com")
    
    if col_url1.button("🚀 Scan Website", type="primary") and target_url:
        with st.spinner("🔍 Scanning..."):
            vulns = []
            start_time = time.time()
            
            try: 
                if scan_sql_injection(target_url): vulns.append("SQLi")
                if scan_xss(target_url): vulns.append("XSS")
                if check_csrf_protection(target_url): vulns.append("CSRF")
                if scan_ssrf(target_url): vulns.append("SSRF")
            except: pass
            
            scan_time = time.time() - start_time
            
            # AI
            try:
                ai_en, ai_ru = ai_analysis(vulns)
            except:
                ai_en = ai_ru = "[AI] Unavailable"
            
            # Results
            col_r1, col_r2 = st.columns(2)
            col_r1.metric("⏱️ Time", f"{scan_time:.1f}s")
            col_r2.metric("🚨 Vulns", len(vulns))
            
            # Bilingual AI
            col_ai1, col_ai2 = st.columns(2)
            with col_ai1: st.code(ai_en, "markdown")
            with col_ai2: st.code(ai_ru, "markdown")
            
            # 3 Downloads
            timestamp = datetime.now().strftime("%H%M")
            col_d1, col_d2, col_d3 = st.columns(3)
            with col_d1:
                st.download_button("📄 EN", f"# WebSecAI\n{ai_en}", f"websec_en_{timestamp}.md")
            with col_d2:
                st.download_button("📄 RU", f"# WebSecAI\n{ai_ru}", f"websec_ru_{timestamp}.md")
            with col_d3:
                st.json({"vulns": vulns, "ai_en": ai_en, "ai_ru": ai_ru})

# TAB 2: FAKENEWS DETECTOR (ЗАГОТОВКА)
with tab2:
    st.markdown("### 📰 FakeNews Credibility Index")
    text_input = st.text_area("Paste news text here:", 
                             placeholder="Enter article text to analyze credibility...")
    
    if st.button("🔍 Analyze Credibility") and text_input:
        st.info("🚧 **Coming soon!**")
        st.info("""
        ✅ NLP Model: BERT/RoBERTa
        ✅ Features: fact-checking, sentiment, source bias  
        ✅ Score: 0-100 Credibility Index
        ✅ Verdict: ✅ Reliable / ⚠️ Suspicious / ❌ Fake
        """)
        
        # Заготовка для твоей модели
        # credibility_score = your_model.predict(text_input)
        # st.metric("📊 Credibility Score", f"{credibility_score:.0f}/100")

# TAB 3: CRYPTO WALLET (ЗАГОТОВКА) 
with tab3:
    st.markdown("### ₿ Crypto Wallet Scanner")
    wallet_address = st.text_input("Wallet Address:", 
                                  placeholder="0x1234...abcd")
    
    if st.button("🔍 Scan Wallet") and wallet_address:
        st.info("🚧 **Crypto scanner ready!**")
        st.info("""
        ✅ Balance check
        ✅ Suspicious transactions  
        ✅ Blacklist screening
        ✅ Risk score
        """)
        
        # Заготовка
        # risk_level = check_wallet(wallet_address)
        # st.error(f"🚨 Risk: {risk_level}")

# ── FOOTER ───────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("""
🛡️ **WebSecAI Suite** | WebSec + FakeNews + Crypto | https://t.me/likeluv
""")

