import streamlit as st
import requests
import re
import os
import tempfile
import logging
import time
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def safe_import():
    try:
        from websec import ai_analysis
        from scanners.sql_scanner import scan_sql_injection
        from scanners.xss import scan_xss
        from scanners.csrf_scanner import check_csrf_protection
        from scanners.ssrf_scanner import scan_ssrf
        from scanners.crypto_scanner import check_wallet  # Только wallet!
        logger.info("✅ Wallet OK")
        return True, locals()
    except ImportError as e:
        st.error(f"❌ Сканеры недоступны: {e}")
        return False, None

loaded, modules = safe_import()
if not loaded:
    st.stop()

scan_sql_injection = modules['scan_sql_injection']
scan_xss = modules['scan_xss']
check_csrf_protection = modules['check_csrf_protection']
scan_ssrf = modules['scan_ssrf']
ai_analysis = modules['ai_analysis']

st.set_page_config(page_title="WebSecAI", page_icon="🛡️", layout="wide")
st.markdown('<style>.main {background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);}</style>', unsafe_allow_html=True)

col1, col2 = st.columns([3, 1])
target_url = col1.text_input("🔗 URL:", placeholder="https://example.com")

if col1.button("🚀 СКАНИРОВАТЬ", type="primary") and target_url:
    logger.info(f"Скан: {target_url}")
    start_time = time.time()
    vulnerabilities = []
    
    with st.spinner("🔍 SQLi..."):
        try:
            if scan_sql_injection(target_url):
                vulnerabilities.append("SQLi")
        except Exception as e:
            st.warning(f"SQLi: timeout/error - {str(e)[:100]}")
    
    with st.spinner("🔍 XSS..."):
        try:
            if scan_xss(target_url):
                vulnerabilities.append("XSS")
        except Exception as e:
            st.warning(f"XSS: timeout/error - {str(e)[:100]}")
    
    with st.spinner("🔍 CSRF..."):
        try:
            if check_csrf_protection(target_url):
                vulnerabilities.append("CSRF")
        except Exception as e:
            st.warning(f"CSRF: timeout/error - {str(e)[:100]}")
    
    with st.spinner("🔍 SSRF..."):
        try:
            if scan_ssrf(target_url):
                vulnerabilities.append("SSRF")
        except Exception as e:
            st.warning(f"SSRF: timeout/error - {str(e)[:100]}")
    
    end_time = time.time()
    
    col1.metric("⏱️ Время", f"{end_time-start_time:.1f}с")
    col1.metric("🚨 Vulns", len(vulnerabilities))
    
    if vulnerabilities:
        col1.error("🚨 Найдено!")
        for v in vulnerabilities:
            col1.error(f"• {v}")
    else:
        col1.success("✅ Чисто!")
    
    # AI всегда
    col2.markdown("**🤖 AI Рекомендации 🇷🇺**")
    try:
        ai_recs = ai_analysis(vulnerabilities or [target_url])
        col2.markdown(ai_recs.get('ru', 'AI недоступен'))
    except Exception as e:
        col2.warning(f"AI: {str(e)[:100]}")
    
    if col1.button("📥 JSON"):
        st.download_button(
            label="Скачать отчёт",
            data=json.dumps({
                "url": target_url,
                "vulns": vulnerabilities,
                "time": end_time - start_time,
                "ai": ai_recs if 'ai_recs' in locals() else 'N/A'
            }, ensure_ascii=False, indent=2),
            file_name=f"websec_{datetime.now().strftime('%d%m%y_%H%M')}.json",
            mime="application/json"
        )

# Tabs без crypto пока
tab1, tab2, tab3 = st.tabs(["📋 Results", "🔍 Other", "ℹ️ Info"])
with tab1: st.success("Результаты выше!")
with tab2: st.info("Дополнительные сканы скоро...")
with tab3: 
    st.markdown("""
    🛡️ **WebSecAI** — быстрый сканер OWASP Top 10  
    ✅ SQLi, XSS, CSRF, SSRF  
    🤖 OpenRouter AI анализ  
    t.me/likeluv
    """)

st.caption("🛡️ WebSecAI | https://t.me/likeluv")
