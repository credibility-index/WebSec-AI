import streamlit as st
import requests
import re
import os
import tempfile
import logging
import time
import json
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('websec_ai.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def safe_import():
    try:
        from websec import ai_analysis
        from scanners.sql_scanner import scan_sql_injection
        from scanners.xss import scan_xss
        from scanners.csrf_scanner import check_csrf_protection
        from scanners.ssrf_scanner import scan_ssrf
        from scanners.crypto_scanner import WebSecAIScanner, check_wallet
        logger.info("✅ Все сканеры OK")
        return True
    except ImportError as e:
        logger.error(f"❌ Импорт: {e}")
        st.error("Сканеры недоступны")
        return False

if not safe_import():
    st.stop()

st.set_page_config(page_title="WebSecAI", page_icon="🛡️", layout="wide")
st.markdown('<style>.main {background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);}</style>', unsafe_allow_html=True)

col1, col2 = st.columns([3, 1])
target_url = col1.text_input("🔗 URL:", placeholder="https://example.com")
if col1.button("🚀 СКАНИРОВАТЬ", type="primary") and target_url:
    logger.info(f"Скан: {target_url}")
    start_time = time.time()
    
    vulnerabilities = []
    
    sql_risk = scan_sql_injection(target_url)
    if sql_risk: vulnerabilities.append("SQLi")
    
    xss_risk = scan_xss(target_url)
    if xss_risk: vulnerabilities.append("XSS")
    
    csrf_status = check_csrf_protection(target_url)
    ssrf_risk = scan_ssrf(target_url)
    
    ai_recs = ai_analysis(target_url)
    
    end_time = time.time()
    
    col1.metric("Vulns", len(vulnerabilities))
    col1.success(f"Готово: {end_time-start_time:.1f}с")
    
    if vulnerabilities:
        col1.error("🚨 Найдено!")
        for v in vulnerabilities: col1.error(f"• {v}")
    else:
        col1.success("✅ Чисто!")
    
    col2.markdown("**🇷🇺**")
    col2.write(ai_recs.get('ru', 'OK'))
    
    if col1.button("📥 JSON"):
        st.download_button(
            label="Скачать",
            data=json.dumps({"url":target_url,"vulns":vulnerabilities,"time":end_time-start_time}, ensure_ascii=False, indent=2),
            file_name=f"scan_{datetime.now().strftime('%d%m%y')}.json",
            mime="application/json"
        )

tab1, tab2, tab3, tab4 = st.tabs(["📋 Results", "₿ Crypto", "🔍 Other", "🧩 CRX"])

with tab1: st.success("Результаты выше!")
with tab2:
    wallet = st.text_input("₿ Адрес:")
    if st.button("Check") and wallet:
        st.markdown(check_wallet(wallet))
with tab3: st.info("Скоро...")
with tab4:
    crx_file = st.file_uploader("CRX файл", type="crx")
    if crx_file and st.button("Скан"):
        path = tempfile.mktemp(suffix=".crx")
        with open(path, "wb") as f: f.write(crx_file.read())
        results = WebSecAIScanner().scan_crx(path)
        st.json(results)
        os.unlink(path)

st.caption("🛡️ WebSecAI | t.me/likeluv")
