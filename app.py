import streamlit as st
import requests
import re
import os
import tempfile
import time
import logging
from urllib.parse import urlparse
from ratelimit import limits, sleep_and_retry

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from websec import ai_analysis
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
    from scanners.network_scanner import scan_network_segmentation
    from scanners.crypto_scanner import WebSecAIScanner, check_wallet
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()

def is_valid_url(url):
    """Проверка валидности URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as e:
        logging.error(f"URL validation error: {e}")
        return False

def format_ai_recommendations(vulns):
    """Форматирование рекомендаций ИИ"""
    if not vulns:
        return {'en': '🎉 No vulnerabilities!', 'ru': '🎉 Уязвимостей нет!'}
    ai_en, ai_ru = ai_analysis(vulns)
    return {'en': ai_en, 'ru': ai_ru}

@sleep_and_retry
@limits(calls=10, period=60)  # Ограничение: 10 запросов в минуту
def perform_scan(url):
    """Выполнение полного сканирования"""
    vulnerabilities = []
    
    if scan_sql_injection(url):
        vulnerabilities.append("SQLi")
    if scan_xss(url):
        vulnerabilities.append("XSS")
    if check_csrf_protection(url):
        vulnerabilities.append("CSRF")
    if scan_ssrf(url):
        vulnerabilities.append("SSRF")
    
    net_issues = scan_network_segmentation(url)
    if net_issues:
        vulnerabilities.extend(net_issues)
    
    return vulnerabilities

st.set_page_config(page_title="🛡️ WebSecAI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp {background: linear-gradient(135deg,#0f0f23 0%,#1a1a2e 100%);}
.stButton>button {background:linear-gradient(45deg,#667eea,#764ba2);color:white;border-radius:25px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ WebSecAI Scanner")
st.markdown("**SQLi • XSS • CSRF • SSRF • Crypto**")
st.divider()

col1, col2 = st.columns([3, 1])
with col1:
    target_url = st.text_input("🌐 URL", "http://testphp.vulnweb.com/")
with col2:
    st.info("Test site")

if st.button("🚀 SCAN", type="primary"):
    if not is_valid_url(target_url):
        st.error("❌ Invalid URL")
        st.stop()
        
    start_time = time.time()
    with st.spinner("Scanning..."):
        try:
            vulnerabilities = perform_scan(target_url)
            
            st.subheader("📊 Results")
            
            # Отображение результатов по каждому типу уязвимости
            st.write(f"✅ SQLi: {'Vulnerable' if 'SQLi' in vulnerabilities else 'Clean'}")
            st.write(f"✅ XSS: {'Vulnerable' if 'XSS' in vulnerabilities else 'Clean'}")
            st.write(f"✅ CSRF: {'Vulnerable' if 'CSRF' in vulnerabilities else 'Clean'}")
            st.write(f"✅ SSRF: {'Vulnerable' if 'SSRF' in vulnerabilities else 'Clean'}")

            if vulnerabilities:
                st.error("Network issues found:")
                for issue in vulnerabilities:
                    if issue not in ["SQLi", "XSS", "CSRF", "SSRF"]:
                        st.write(f"- {issue}")
            else:
                st.success("✅ Network OK")

            # Крипто проверка
            st.markdown("---")
            st.subheader("₿ Crypto Test")
            crypto_result = check_wallet("0x742d35cc6e3e8e1C5eD9a12345678901234567890123")
            st.markdown(crypto_result)

            # AI анализ
            st.markdown("---")
            st.subheader("🤖 AI Analysis")
            ai_recs = format_ai_recommendations(vulnerabilities)

            col1, col2 = st.columns(2)
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
