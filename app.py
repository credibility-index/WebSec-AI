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
            with col1:
                st.markdown("**🇺🇸 EN**")
                st.write(ai_recs['en'])import streamlit as st
import requests
import re
import os
import tempfile
import logging
import time
import json
from datetime import datetime

# Логгирование
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('websec_ai.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

try:
    from websec import ai_analysis
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
    from scanners.network_scanner import scan_network_segmentation
    from scanners.crypto_scanner import WebSecAIScanner, check_wallet
    logger.info("Все сканеры загружены")
except ImportError as e:
    logger.error(f"Импорт ошибка: {e}")
    st.error("❌ Сканеры недоступны")

st.set_page_config(page_title="WebSecAI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .main {background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);}
</style>
""")

col1, col2 = st.columns([3, 1])
target_url = col1.text_input("🔗 URL для скана:", placeholder="https://example.com")
run_scan = col1.button("🚀 СКАНИРОВАТЬ", type="primary")

if run_scan and target_url:
    logger.info(f"Скан {target_url}")
    start_time = time.time()
    
    with st.spinner("Сканирую..."):
        try:
            vulnerabilities = []
            
            sql_risk = scan_sql_injection(target_url)
            if sql_risk:
                vulnerabilities.append("SQL Injection")
            
            xss_risk = scan_xss(target_url)
            if xss_risk:
                vulnerabilities.append("XSS")
            
            csrf_status = check_csrf_protection(target_url)
            ssrf_risk = scan_ssrf(target_url)
            network_risk = scan_network_segmentation(target_url)
            
            ai_recs = ai_analysis(target_url)
            
            logger.info(f"Найдено: {len(vulnerabilities)} уязвимостей")
            
            with col1:
                if vulnerabilities:
                    st.error(f"🚨 Найдено: {len(vulnerabilities)} уязвимостей")
                    for vuln in vulnerabilities:
                        st.error(f"• {vuln}")
                else:
                    st.success("✅ Критичных нет")
            
            with col2:
                st.markdown("**🇷🇺 RU**")
                st.write(ai_recs.get('ru', 'Нет рекомендаций'))
            
            st.metric("Vulns found", len(vulnerabilities))
            end_time = time.time()
            st.success(f"Скан: {end_time - start_time:.2f} сек")

            if st.button("📥 Download Results"):
                results = {
                    "url": target_url,
                    "vulnerabilities": vulnerabilities,
                    "scan_time": end_time - start_time,
                    "ai_recs": ai_recs
                }
                csv = json.dumps(results, indent=2, ensure_ascii=False)
                st.download_button(
                    label="Download JSON",
                    data=csv,
                    file_name=f"scan_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json"
                )
                
        except Exception as e:
            logger.error(f"Скан ошибка: {e}")
            st.error(f"Ошибка: {str(e)}")

# Табы (вне if)
tab1, tab2, tab3, tab4 = st.tabs(["📋 Results", "₿ Crypto", "🔍 Other", "🧩 Ext"])

with tab1:
    st.success("Результаты выше!")

with tab2:
    wallet = st.text_input("₿ Wallet:")
    if st.button("Check") and wallet:
        try:
            result = check_wallet(wallet)
            st.markdown(result)
            logger.info(f"Wallet check: {wallet[:10]}...")
        except Exception as e:
            logger.error(f"Wallet error: {e}")
            st.error(f"Ошибка: {e}")

with tab3:
    st.info("Больше сканеров скоро...")

with tab4:
    crx = st.file_uploader("Upload .crx", type=["crx"])
    if crx and st.button("Scan CRX"):
        try:
            with tempfile.NamedTemporaryFile(suffix=".crx", delete=False) as tmp:
                tmp.write(crx.read())
                path = tmp.name
            
            logger.info("CRX скан начат")
            scanner = WebSecAIScanner()
            results = scanner.scan_crx(path)
            
            st.json(results)
            os.unlink(path)
            logger.info("CRX скан завершён")
            
        except Exception as e:
            logger.error(f"CRX ошибка: {e}")
            st.error(f"CRX ошибка: {e}")

st.markdown("---")
st.caption("🛡️ WebSecAI 2026 | Логи: websec_ai.log")
