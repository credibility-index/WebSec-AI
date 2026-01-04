import streamlit as st
import requests
import re
import os
import tempfile
import logging
import time
import json
from datetime import datetime
from typing import Dict, List

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

def generate_detailed_report(vulnerabilities: List[str], url: str, scan_time: float) -> Dict:
    report = {
        "target": url,
        "scan_time": scan_time,
        "vulnerabilities": {
            "sql_injection": "Обнаружено" if "SQLi" in vulnerabilities else "Не обнаружено",
            "xss": "Обнаружено" if "XSS" in vulnerabilities else "Не обнаружено",
            "csrf": "Обнаружено" if "CSRF" in vulnerabilities else "Не обнаружено",
            "ssrf": "Обнаружено" if "SSRF" in vulnerabilities else "Не обнаружено"
        },
        "ai_analysis": {}
    }
    return report

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
    
        # Расчет времени сканирования
    scan_duration = end_time - start_time
    
    # Генерация детального отчета
    report = generate_detailed_report(vulnerabilities, target_url, scan_duration)
    
    # Вывод метрик
    col1.metric("⏱️ Время сканирования", f"{scan_duration:.1f}с")
    col1.metric("🚨 Найденные уязвимости", len(vulnerabilities))
    
    # Отображение результатов сканирования
    if vulnerabilities:
        col1.error("🚨 Уязвимости обнаружены!")
        for v in vulnerabilities:
            col1.error(f"• {v}")
    else:
        col1.success("✅ Уязвимости не обнаружены")
    
    # Улучшенный AI-анализ
    try:
        ai_recs = ai_analysis(vulnerabilities or [target_url])
        ai_report = ai_recs.get('ru', 'AI недоступен')
        
        # Добавление AI-анализа в отчет
        report['ai_analysis'] = {
            "summary": ai_recs.get('summary', ''),
            "recommendations": ai_recs.get('recommendations', []),
            "risk_level": ai_recs.get('risk_level', 'Неизвестно')
        }
        
        col2.markdown("**🤖 AI Рекомендации**")
        col2.markdown(f"### Общий вывод:\n{ai_recs.get('summary', 'Нет данных')}")
        col2.markdown(f"### Уровень риска:\n{ai_recs.get('risk_level', 'Неизвестно')}")
        col2.markdown(f"### Рекомендации:\n{ai_recs.get('recommendations', 'Нет рекомендаций')}")
    except Exception as e:
        col2.warning(f"Ошибка AI-анализа: {str(e)[:100]}")
    
    # Функция экспорта JSON
    def get_json_report():
        return json.dumps(report, ensure_ascii=False, indent=2)
    
    # Кнопка экспорта
    if col1.button("📥 Экспортировать отчет в JSON"):
        st.download_button(
            label="Скачать отчет",
            data=get_json_report(),
            file_name=f"websec_report_{datetime.now().strftime('%d%m%y_%H%M')}.json",
            mime="application/json"
        )

# Табы с информацией
tab1, tab2, tab3 = st.tabs(["📋 Результаты", "🔍 Дополнительно", "ℹ️ Информация"])

with tab1:
    st.markdown("### Основные результаты сканирования")
    st.json(report, expanded=False)

with tab2:
    st.info("Здесь будут доступны дополнительные сканы и анализы...")

with tab3:
    st.markdown("""
    # WebSecAI
    
    ## О приложении
    **WebSecAI** — инструмент для быстрого сканирования веб-уязвимостей.
    
    ## Проверяемые уязвимости
    * SQL-инъекции
    * XSS-атаки
    * CSRF-уязвимости
    * SSRF-уязвимости
    
    ## Особенности
    * AI-анализ результатов
    * Детальная отчетность
    * Экспорт в JSON
    
    ## Контакты
    [Telegram](https://t.me/likeluv)
    """)

st.caption("© WebSecAI 2026 | Все права защищены")

