import streamlit as st
import os
import time
import json
import re
from datetime import datetime
from PIL import Image

# Safe imports с улучшенной диагностикой
try:
    from websec import ai_analysis
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
    st.success(result)
    st.success("✅ All security modules loaded")
except ImportError as e:
    st.warning(f"⚠️ Some scanners unavailable: {e}")
    st.info("Install: pip install -r requirements.txt")

# Глобальное кэширование моделей (один раз)
@st.cache_resource
def load_gigachat():
    """GigaChat Pro с secrets"""
    try:
        from gigachat import GigaChat
        return GigaChat(credentials=st.secrets["GIGACHAT_API_KEY"], verify_ssl_certs=False)
    except:
        return None

@st.cache_resource
def load_ai_detector():
    """AI Image Detector"""
    try:
        from transformers import pipeline
        return pipeline("image-classification", model="umm-maybe/AI-image-detector")
    except:
        return None

st.set_page_config(
    page_title="🛡️ WebSecAI", 
    page_icon="🛡️", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

st.title("🛡️ **WebSecAI Suite v2.0**")
st.markdown("*OWASP Top 10 • FakeNews • AI Images • Crypto Analysis*")

# ── SIDEBAR: API Keys + Mission ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔑 **API Configuration**")
    
    # OpenRouter (опционально)
    openrouter_key = st.text_input("OpenRouter API", type="password", 
                                  help="openrouter.ai (для ai_analysis)")
    if openrouter_key:
        os.environ["OPENROUTER_API_KEY"] = openrouter_key
    
    st.markdown("### 🚀 **WebSecAI Mission**")
    st.markdown("""
    **Комплексная защита цифрового пространства:**

    🔒 **WebSec** — OWASP Top 10 сканер  
    📰 **FakeNews** — GigaChat анализ достоверности  
    🖼️ **AI Images** — Детектор ИИ-генераций  
    ₿ **Crypto** — Риск-анализ кошельков  
    🔍 **Corpus** — Сбор данных для ML

    **Цель:** Сделать интернет безопаснее! 🌐
    
    👨‍💻 **Creator:** Moscow Cybersecurity Expert  
    📱 **Telegram:** t.me/likeluv  
    🌐 **GitHub:** credibility-index/WebSec-AI
    """)
    
    st.markdown("---")
    st.caption("© WebSecAI 2026")

# ── TABS ─────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔒 Web Security", "📰 FakeNews", "🖼️ AI Images", 
    "₿ Crypto", "ℹ️ Dashboard"
])

# TAB 1: WEB SECURITY SCANNER
with tab1:
    st.markdown("### 🔗 **OWASP Top 10 Vulnerability Scanner**")
    col_url, col_scan = st.columns([3, 1])
    
    url = col_url.text_input("🎯 Target URL:", 
                           placeholder="https://example.com", 
                           help="Public websites only")
    
    if col_scan.button("🚀 **FULL SCAN**", type="primary", use_container_width=True) and url:
        with st.spinner("🔍 Active scanning..."):
            vulns = []
            t0 = time.time()
            
            # Parallel scanning
            scans = {
                "SQLi": scan_sql_injection(url),
                "XSS": scan_xss(url),
                "CSRF": check_csrf_protection(url),
                "SSRF": scan_ssrf(url)
            }
            
            for vuln, detected in scans.items():
                if detected:
                    vulns.append(vuln)
            
            scan_time = time.time() - t0
            
            # AI Analysis
            try:
                ai_en, ai_ru = ai_analysis(vulns or ["No vulnerabilities"])
            except:
                ai_en = ai_ru = "AI analysis unavailable"
            
            # 📊 Metrics Dashboard
            col_m1, col_m2, col_m3 = st.columns(3)
            col_m1.metric("⏱️ Scan Time", f"{scan_time:.2f}s")
            col_m2.metric("🚨 Vulnerabilities", len(vulns))
            col_m3.metric("🛡️ Security Score", f"{max(0, 100 - len(vulns)*20)}/100")
            
            # Status Table
            st.markdown("### 📋 **Scan Results**")
            status_data = []
            for vuln in ["SQLi", "XSS", "CSRF", "SSRF"]:
                status = "🟢 Clean" if vuln not in vulns else "🔴 Detected"
                status_data.append({"Vulnerability": vuln, "Status": status})
            
            st.table(status_data)
            
            # Bilingual AI Reports
            col_ai1, col_ai2 = st.columns(2)
            with col_ai1:
                st.markdown("### 🇺🇸 **AI Analysis**")
                st.code(ai_en, language="markdown")
            with col_ai2:
                st.markdown("### 🇷🇺 **AI Анализ**")
                st.code(ai_ru, language="markdown")
            
            # 📥 Downloads
            st.markdown("---")
            ts = datetime.now().strftime("%Y%m%d_%H%M")
            col_d1, col_d2 = st.columns(2)
            
            report_en = f"""# WebSecAI Report
**URL:** {url}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Vulnerabilities:** {', '.join(vulns) or 'None'}
**Score:** {max(0, 100 - len(vulns)*20)}/100

{ai_en}"""
            
            report_ru = f"""# WebSecAI Отчёт
**URL:** {url}
**Время:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Уязвимости:** {', '.join(vulns) or 'Нет'}
**Оценка:** {max(0, 100 - len(vulns)*20)}/100

{ai_ru}"""
            
            with col_d1:
                st.download_button(
                    "📄 EN Report", report_en, 
                    f"websec_report_en_{ts}.md", "text/markdown"
                )
            with col_d2:
                st.download_button(
                    "📄 RU Report", report_ru, 
                    f"websec_report_ru_{ts}.md", "text/markdown"
                )

# TAB 2: FAKENEWS DETECTOR (Оптимизировано)
with tab2:
    st.markdown("### 📰 **FakeNews Detector** *Powered by GigaChat Pro*")
    
    news_text = st.text_area(
        "📝 Вставьте текст новости:", 
        placeholder="Полный текст статьи для анализа достоверности...", 
        height=300
    )
    
    if st.button("🚀 **АНАЛИЗ ДОСТОВЕРНОСТИ**", type="primary", use_container_width=True) and news_text.strip():
        gigachat = load_gigachat()
        if not gigachat:
            st.error("❌ GigaChat unavailable. Check GIGACHAT_API_KEY in secrets.toml")
            st.stop()
            
        with st.spinner("🤖 GigaChat анализирует..."):
            try:
                from gigachat.models import Chat
                
                # Улучшенный промпт с chunking
                text_chunk = news_text[:2000]  # GigaChat limit
                prompt = f"""АНАЛИЗ НОВОСТИ. ОТВЕЧАЙ ТОЛЬКО JSON:

{{
  "credibility": "high|medium|low",
  "score": 85,
  "fake_probability": 0.23,
  "sources_reliability": "high|medium|low",
  "reason": "2-3 ключевых аргумента",
  "recommendation": "доверять|проверить|не доверять"
}}

ТЕКСТ: {text_chunk}"""
                
                chat = Chat(messages=[{"role": "user", "content": prompt}])
                response = gigachat.chat(chat)
                
                # Парсинг JSON
                raw = response.choices[0].message.content.strip()
                json_match = re.search(r'\{.*\}', raw, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    result = {"error": "JSON parse failed", "raw": raw}
                
                # 📊 Metrics
                col1, col2, col3 = st.columns(3)
                col1.metric("📊 Достоверность", f"{result.get('score', 50)}/100")
                col2.metric("⚠️ Риск фейка", f"{result.get('fake_probability', 0.5):.0%}")
                col3.metric("📚 Источники", result.get('sources_reliability', 'unknown').upper())
                
                # 🎯 Verdict
                status_colors = {"high": "🟢", "medium": "🟡", "low": "🔴"}
                status = result.get('credibility', 'medium')
                st.markdown(f"""
                ## {status_colors.get(status, '⚪')} **{status.upper()}**
                **Рекомендация:** {result.get('recommendation', 'проверить')}
                **Причины:** {result.get('reason', 'N/A')}
                """)
                
                with st.expander("📄 Полный отчёт JSON"):
                    st.json(result)
                
                # Download
                st.download_button(
                    "💾 JSON Report", 
                    json.dumps(result, ensure_ascii=False, indent=2),
                    f"fakenews_{result.get('score', 0)}_{ts}.json"
                )
                
            except Exception as e:
                st.error(f"❌ Analysis failed: {e}")
                st.info("🔧 Проверьте: pip install gigachat, secrets.toml")

# TAB 3: AI IMAGE DETECTOR (Оптимизировано)
with tab3:
    st.markdown("### 🖼️ **AI Image Detector**")
    st.markdown("*Midjourney • DALL-E • Stable Diffusion vs Real Photos*")
    
    uploaded_image = st.file_uploader(
        "📁 Upload Image", 
        type=['png','jpg','jpeg','webp','heic','gif']
    )
    
    col_img, col_res = st.columns([1, 2])
    
    if uploaded_image:
        image = Image.open(uploaded_image).convert('RGB')
        # Resize для скорости
        image_resized = image.resize((512, 512))
        
        col_img.image(image_resized, caption="Uploaded", use_column_width=True)
        
        if col_img.button("🤖 **DETECT AI**", type="primary"):
            detector = load_ai_detector()
            if not detector:
                st.error("❌ Model unavailable. Install: pip install transformers torch")
                st.stop()
                
            with st.spinner("🔍 Analyzing image authenticity..."):
                results = detector(image_resized)
                
                # Расчёт вероятностей
                ai_scores = [r['score'] for r in results if 'fake' in r['label'].lower()]
                ai_prob = ai_scores[0] if ai_scores else 0.5
                human_prob = 1 - ai_prob
                
                # 📊 Metrics
                m1, m2, m3 = st.columns(3)
                m1.metric("🤖 AI Generated", f"{ai_prob:.1%}")
                m2.metric("👤 Real Photo", f"{human_prob:.1%}")
                
                # Verdict
                if ai_prob > 0.6:
                    verdict = "🔴 **AI GENERATED**"
                    st.error("🚨 Detected: Midjourney/Stable Diffusion/DALL-E")
                elif ai_prob < 0.4:
                    verdict = "🟢 **REAL PHOTO**"
                    st.success("✅ Taken with camera")
                else:
                    verdict = "🟡 **UNCERTAIN**"
                    st.warning("⚠️ Model confidence low")
                
                m3.metric("🎯 Verdict", verdict)
                
                # Детали
                st.markdown("### 📊 Model Confidence:")
                for result in results[:5]:
                    icon = "🤖" if 'fake' in result['label'].lower() else "👤"
                    st.write(f"{icon} **{result['label']}**: {result['score']:.1%}")
                
                # Report
                report = f"""WebSecAI AI Image Analysis
AI Probability: {ai_prob:.1%}
Real Probability: {human_prob:.1%}
Verdict: {verdict}
Top Prediction: {results[0]['label']} ({results[0]['score']:.1%})"""
                st.download_button("📄 Report", report, "ai_image_report.txt")

with tab4:
    st.markdown("### ₿ **Crypto Wallet Risk Scanner**")
    wallet_text = st.text_area("📝 Paste wallet address or text:", height=150, 
                              placeholder="0x742d35cc... или bc1q...")
    
    if st.button("🔍 **FULL WALLET SCAN**", type="primary", use_container_width=True):
        if not wallet_text.strip():
            st.warning("👆 Enter wallet address!")
            st.stop()
            
        with st.spinner("🔄 Scanning Etherscan + blacklist..."):
            result = check_wallet(wallet_text)
# TAB 5: DASHBOARD
with tab5:
    st.markdown("""
    # 🌟 **WebSecAI Dashboard**
    
    ## ✅ **Working Features:**
    - 🔒 OWASP Top 10 Scanner
    - 📰 GigaChat FakeNews 
    - 🖼️ AI Image Detector
    - 📊 Professional Reports
    
    ## 🚀 **Tech Stack:**
    ```
    Python 3.11 • Streamlit • GigaChat Pro
    Transformers • Pillow • OWASP Scanners
    ```
    
    ## 📈 **Next:**
    1. 💾 Results Database
    2. ₿ Real Crypto Scanner
    3. 🔍 Corpus Builder ML
    4. 📱 Mobile API
    
    **👨‍💻 Creator:** Cybersecurity Expert | MSc Data Science 2026
    """)
    st.balloons()

# Test button (sidebar)
if st.sidebar.button("🧪 Test GigaChat Connection"):
    gigachat = load_gigachat()
    if gigachat:
        try:
            from gigachat.models import Chat
            chat = Chat(messages=[{"role": "user", "content": "Тест"}])
            response = gigachat.chat(chat)
            st.sidebar.success("✅ GigaChat OK!")
            st.sidebar.write(response.choices[0].message.content[:100])
        except Exception as e:
            st.sidebar.error(f"❌ Test failed: {e}")
