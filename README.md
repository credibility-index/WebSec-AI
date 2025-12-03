## 🚀 Быстрый старт 

**Веб-версия:** [websec-ai.streamlit.app](https://websec-ai.streamlit.app/)  
**CLI:** `pip install -r requirements.txt && python websec.py`

Проверяет SQLi/XSS/CSRF/SSRF + network scan + AI-отчеты EN/RU.

# WebSecAI
AI-powered web vulnerability scanner designed to automatically detect common security flaws in web applications and help developers and security engineers prioritize remediation efforts.

## Features
- Detects SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Server-Side Request Forgery (SSRF)
- Generates detailed, dual-language reports (English/Russian)
- Integrates with OpenAI/OpenRouter for AI-driven analysis and recommendations
- Supports scanning multiple target URL

## 📸 Демо

**Streamlit UI:**
![Streamlit demo](<img width="970" height="806" alt="image" src="https://github.com/user-attachments/assets/a9458361-4bad-4692-99e8-51c801aac68b" />)

**Консоль + отчеты:**

## Installation
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set your OpenAI or OpenRouter API keys

## Usage
Run the scanner and specify the URL to scan:
python websecai.py --url http://testphp.vulnweb.com

## Output
Generates Markdown reports in English and Russian containing vulnerability details, severity, and remediation advice.

## Legal and Ethical Use
Use this tool only on sites you have permission to test. Unauthorized scanning may be illegal.
