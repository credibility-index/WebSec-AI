## 🚀 Быстрый старт

**Python:** 3.10, 3.11 или 3.12.

```bash
pip install -r requirements.txt
python3 run.py
# или: streamlit run app.py
# или: python3 websec.py interactive
```

В боковой панели веб-интерфейса укажите **API-ключ OpenRouter** и выберите **модель** (GLM-4.5-Air, DeepSeek R1T2 Chimera или Llama 3 8B). Без ключа AI-функции недоступны.

**CLI:** `python3 websec.py ctf --url http://target`  
**REST API:** `python3 websec.py api` → http://localhost:8000/docs

- **CTF:** профили ctf_quick/ctf_full, поиск флагов, эксплуатация (SQLi/XSS/LFI/RCE/SSRF).
- **Recon:** поддомены (crt.sh), технологии, Google/GitHub dorks, Wayback.
- **Flag Hunter:** HTML, JS, cookies, заголовки, robots.txt, .git, .env.
- **AI:** анализ уязвимостей, подсказки по эксплуатации, оценка достоверности текста, туториалы.

# WebSecAI
AI-powered web vulnerability scanner designed to automatically detect common security flaws in web applications and help developers and security engineers prioritize remediation efforts.

## Возможности
- **Веб-аудит:** SQLi, XSS, CSRF, SSRF; отчёты EN/RU; валидация URL (только http/https).
- **AI (OpenRouter):** модели z-ai/glm-4.5-air:free, tngtech/deepseek-r1t2-chimera:free, meta-llama/llama-3-8b-instruct:free; ключ и выбор модели в веб-интерфейсе.
- **CTF:** сканы по профилям, поиск флагов (robots, .git, JS, cookies), эксплуатация, payloads, стеганография, Web3-анализ контрактов.
- **DevSecOps:** secrets, deps, SAST, container, IaC, compliance.
- Без заглушек: все функции либо работают с реальными сервисами/моделями, либо выводят явное сообщение о настройке (ключ, зависимости).

## 📸 Демо

**Streamlit UI:**
![Streamlit demo](https://github.com/user-attachments/assets/a9458361-4bad-4692-99e8-51c801aac68b =800x600)

**Результаты скана:**
![Results]((https://github.com/user-attachments/assets/0c877b8d-357a-4305-b52f-4fc194ca58cf =800x600)


## Installation

1. Clone the repository.
2. **Версия Python:** лучше 3.10–3.12. Если установлен только 3.14:
   - **macOS (Homebrew):** `brew install python@3.12` → `python3.12 -m venv venv` → `source venv/bin/activate`
   - **pyenv:** `pyenv install 3.12` → в каталоге проекта будет использоваться версия из `.python-version`
3. Установить зависимости: `pip install -r requirements.txt`
4. В веб-интерфейсе задать API-ключ OpenRouter и модель (боковая панель → AI). Опционально: Etherscan, Shodan, Censys — в соответствующих вкладках.

## Usage

**CLI (CTF / DevSecOps):**
```bash
# CTF-скан с поиском флагов
python websec.py ctf --url http://ctf.example.com --find-flags [--auto-exploit] [--profile ctf_full]

# Recon по домену
python websec.py recon --domain example.com

# Запуск веб-интерфейса (Streamlit)
python websec.py interactive

# Запуск REST API (FastAPI)
python websec.py api
```

**REST API (порт 8000):**
- `POST /api/scan` — запуск скана (url, profile, find_flags)
- `GET /api/scan/{id}` — статус и результат
- `GET /api/flags` — найденные флаги
- `POST /api/exploit` — запуск эксплуатации
- `POST /api/recon` — recon по домену

**Конфигурация:** `config.yaml` — профили сканирования (ctf_quick, ctf_full, devsecops, stealthy), паттерны флагов.

## Output
Generates Markdown reports in English and Russian containing vulnerability details, severity, and remediation advice.

## Legal and Ethical Use
Use this tool only on sites you have permission to test. Unauthorized scanning may be illegal.
