<div align="center">

# 🛡️ AI Bug Bounty Scanner

### AI-Powered Automated Vulnerability Scanner for Bug Bounty Hunters

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1-green?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/saurabh498/AI_BUG_BOUNTY?style=for-the-badge)](https://github.com/saurabh498/AI_BUG_BOUNTY)

**A professional-grade automated vulnerability scanner with AI-powered exploit suggestions,
PoC generation, and HackerOne-ready report writing.**

[🚀 Quick Start](#-quick-start) •
[✨ Features](#-features) •
[📸 Screenshots](#-screenshots) •
[🐳 Docker](#-docker-setup) •
[📖 Usage](#-usage)

---

![Demo](https://raw.githubusercontent.com/saurabh498/AI_BUG_BOUNTY/main/assets/demo.gif)

</div>

---

## ✨ Features

### 🔍 Vulnerability Detection
| Module | Description |
|--------|-------------|
| 💉 SQL Injection | Error-based, blind, UNION-based detection |
| ⚡ XSS | Reflected XSS with AI-mutated payloads |
| 🔐 Login Bypass | SQLi-based authentication bypass |
| 🔑 Weak Credentials | Default credential testing |
| 🗂️ Sensitive Files | `.env`, `.git`, backups, configs |
| 🔎 Security Headers | CSP, HSTS, X-Frame-Options, etc. |
| ↪️ Open Redirect | Parameter-based redirect testing |
| 📁 Directory Bruteforce | Hidden path discovery |
| ⚡ JS Endpoint Discovery | Hidden API endpoint extraction |
| 🎯 Parameter Fuzzing | Automated parameter testing |

### 🤖 AI-Powered Features
- **AI Payload Generator** — Mutates and generates smart payloads
- **Exploit Suggestions** — Next steps for each finding
- **PoC Generator** — Auto-generates curl, Python, and Burp requests
- **AI Report Writer** — HackerOne-ready reports via Groq LLaMA
- **Risk Score** — 0-100 overall risk assessment

### 📊 Dashboard & Reporting
- **Live Dashboard** — Real-time scan updates
- **Toast Notifications** — Instant alerts for new findings
- **PDF Report** — Professional downloadable report
- **JSON Export** — Machine-readable findings
- **Scan History** — Per-user scan history
- **Progress Tracking** — Phase-by-phase scan progress

### 🔐 Security & Auth
- User authentication (Login/Signup)
- Per-user scan isolation
- Session-based security
- Password reset with security questions

---

## 🚀 Quick Start

### Option 1 — Docker (Recommended)
```bash
git clone https://github.com/saurabh498/AI_BUG_BOUNTY.git
cd AI_BUG_BOUNTY
cp .env.example .env          # Add your Groq API key
docker-compose up
```
Open `http://localhost:5000` 🎉

### Option 2 — Manual Setup
```bash
git clone https://github.com/saurabh498/AI_BUG_BOUNTY.git
cd AI_BUG_BOUNTY
pip install -r requirements.txt
cp .env.example .env          # Add your Groq API key
python dashboard.py
```

---

## ⚙️ Configuration

Create a `.env` file:
```env
GROQ_API_KEY=your_groq_api_key_here
```

Get your **free** Groq API key at: https://console.groq.com

---

## 📖 Usage

### 1️⃣ Sign Up & Login
```
http://localhost:5000
→ Create account
→ Login
```

### 2️⃣ Configure Scan
```
Enter target URL
→ Choose scan mode (Fast / Standard / Deep)
→ Select modules
→ Set threads and delay
→ Launch scan
```

### 3️⃣ Monitor Live Dashboard
```
Real-time vulnerability feed
Toast notifications for new findings
Live risk score updates
Progress bar with phase tracking
```

### 4️⃣ Generate Reports
```
📄 PDF Report      → Download professional PDF
📦 JSON Export     → Machine-readable data
🤖 AI Report       → HackerOne-ready submission
```

---

## 🐳 Docker Setup
```bash
# Build and run
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## 🧠 Scan Modes

| Mode | Modules | Time | Use Case |
|------|---------|------|----------|
| 🚀 Fast | Headers + Sensitive Files | ~30 sec | Quick recon |
| 🎯 Standard | All except fuzzer | ~2-5 min | Normal scan |
| 🔬 Deep | All modules | ~10-15 min | Full audit |

---

## 📸 Screenshots

### Login Page
> Beautiful animated login with typewriter effect

### Scan Configuration
> Configure scan mode, modules, threads and delay

### Live Dashboard
> Real-time vulnerability feed with toast notifications

### AI Report
> HackerOne-ready professional reports

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| AI/ML | Groq LLaMA 3.3 70B |
| PDF | ReportLab |
| Auth | Flask-Login, Werkzeug |
| Scanning | Requests, BeautifulSoup |
| Docker | Docker, Docker Compose |

---


## 📁 Project Structure
```
AI_BUG_BOUNTY/
├── ai/                     # AI payload generation & classification
│   ├── ai_payloads.py
│   ├── payload_generator.py
│   └── vuln_classifier.py
├── auth/                   # Authentication & User DB system
│   ├── database.py
│   └── models.py
├── core/                   # Core multithreaded engine
│   ├── crawler.py
│   ├── engine.py
│   ├── http_client.py
│   ├── intelligence.py
│   ├── mutation_engine.py
│   ├── param_discovery.py
│   ├── payloads.py
│   ├── report.py
│   ├── storage.py
│   ├── thread_engine.py
│   └── validator.py
├── modules/                # Specialized Vulnerability Scanners
│   ├── ai_reasoning.py
│   ├── attack_path.py      # New! Attack Chain mapping
│   ├── auth_scanner.py
│   ├── dir_scanner.py
│   ├── exploit_suggester.py
│   ├── fuzzer.py
│   ├── header_scanner.py
│   ├── js_scanner.py
│   ├── login_scanner.py
│   ├── open_redirect.py
│   ├── poc_generator.py
│   ├── rate_limiter.py     # New! Smart throttling
│   ├── report_writer.py
│   ├── sensitive_scanner.py
│   ├── tech_detector.py    # New! Stack profiling
│   └── xss_scanner.py
├── recon/                  # Reconnaissance tools
│   └── subdomain_enum.py
├── templates/              # Beautiful UI / HTML templates
├── dashboard.py            # Main Flask Routing App
├── main.py                 # CLI/Core Scan Trigger
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## ⚠️ Legal Disclaimer
```
This tool is intended for authorized security testing only.
Only scan systems you own or have explicit written permission to test.
The developer is not responsible for any misuse or damage caused by this tool.
Always follow responsible disclosure practices.
```

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit changes: `git commit -m 'Add AmazingFeature'`
4. Push to branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📊 Comparison

| Feature | Your Tool | Nikto | OWASP ZAP |
|---------|-----------|-------|-----------|
| AI Payloads | ✅ | ❌ | ❌ |
| PoC Generator | ✅ | ❌ | ❌ |
| AI Reports | ✅ | ❌ | ❌ |
| HackerOne Ready | ✅ | ❌ | ❌ |
| Live Dashboard | ✅ | ❌ | ✅ |
| Docker Support | ✅ | ✅ | ✅ |
| Free & Open Source | ✅ | ✅ | ✅ |

---

## 👨‍💻 Author

**Saurabh**
- GitHub: [@saurabh498](https://github.com/saurabh498)

---

## ⭐ Star History

If this project helped you, please give it a ⭐ on GitHub!

---

<div align="center">
Made with ❤️ for the Bug Bounty Community
</div>