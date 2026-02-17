[ [🇫🇷 Français](README.md) ] | [ 🇬🇧 English ]

# 🛡️ CyberConfiance

**The Digital Shield for Francophone Africa**

![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat&logo=python)
![Framework](https://img.shields.io/badge/Framework-Flask%203.0-green?style=flat&logo=flask)
![Database](https://img.shields.io/badge/Database-PostgreSQL-336791?style=flat&logo=postgresql)
![Status: Private/Internal](https://img.shields.io/badge/Status-Private%2FInternal-red?style=flat)
![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red?style=flat)
![Owner: MOA Digital Agency](https://img.shields.io/badge/Owner-MOA%20Digital%20Agency-orange?style=flat)

---

## 🚀 Pitch

**CyberConfiance** is the first unified cybersecurity platform designed specifically for leaders, decision-makers, and citizens of Francophone Africa. Developed by **MOA Digital Agency**, it democratizes access to forensic analysis tools (VirusTotal, HIBP) and digital education via a simple, bilingual interface adapted to local realities.

> *"Security is not a luxury, it is a right."* - Aisance KALONJI

---

## 🏗 Technical Architecture

```mermaid
graph TD
    User((User)) -->|HTTPS| WebServer[Web Server (Flask)]

    subgraph "Core System"
        WebServer -->|SQLAlchemy| DB[(PostgreSQL)]
        WebServer -->|File I/O| Storage[Secure Storage]
        WebServer -->|Templates| Jinja[Jinja2 Engine]
    end

    subgraph "Security Services (APIs)"
        WebServer -->|REST API| VT[VirusTotal]
        WebServer -->|REST API| HIBP[Have I Been Pwned]
        WebServer -->|REST API| GSB[Google Safe Browsing]
    end

    style WebServer fill:#f9f,stroke:#333,stroke-width:2px
    style DB fill:#bbf,stroke:#333,stroke-width:2px
    style VT fill:#ddd,stroke:#333,stroke-width:1px
    style HIBP fill:#ddd,stroke:#333,stroke-width:1px
```

---

## 📑 Table of Contents

1.  [Key Features](#-key-features)
2.  [Installation & Start](#-installation--start)
3.  [Full Documentation](#-full-documentation)
4.  [Legal Notices](#-legal-notices)

---

## 🌟 Key Features

*   **Unified Analyzer:** Check files, URLs, and IPs via 70+ antivirus engines.
*   **Anti-Quishing:** Decode and analyze QR Codes for security before scanning.
*   **Interactive Quiz:** Gamified assessment of cyber maturity.
*   **Code Audit (BETA):** Static analysis of GitHub repositories to detect secrets and vulnerabilities.
*   **Citizen Services:** Fact-checking and cybercrime reporting.

---

## ⚡ Installation & Start

This project is strictly internal. Access to source code is subject to authorization.

### Prerequisites
*   Python 3.11+
*   PostgreSQL
*   API Keys (HIBP, VirusTotal)

### Quick Start
```bash
# 1. Clone (Restricted Access)
git clone https://github.com/moa-digital/CyberConfiance.git

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with API keys and DATABASE_URL

# 4. Launch application
python main.py
```

---

## 📚 Full Documentation

All technical and functional documentation can be found in the `docs/` folder.

*   📖 **[The Features Bible](docs/CyberConfiance_Features_Full_List_en.md)** (Exhaustive reference)
*   🏗️ **[Technical Architecture](docs/CyberConfiance_Architecture_en.md)** (Stack, Flow, Security)
*   👤 **[User Guide](docs/CyberConfiance_User_Guide_en.md)** (User Manual)

---

## ⚖️ Legal Notices

**Produced by**: MOA Digital Agency (www.myoneart.com)
**Author**: Aisance KALONJI
**License**: Proprietary (See `LICENSE_en` file). All reproduction prohibited.
