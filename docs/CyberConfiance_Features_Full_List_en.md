[ [🇫🇷 Français](CyberConfiance_Features_Full_List.md) ] | [ 🇬🇧 English ]

# CyberConfiance - Comprehensive Feature List ("The Bible")

This document details **every feature** of the CyberConfiance platform in granular technical and functional detail. It serves as the absolute reference for developers, auditors, and administrators.

**Document Version**: 1.0
**Last Updated**: 2025

---

## 1. Unified Security Analysis Engine

The core of the platform relies on a multi-vector analysis system capable of processing files, URLs, IPs, and text via an orchestration of third-party services and internal algorithms.

### 1.1. URL and Domain Analyzer (`/outils/analyseur-liens`)
*   **Strict Validation**: Uses `utils.security_utils.is_safe_url_strict` to block SSRF, private/reserved IPs, and local loops.
*   **Redirection Tracing**:
    *   Follows up to 10 redirection hops (HTTP 301, 302, 303, 307, 308).
    *   Detects infinite redirection loops.
    *   Captures HTTP headers at each hop.
*   **Detection Engines**:
    *   **VirusTotal API**: Checks domain reputation.
    *   **Google Safe Browsing**: Detects phishing and malware.
    *   **URLhaus**: Database of malware distribution sites.
*   **Report**: Generates a risk score (0-100) and threat level.

### 1.2. File Analyzer
*   **Secure Upload**: 50 MB limit, UUID filenames, automatic cleanup.
*   **Type Identification**: Uses `python-magic` for real MIME type detection.
*   **Hashing**: MD5, SHA-1, SHA-256.
*   **VirusTotal Scan**: Search by hash or asynchronous upload.

### 1.3. QR Code Analyzer (Anti-Quishing)
*   **Input**: Image upload or direct camera capture.
*   **Decoding**: `pyzbar` / `opencv`.
*   **Analysis**: Full URL pipeline if the QR contains a link.
*   **Quishing**: Detection of obfuscated redirections.

### 1.4. LLM Prompt Analyzer
*   **Goal**: Prevent prompt injections and data leaks.
*   **Detection**: Injection patterns ("DAN mode"), malicious code, sensitive data.
*   **Sanitization**: Proposal of a cleaned version.

### 1.5. GitHub Code Analyzer (BETA)
*   **Cloning**: Partial (`depth=100`).
*   **SAST**: Detection of secrets (Regex), OWASP vulnerabilities, outdated dependencies.
*   **Scoring**: Weighted score (Security, Quality, Maintenance).

---

## 2. User Tools and Services

### 2.1. Cybersecurity Quiz
*   **Logic**: 15 random questions (Vigilance, Technical, Hygiene).
*   **HIBP**: Option to check email leaks at the end of the flow.
*   **Persistence**: Saves results (`QuizResult`) with a unique code.

### 2.2. Breach Verification (`/analyze-breach`)
*   **HIBP API**: Secure query (TLS).
*   **Mapping**: Maps compromised data to risk scenarios.

### 2.3. Forms & PDF Reports
*   **Security**: CSRF tokens, attachment scanning.
*   **PDF**: Vector generation via `PyMuPDF`.
*   **Tracking**: Unique code and status QR code.

---

## 3. Administration Interface (`/my4dm1n/admin`)

*   **Access**: Obfuscated URL, strong authentication, brute-force protection.
*   **Dashboard**: Real-time statistics, activity logs.
*   **CRUD**: Full management of analyses, user requests, and content (Blog, Glossary).
*   **Audit**: Detailed logs (`ActivityLog`, `SecurityLog`, `ThreatLog`).

---

## 4. Technical Architecture and Security

*   **CSP**: Unique `nonce` per request for scripts.
*   **CSRF**: `Flask-WTF` protection on all mutations.
*   **Secure Headers**: HSTS, X-Content-Type-Options, X-Frame-Options.
*   **Rate Limiting**: Global and per-route protection.
*   **Database**: PostgreSQL + SQLAlchemy + Alembic.

---

*This document is the property of CyberConfiance. Any modification must be validated by the technical team.*
