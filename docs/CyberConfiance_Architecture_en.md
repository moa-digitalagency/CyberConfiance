[ [🇫🇷 Français](CyberConfiance_Architecture.md) ] | [ 🇬🇧 English ]

# Technical Architecture - CyberConfiance

## 1. Technology Stack

*   **Language**: Python 3.11+
*   **Web Framework**: Flask 3.0 (Application Factory Pattern)
*   **Database**: PostgreSQL 14+
*   **ORM**: SQLAlchemy 2.0
*   **Migrations**: Alembic
*   **Frontend**: Jinja2, HTML5, CSS3 (Glassmorphism), JavaScript (Vanilla)
*   **WSGI Server**: Gunicorn (Production)
*   **Reverse Proxy**: Nginx (Recommended)

---

## 2. Project Structure (Modular MVC)

The application follows a modular architecture based on Flask "Blueprints" to separate responsibilities.

```
CyberConfiance/
├── main.py                  # Application Entry Point
├── config.py                # Configuration (Environment, API Keys)
├── check_env.py             # Startup prerequisites validation
├── init_db.py               # Database initialization script
├── requirements.txt         # Python Dependencies
│
├── services/                # BUSINESS LAYER (Business Logic)
│   ├── security_service.py  # VirusTotal/GSB Orchestration
│   ├── breach_checker.py    # HIBP Logic
│   ├── pdf_service.py       # Report Generation
│   └── ...
│
├── routes/                  # CONTROLLERS (Blueprints)
│   ├── main.py              # Main Routes (Home, Quiz)
│   ├── outils.py            # Tool Routes (Scanner, QR, etc.)
│   └── admin_routes.py      # Back-office
│
├── models/                  # DATA MODELS (SQLAlchemy)
│   ├── user.py              # Users and Roles
│   ├── analysis.py          # Scan History
│   └── content.py           # Blog, Glossary
│
├── templates/               # VIEWS (Jinja2)
│   ├── layouts/             # Base templates
│   ├── outils/              # Tool Pages
│   └── admin/               # Admin Panel
│
├── static/                  # ASSETS
│   ├── css/                 # Styles
│   ├── js/                  # Client-side Scripts
│   └── img/                 # Images
│
└── utils/                   # UTILITIES
    ├── security_utils.py    # Security Functions (Sanitize, Hash)
    └── helpers.py           # Helper Functions
```

---

## 3. Implemented Security

Security is "Native by Design".

### 3.1. Content Security Policy (CSP)
A cryptographic `nonce` is generated for each request (`secrets.token_hex(16)`). It is injected into HTTP headers and authorized `<script>` tags. Any script without this nonce is blocked by the browser.

### 3.2. CSRF Protection
`Flask-WTF` generates a unique token for each user session. This token is required for any HTTP method modifying state (POST, PUT, DELETE).

### 3.3. Secure Headers
*   `Strict-Transport-Security`: Forces HTTPS.
*   `X-Content-Type-Options`: Blocks MIME sniffing.
*   `X-Frame-Options`: Prevents Clickjacking.
*   `X-XSS-Protection`: Enables browser XSS filter.

---

## 4. Data Flow

1.  **User Request**: Arrives at Nginx -> Forwarded to Gunicorn -> Processed by Flask.
2.  **Validation**: `CheckEnv` validates configuration. `WTForms` validates input.
3.  **Business Logic**: Controller (`routes/`) calls a service (`services/`).
4.  **External Service**: Service calls an API (e.g., VirusTotal) via `requests`.
5.  **Persistence**: Result is stored via SQLAlchemy.
6.  **Response**: Controller renders a Jinja2 template with data.

---

*Confidential Document - MOA Digital Agency*
