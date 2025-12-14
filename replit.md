# CyberConfiance - Cybersecurity Awareness Platform

## Overview
CyberConfiance is a production-ready Flask-based cybersecurity awareness training platform. It offers a comprehensive suite of analysis tools, including email breach checking, security analysis for various digital assets, and novel anti-quishing (QR code analysis) and anti-injection (prompt analysis) capabilities. The platform features an interactive quiz, personalized recommendations, and an admin panel for managing user requests and site settings. It ensures data persistence through a robust database schema and is fully compatible with VPS deployments, offering standardized IP collection and automated deployment scripts. The core vision is to empower users with tools and knowledge to enhance their digital security posture against evolving cyber threats.

## User Preferences
I prefer that the agent adheres to existing architectural patterns and design decisions. Major changes to the system design or core functionalities should be proposed and discussed before implementation. I value clear, concise communication and detailed explanations for complex changes. When introducing new features or making significant modifications, the agent should prioritize security hardening and ensure robust error handling. I also prefer an iterative development approach, with regular updates on progress and potential issues.

## System Architecture

### UI/UX Decisions
- **Thematic Design**: Utilizes a cybersecurity-focused aesthetic.
- **Interactive Elements**: Features like the interactive quiz and real-time QR code scanner are designed for engaging user experience.
- **Admin Panel**: Provides a comprehensive, user-friendly interface for site management.
- **Responsive Design**: All features, including camera access for QR scanning, are designed to work across desktop and mobile devices.
- **SEO & Open Graph**: Implements dynamic SEO tags, Open Graph support, and Twitter Cards for improved search engine visibility and social media sharing, with a default fallback image.

### Technical Implementations
- **Flask Framework**: Core application developed using Flask.
- **Database Persistence**: All analysis types, quiz results, and site settings are stored in a relational database with 20 tables, including specific fields for PDF reports (LargeBinary) and linked analysis IDs.
- **PDF Generation**: On-demand generation and storage of forensic-style PDF reports for breaches, security analyses, quizzes, QR codes, and prompts.
- **IP Address Collection**: Standardized across the application using `get_client_ip(request)` to correctly handle proxy and load balancer environments.
- **Dynamic Content**: Context processors load site settings and SEO metadata dynamically from the database.
- **Image Uploads**: Direct image upload functionality for logos and other assets, with file storage in `/static/img/uploads/`.
- **Custom Head Code Injection**: Allows administrators to inject custom HTML/JS into the `<head>` section for analytics or tracking, with security warnings.

### Feature Specifications
- **Email Breach Analysis**: Integrates with Have I Been Pwned for email compromise checks.
- **Security Analysis (Multi-Source)**: 
    - Provides analysis for URLs, files, domains, IPs, and hashes.
    - **URL Shortener Detection (100+ services)**:
        - Detects URLs from popular shortening services (bit.ly, tinyurl, t.co, goo.gl, etc.)
        - Automatically expands shortened URLs to reveal the final destination
        - Detects multiple shorteners in redirect chains (potential obfuscation technique)
        - Analyzes all URLs in the redirect chain with security APIs
    - **URL Analysis uses 5 security sources in parallel**:
        - VirusTotal: 90+ antivirus engines for malware/phishing detection
        - Google Safe Browsing: Real-time phishing/malware database from Google
        - URLhaus: Malware distribution URL database from abuse.ch
        - URLScan.io: Behavioral analysis with screenshot, brand detection, tracker identification
        - TrackerDetector (internal): IP logger detection (Grabify, iplogger, etc.), fingerprinting, tracking parameters
    - Results are combined with highest threat level prioritization
    - UI displays individual source results with visual indicators
    - **Tracker & IP Logger Detection**:
        - Detects 30+ known IP logger services (Grabify, iplogger, 2no.co, etc.)
        - Fingerprinting detection (Canvas, WebGL, Audio fingerprinting)
        - Tracking parameter analysis (UTM, gclid, fbclid, etc.)
        - Ad network and tracking pixel detection
- **QR Code Analyzer (Anti-Quishing)**:
    - Decodes QR codes from images or real-time camera feeds.
    - **URL Shortener Detection in QR Codes**:
        - Detects shortened URLs from 100+ shortening services
        - Follows all redirects to reveal the final destination URL
        - Alerts on multiple shorteners in chain (obfuscation technique)
        - Full multi-API security analysis of final and intermediate URLs
    - **Comprehensive Multi-Protocol Redirect Detection**:
        - HTTP redirects (301, 302, 303, 307, 308 status codes)
        - Meta refresh tags parsed with BeautifulSoup
        - JavaScript redirects (18+ patterns: window.location, document.location, location.href, setTimeout+location, history.pushState, etc.)
        - HTTP header redirects (Refresh, Content-Location, Link rel=canonical)
        - URL parameter redirects (common params: url, redirect, next, return_url, etc.)
        - Frame/iframe full-page embed detection
    - **Multi-API Security Analysis**:
        - VirusTotal, Google Safe Browsing, URLhaus, URLScan.io, and TrackerDetector analysis
        - Analyzes both original and final URLs after redirect resolution
        - Threat detection with combined severity scoring
    - **Tracker & IP Logger Detection in QR Codes**:
        - Real-time detection of IP loggers in QR code URLs
        - Chain analysis for trackers in redirect paths
        - Clear warnings displayed in analysis results
    - Session-backed HTTP client with realistic browser headers
    - Hardened with SSRF protection, DNS rebinding prevention, content-length limits, and cloud metadata endpoint protection.
- **Prompt Analyzer (Anti-Injection)**:
    - Detects prompt injection patterns, dangerous code (eval, exec), obfuscation, and jailbreak attempts using pattern matching and AST analysis.
    - **URL/IP/Domain Detection in Prompts**:
        - Extracts URLs from text and routes them through full multi-API security analysis (VirusTotal, Google Safe Browsing, URLhaus, URLScan.io)
        - Detects public IPv4 and IPv6 addresses (filters out private/local ranges)
        - Identifies standalone domain names
        - Reports security threats found in embedded URLs
    - Hardened with input size limits and robust error handling.
- **GitHub Code Analyzer**:
    - Analyzes public GitHub repositories for security vulnerabilities and code quality issues
    - **Advanced Language & Framework Detection**:
        - Supports 40+ programming languages (Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby, PHP, etc.)
        - Framework detection with confidence scores for Python (Django, Flask, FastAPI, Celery, SQLAlchemy, TensorFlow, PyTorch)
        - JavaScript/TypeScript frameworks (React, Vue, Angular, Express, NestJS, Next.js, Nuxt.js)
        - Backend frameworks (Ruby on Rails, Laravel, ASP.NET, Gin, Actix, Spring)
    - **Security Scanning (OWASP Top 10 aligned)**:
        - 30+ secret detection patterns (AWS, OpenAI, Anthropic, GitHub, Slack, Stripe, Discord, Telegram, etc.)
        - SQL injection patterns (17 patterns for Python, Node.js, PHP)
        - XSS vulnerability detection (18 patterns including React dangerouslySetInnerHTML, Vue v-html)
        - Command injection detection (20 patterns for os.system, subprocess, child_process, exec)
        - Path traversal vulnerabilities (LFI/RFI patterns)
        - Insecure deserialization (pickle, yaml, marshal, unserialize)
        - SSRF and CSRF vulnerability patterns
        - Authentication issues (weak password comparison, insecure JWT, MD5/SHA1 hashing)
        - Insecure configuration (DEBUG mode, CORS wildcards, disabled SSL verification)
    - **Vulnerable Dependencies Database**:
        - Known vulnerable Python packages (PyYAML, Django, Flask, Jinja2, etc.)
        - Known vulnerable NPM packages (lodash, express, axios, etc.)
        - Unpinned version detection and lockfile validation
    - **Toxic AI Pattern Detection (Vibecoding)**:
        - Unresolved TODOs and FIXMEs
        - Silent exception handling (except: pass patterns)
        - Placeholder code (pass statements, NotImplementedError)
        - Debug prints and debugger statements left in code
        - AI-generated code markers
    - **Performance Issue Detection**:
        - N+1 query patterns (Django ORM, Sequelize)
        - Infinite loop risks
        - Unoptimized SELECT * queries
        - Async/await antipatterns
    - **Architecture Analysis**: File structure, test presence, CI/CD detection, modular design
    - **Git Hygiene Analysis**: Sensitive files in history, commit quality, stale branches
    - **Documentation Check**: README presence/quality, .gitignore configuration
    - **Scoring System**: Weighted algorithm (Security 55%, Dependencies 12%, Architecture 8%, Toxic AI 8%, Performance 7%, Git 5%, Docs 5%)
    - PDF report generation with OWASP references and remediation suggestions
- **Admin Panel Enhancements**:
    - Detailed history views for all analyses (QR code, prompt, breach, security) with filtering and search.
    - Formatted display of analysis results, replacing raw JSON with visual cards and statistics.
    - Extensive site settings with 24 configurable parameters, including sensitive fields masked with toggle visibility.
    - Corrected Flask-Admin routing and improved SEO Metadata editing.

### System Design Choices
- **Modular Structure**: Application is organized into `models/`, `routes/`, and `services/` for clear separation of concerns.
- **Automated Deployment**: `deploy_vps.sh` script automates code synchronization, dependency updates, and database initialization for VPS environments.
- **Database Schema Verification**: `init_db.py` ensures all tables and columns are correctly created and configured, verifying data types and relationships.
- **Error Handling**: Comprehensive error handling is implemented across routes and services.

## External Dependencies
- **Have I Been Pwned API**: For email breach detection.
- **VirusTotal API (v3 REST)**: For URL and file reputation analysis in security and QR code analyses.
- **Google Safe Browsing API (v4)**: For real-time phishing and malware URL detection.
- **URLhaus API (abuse.ch)**: For malware distribution URL detection.
- **URLScan.io API**: For behavioral URL analysis, screenshot capture, brand detection, and tracker identification.
- **jsQR library**: Used for real-time QR code scanning via camera.
- **Flask-Admin**: For administrative interface functionalities.
- **MediaDevices API**: For camera access in the QR code analyzer.
- **PostgreSQL (or compatible SQL database)**: For data persistence.
- **Google Analytics / Facebook Pixel (Optional)**: Via custom head code injection.
- **reCAPTCHA (Optional)**: For form security, configurable via site settings.

## Documentation
Comprehensive documentation is available in the `docs/` folder (harmonized November 2025):
- **GUIDE_TECHNIQUE.md**: Complete technical documentation including architecture, all services (QRCodeAnalyzer, SecurityAnalyzer, TrackerDetector, URLShortener, PromptAnalyzer), API integrations, database schema, deployment procedures (VPS, Docker), and maintenance guides
- **GUIDE_UTILISATEUR.md**: User-friendly guide explaining each tool, how to use them, understanding results, security tips, and FAQ

## Recent Changes (December 2025)
- **GitHub Code Analyzer Enhanced**: Major upgrade with 40+ language support, framework detection with confidence scores, 30+ secret patterns (AWS, OpenAI, Anthropic, Discord, Telegram, etc.), OWASP Top 10 aligned vulnerability detection, vulnerable package database for Python/NPM, SSRF/CSRF detection, and improved weighted scoring algorithm.

## Recent Changes (November 2025)
- **QR Code Detection Enhancement**: Added OpenCV QRCodeDetector with 8 preprocessing techniques (CLAHE, thresholding, sharpening, resizing) as primary detector with pyzbar fallback
- **QR Scanner Progress Animation**: When a QR code is detected during camera scanning, the camera view is replaced with an animated progress bar and step indicators showing analysis status
- **Contact Form Security Analysis**: Contact form now includes prompt injection detection and security analysis using PromptAnalyzerService, with threat logging and redirect to security alert page
- **All Forms Protected**: All submission forms (contact, fact-checking, cybercrime report, cyberconsultation, OSINT investigation) now have security analysis with prompt injection detection
- **Unified Security Analysis Pipeline**: All analyzers now use the same SecurityAnalyzerService for consistent multi-API security checks
- **Prompt Analyzer URL/IP Detection**: Prompt analyzer now detects and analyzes URLs, IP addresses, and domains embedded in prompts, routing URLs through the full security analysis pipeline
- **Harmonized PDF Reports**: QR code PDF reports now display per-source security results (VirusTotal, Google Safe Browsing, URLhaus, URLScan.io) matching the security analysis report format
- **Consolidated Summary System**: QR code analyzer produces a unified, consistent verdict by aggregating all detection sources (tracker_analysis, chain_tracker_analysis, multi_api_analysis) into a single authoritative summary
- **Coherent PDF Reports**: PDF service uses consolidated summary for consistent, non-redundant reports with proper section ordering
- **Legacy Data Support**: Template and service handle historical records without consolidated_summary via fallback rendering
- **Environment Check**: check_env.py now verifies all 5 security APIs with detailed descriptions at startup

## API Keys Configuration
- `SECURITY_ANALYSIS_API_KEY`: VirusTotal API key
- `SECURITY_ANALYSIS_API_KEY_1`: Google Safe Browsing API key
- `SECURITY_ANALYSIS_API_KEY_2`: URLhaus API key (optional)
- `SECURITY_ANALYSIS_API_KEY_3`: URLScan.io API key
- `HIBP_API_KEY`: Have I Been Pwned API key