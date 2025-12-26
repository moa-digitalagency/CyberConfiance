# CyberConfiance - Cybersecurity Awareness Platform

---

**CyberConfiance**  
By MOA Digital Agency LLC  
Developed by: Aisance KALONJI  
Contact: moa@myoneart.com  
Website: www.myoneart.com

---

## Documentation

Complete documentation is available in the `docs/` folder:

| Document | Description |
|----------|-------------|
| [README.md](docs/README.md) | Main overview and quick start |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical architecture details |
| [SERVICES.md](docs/SERVICES.md) | Analysis services documentation |
| [API_INTEGRATIONS.md](docs/API_INTEGRATIONS.md) | External API integrations |
| [ADMINISTRATION.md](docs/ADMINISTRATION.md) | Admin panel guide |
| [GUIDE_UTILISATEUR.md](docs/GUIDE_UTILISATEUR.md) | End-user guide (French) |
| [GUIDE_TECHNIQUE.md](docs/GUIDE_TECHNIQUE.md) | Technical reference (French) |
| [GITHUB_ANALYZER_TECHNICAL.md](docs/GITHUB_ANALYZER_TECHNICAL.md) | GitHub analyzer deep-dive |

## Overview
CyberConfiance is a production-ready Flask-based cybersecurity awareness training platform. It offers a comprehensive suite of analysis tools, including email breach checking, security analysis for various digital assets, and novel anti-quishing (QR code analysis) and anti-injection (prompt analysis) capabilities. The platform features an interactive quiz, personalized recommendations, and an admin panel for managing user requests and site settings. It ensures data persistence through a robust database schema and is fully compatible with VPS deployments. The core vision is to empower users with tools and knowledge to enhance their digital security posture against evolving cyber threats.

**Version**: 2.1 (December 2025)
**Status**: Production-ready with GitHub Analyzer in BETA

## User Preferences
I prefer that the agent adheres to existing architectural patterns and design decisions. Major changes to the system design or core functionalities should be proposed and discussed before implementation. I value clear, concise communication and detailed explanations for complex changes. When introducing new features or making significant modifications, the agent should prioritize security hardening and ensure robust error handling. I also prefer an iterative development approach, with regular updates on progress and potential issues.

## System Architecture

### UI/UX Decisions
- **Thematic Design**: Utilizes a cybersecurity-focused aesthetic.
- **Interactive Elements**: Features like the interactive quiz and real-time QR code scanner are designed for engaging user experience.
- **Admin Panel**: Provides a comprehensive, user-friendly interface for site management.
- **Responsive Design**: All features are designed to work across desktop and mobile devices.
- **SEO & Open Graph**: Implements dynamic SEO tags, Open Graph support, and Twitter Cards for improved search engine visibility and social media sharing.

### Technical Implementations
- **Flask Framework**: Core application developed using Flask.
- **Database Persistence**: All analysis types, quiz results, and site settings are stored in a relational database with 20 tables, including specific fields for PDF reports and linked analysis IDs.
- **PDF Generation**: On-demand generation and storage of forensic-style PDF reports.
- **IP Address Collection**: Standardized across the application using `get_client_ip(request)`.
- **Dynamic Content**: Context processors load site settings and SEO metadata dynamically from the database.
- **Image Uploads**: Direct image upload functionality for logos and other assets.
- **Custom Head Code Injection**: Allows administrators to inject custom HTML/JS into the `<head>` section.

### Feature Specifications
- **Email Breach Analysis**: Integrates with Have I Been Pwned for email compromise checks.
- **Security Analysis (Multi-Source)**: Provides analysis for URLs, files, domains, IPs, and hashes. Includes URL shortener detection and expansion, and uses multiple security APIs (VirusTotal, Google Safe Browsing, URLhaus, URLScan.io) and an internal TrackerDetector.
- **QR Code Analyzer (Anti-Quishing)**: Decodes QR codes from images or real-time camera feeds. Features comprehensive multi-protocol redirect detection (HTTP, Meta refresh, JavaScript, HTTP header, URL parameter, iframe), multi-API security analysis, and tracker/IP logger detection. Hardened with SSRF protection and DNS rebinding prevention.
- **Prompt Analyzer (Anti-Injection)**: Detects prompt injection patterns, dangerous code, obfuscation, and jailbreak attempts using pattern matching and AST analysis. Extracts and analyzes URLs, IPs, and domains embedded in prompts.
- **GitHub Code Analyzer (BETA)**: Analyzes public GitHub repositories for security vulnerabilities and code quality issues. Features advanced language and framework detection (50+ languages, 30+ frameworks), OWASP Top 10 aligned security scanning (200+ patterns including secret detection, SQLi, XSS, command injection, path traversal, insecure deserialization, SSRF/CSRF, auth issues, insecure config), vulnerable dependencies database, toxic AI pattern detection ("vibecoding"), performance issue detection, architecture analysis, Git hygiene analysis, and documentation checks. See `docs/GITHUB_ANALYZER_TECHNICAL.md` for detailed algorithm documentation.
- **Admin Panel Enhancements**: Detailed history views for all analyses, formatted display of results, extensive site settings, and improved SEO Metadata editing.

### System Design Choices
- **Modular Structure**: Application is organized into `models/`, `routes/`, and `services/` for clear separation of concerns.
- **Automated Deployment**: `deploy_vps.sh` script automates deployment for VPS environments.
- **Database Schema Verification**: `init_db.py` ensures correct database setup.
- **Error Handling**: Comprehensive error handling across routes and services.

### Project Structure (Updated December 2025)

#### Models (`models/`)
Individual model files organized by domain:
- `base.py` - Database instance import
- `user.py` - User model
- `content.py` - Article, Rule, Tool, Scenario, Resource, News, GlossaryTerm, AttackType
- `contact.py` - Contact, Newsletter
- `analysis.py` - BreachAnalysis, SecurityAnalysis, QRCodeAnalysis, PromptAnalysis, QuizResult, GitHubCodeAnalysis
- `logs.py` - ActivityLog, SecurityLog, ThreatLog
- `settings.py` - SiteSettings, SEOMetadata
- `request.py` - RequestSubmission
- `__init__.py` - Exports all models

#### Services (`services/`)
Organized by functionality:
- `breach/` - HaveIBeenPwnedService
- `security/` - SecurityAnalyzerService, GoogleSafeBrowsingService, URLhausService, URLScanService, URLShortenerService, TrackerDetectorService
- `prompt/` - PromptAnalyzerService
- `quiz/` - QuizService
- `qrcode/` - QRCode analyzer
- `github/` - GitHub code analyzer
- `pdf/` - PDF generation
- `analyzers/` - Code analyzers
- `file_upload_service.py` - File upload handling
- `request_submission_service.py` - Request submission handling
- `__init__.py` - ContentService + re-exports from submodules

## External Dependencies
- **Have I Been Pwned API**: For email breach detection.
- **VirusTotal API (v3 REST)**: For URL and file reputation analysis.
- **Google Safe Browsing API (v4)**: For real-time phishing and malware URL detection.
- **URLhaus API (abuse.ch)**: For malware distribution URL detection.
- **URLScan.io API**: For behavioral URL analysis.
- **jsQR library**: Used for real-time QR code scanning.
- **Flask-Admin**: For administrative interface functionalities.
- **MediaDevices API**: For camera access in the QR code analyzer.
- **PostgreSQL (or compatible SQL database)**: For data persistence.
- **Google Analytics / Facebook Pixel (Optional)**: Via custom head code injection.
- **reCAPTCHA (Optional)**: For form security.