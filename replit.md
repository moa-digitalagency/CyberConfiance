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
- **Security Analysis**: Provides analysis for URLs, files, domains, IPs, and hashes.
- **QR Code Analyzer (Anti-Quishing)**:
    - Decodes QR codes from images or real-time camera feeds.
    - **Comprehensive Multi-Protocol Redirect Detection**:
        - HTTP redirects (301, 302, 303, 307, 308 status codes)
        - Meta refresh tags parsed with BeautifulSoup
        - JavaScript redirects (18+ patterns: window.location, document.location, location.href, setTimeout+location, history.pushState, etc.)
        - HTTP header redirects (Refresh, Content-Location, Link rel=canonical)
        - URL parameter redirects (common params: url, redirect, next, return_url, etc.)
        - Frame/iframe full-page embed detection
    - Session-backed HTTP client with realistic browser headers
    - Checks URLs against blacklists (e.g., VirusTotal).
    - Hardened with SSRF protection, DNS rebinding prevention, content-length limits, and cloud metadata endpoint protection.
- **Prompt Analyzer (Anti-Injection)**:
    - Detects prompt injection patterns, dangerous code (eval, exec), obfuscation, and jailbreak attempts using pattern matching and AST analysis.
    - Hardened with input size limits and robust error handling.
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
- **jsQR library**: Used for real-time QR code scanning via camera.
- **Flask-Admin**: For administrative interface functionalities.
- **MediaDevices API**: For camera access in the QR code analyzer.
- **PostgreSQL (or compatible SQL database)**: For data persistence.
- **Google Analytics / Facebook Pixel (Optional)**: Via custom head code injection.
- **reCAPTCHA (Optional)**: For form security, configurable via site settings.