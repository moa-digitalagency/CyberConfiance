# CyberConfiance

## Overview
CyberConfiance is a bilingual (French/English) Flask-based cybersecurity awareness platform. It provides educational content on best practices, threat scenarios, security tools, and news through a public website, interactive request submission forms with VirusTotal security scanning, and an admin panel. The platform aims to enhance users' cybersecurity knowledge and provide practical security analysis tools.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Application Structure
The application uses a modular Flask architecture with a factory pattern and blueprints for public and admin routes. A `ContentService` class centralizes data retrieval logic, abstracting database interactions.

### Data Architecture
SQLAlchemy ORM manages PostgreSQL database operations. The schema includes models for various content types (e.g., `Article`, `Rule`, `Tool`), user management (`User`), and platform-specific data such as `RequestSubmission` and `SiteSettings`. A JSON-based seeding system ensures content persistence and idempotent updates across deployments.

### Authentication & Authorization
Flask-Login handles session-based authentication with Werkzeug for secure password hashing. Flask-Admin views are protected by `SecureModelView`, restricting content management to authenticated administrators.

### Frontend Architecture
Jinja2 templates use a base layout. The design features a professional dark theme with glassmorphism effects, CSS custom properties, gradient accents, smooth animations, scroll-triggered effects, and parallax scrolling. Typography uses the Inter font, and the design is fully responsive. The platform also supports a light/dark theme system with automatic detection and a user-controlled switcher, along with bilingual support (French/English) via Flask-Babel.

### Feature Specifications
- **Admin Panel**: Flask-Admin provides management for user requests (fact-checking & cyberconsultation), history logs (breach analysis, quiz results, security analysis), activity/security logs, site settings, and SEO metadata. Content management (articles, rules, tools, etc.) has been removed - content is managed via JSON seed files.
- **Request Submission Forms**: Dedicated secure forms at `/request/factchecking` and `/request/cyberconsultation` support text, file, and URL inputs with anonymous submission option. All submissions are automatically scanned using VirusTotal for malicious content detection.
- **Email Breach Analysis**: Integrates with Have I Been Pwned API for user email breach detection.
- **Attack Types Catalog**: A comprehensive, categorized, and filterable catalog of 42 common cyber attack types with descriptions, prevention, and severity.
- **Security Quiz**: An interactive quiz assessing user vigilance, security, and digital hygiene, providing personalized recommendations and an optional email breach check.
- **Blog & Newsletter System**: A news/blog system with categorized articles and a newsletter subscription management, displayed on homepage.
- **Security Analyzer**: A tool for analyzing files, domains, IPs, and URLs against threat databases using VirusTotal, storing results for admin review.
- **Bilingual Support**: Complete English/French translation with automatic browser language detection and user-controlled language switcher (bottom-left corner).
- **Theme System**: Light and dark themes with automatic system detection and user-controlled theme switcher (bottom-left corner). Logo variants (light/dark) configurable in site settings.

### UI/UX Decisions
The platform features a minimalist design with a pure black background, colorful glow orb effects, minimalist typography, and a simplified color palette. UI elements are clean with subtle borders, generous spacing, and scroll-triggered animations. Recent design improvements focus on enhanced primary buttons with advanced glassmorphism effects and mobile optimization.

## External Dependencies

### Core Framework
- **Flask**: Web application framework
- **Werkzeug**: WSGI utilities and password hashing

### Database
- **PostgreSQL**: Primary data store
- **Flask-SQLAlchemy**: ORM for database operations
- **psycopg2-binary**: PostgreSQL adapter
- **Alembic**: Database migration tool

### Authentication & Admin
- **Flask-Login**: User session management
- **Flask-Admin**: Administrative interface

### Deployment & Configuration
- **python-dotenv**: Environment variable management
- **gunicorn**: Production WSGI HTTP server

### Security & API Integration
- **requests**: HTTP library for external API calls
- **Have I Been Pwned API v3**: Email breach detection service
- **vt-py**: Python client for VirusTotal API
- **Flask-Babel**: Internationalization and localization framework
- **filetype**: MIME type detection for uploaded files