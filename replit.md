# CyberConfiance

## Overview
CyberConfiance is a French-language Flask-based cybersecurity awareness platform. It offers educational content on best practices, threat scenarios, security tools, and news through a public website and an admin panel for content management. The platform aims to educate general users, from beginners to intermediate, in accessible language, enhancing their cybersecurity knowledge.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Application Structure
The application uses a modular Flask architecture with a factory pattern and blueprints for public and admin routes. A `ContentService` class centralizes data retrieval logic, abstracting database interactions from route handlers.

### Data Architecture
SQLAlchemy ORM manages PostgreSQL database operations. The schema includes models for `User`, `Article`, `Rule`, `Tool`, `Scenario`, `Resource`, `News`, `Contact`, `GlossaryTerm`, and `AttackType`, supporting timestamps and content publication states.

### Authentication & Authorization
Flask-Login handles session-based authentication with Werkzeug for secure password hashing. Flask-Admin views are protected by `SecureModelView`, ensuring only authenticated administrators can access content management features. A default admin account is created in development, with production requiring the `ADMIN_PASSWORD` environment variable.

### Frontend Architecture
Jinja2 templates use a base layout (`base.html`) for consistency. The design features a professional dark theme with glassmorphism effects, CSS custom properties, gradient accents, smooth animations, scroll-triggered effects, and parallax scrolling. Typography uses the Inter font, and the design is fully responsive with CSS Grid and Flexbox. Navigation includes dropdown menus with enhanced glassmorphism.

### Content Management
Flask-Admin provides CRUD operations for all content models via an intuitive interface. A `published` field in the `Article` model supports a draft/published workflow.

### Data Persistence System
A JSON-based seeding system ensures content persists across deployments:
- **Seed Files**: `data/rules_seed.json`, `data/scenarios_seed.json`, and other seed files serve as single sources of truth for content
- **Idempotent Seeding**: The `utils/seed_data.py` module provides seeding functions (`seed_rules()`, `seed_scenarios()`, `seed_attack_types()`, etc.) that:
  - Update existing records when found (by title or name)
  - Create new records when not found
  - Only update fields present in seed data (preserving manually added fields)
- **Automatic Initialization**: `init_db.py` runs on application startup to seed/update database with latest content
- **Benefits**: Easy content updates, persistent data across workflow restarts, no code changes needed for content modifications

### UI/UX Decisions
The platform features a minimalist design inspired by ChatflowAI, utilizing a pure black background, colorful glow orb effects, minimalist typography (San Francisco / System Font stack with negative letter-spacing), and a simplified color palette (black, white, grays, and vibrant accents). UI elements are clean with subtle borders and generous spacing. Animations are subtle and scroll-triggered.

**Recent Design Updates (Nov 2025):**
- Hero section height: 60vh (increased from previous 42vh for better visual balance)
- Hero section padding: increased top padding (8rem) and reduced bottom padding (2rem) for better visual hierarchy
- Dynamic hero text now includes: "Dirigeants d'entreprise", "Décideurs publics", "Citoyens soucieux" (simplified from previous version)
- Reduced spacing between "Votre bouclier numérique" and dynamic text (margin-top: 0.2em)
- Removed all emojis from service pages (Sensibilisation, Fact-Checking, Cyberconsultation)
- Standardized page headers across all pages using `page-header` component
- Unified font sizes (hero title: 3.2rem, section titles: 2rem, body text: 0.95rem)
- Removed newsletter section decorative elements for cleaner design
- Consistent glassmorphism styling across pillar cards and content sections (text-align: center)
- Responsive grid displays for rules (3 columns), scenarios/tools (2 columns), and glossary
- All 20 règles d'or from VADE MECUM PDF now populated with complete content including risks and solutions
- À propos page: "Le contexte" and "Notre approche" sections now displayed in two-column layout
- Rule detail pages: reorganized header with back button ("← Retour aux règles") and rule number badge ("Règle 1/20")

**New Feature - Email Breach Analysis (Nov 18, 2025):**
- Hero newsletter form converted to breach analysis tool with "Analyser" button
- Integration with Have I Been Pwned API v3 for email breach detection
- New `HaveIBeenPwnedService` class in `services/__init__.py` for API communication
- Comprehensive breach analysis page (`templates/breach_analysis.html`) with:
  - Visual status indicators (safe/warning/danger) based on breach count
  - Detailed breach information with dates, affected data types, and account counts
  - Contextual security recommendations tailored to breach severity levels
  - Responsive design matching the platform's glassmorphism aesthetic
- URL-encoded email addresses for API calls to handle special characters
- Proper error handling for API failures, rate limiting, and invalid credentials

**New Feature - Attack Types Catalog (Nov 18, 2025):**
- Comprehensive catalog of 42 common cyber attack types from Hacksplaining, fully translated to French
- New `AttackType` model with fields: name_en, name_fr, description_fr, category, severity, prevention, order
- Accessible via `/outils/types-attaques` route
- Category-based filtering (Toutes, IA, Web, Réseau, Données, Social) with interactive JavaScript
- Glass-card design with severity badges (Critique, Élevé, Moyen, Faible) color-coded by risk level
- Each attack includes:
  - French name and English reference
  - Detailed description in French
  - Prevention recommendations specific to each attack type
  - Severity classification for risk assessment
- Idempotent seeding via `seed_attack_types()` function in `utils/seed_data.py`
- Responsive grid layout (auto-fill minmax 300px) matching platform aesthetic

**New Feature - Quiz de Sécurité Numérique (Nov 18, 2025):**
- Interactive security assessment quiz with 15 questions based on the 20 golden security rules
- Questions cover common tools and habits (Gmail, WhatsApp, VPN, public WiFi, password managers, etc.)
- Three-axis scoring system evaluating users across:
  - **Vigilance** (🛡️): Awareness and threat detection capabilities
  - **Sécurité** (🔒): Technical security practices and tools usage
  - **Hygiène Numérique** (✨): Digital hygiene and privacy habits
- Personalized recommendations engine that:
  - Calculates overall security score (0-100%)
  - Identifies weak areas based on user responses
  - Suggests priority security rules to implement
  - Recommends relevant security tools from the catalog
- Integration with Have I Been Pwned API for email breach analysis post-quiz
- Two-step interface:
  1. **Quiz interface** (`templates/outils/quiz.html`): Multi-question form with progress tracking and navigation
  2. **Results page** (`templates/outils/quiz_results.html`): Detailed score breakdown, recommendations, and optional email breach check
- Client-side JavaScript (`static/js/quiz.js`) for smooth question navigation and form validation
- Server-side score calculation via `QuizService` class in `services/quiz_service.py`
- JSON-based question storage (`data/quiz_questions.json`) for easy content updates
- Session-based data persistence (primitives only, no ORM objects) for multi-step flow
- Comprehensive CSS styling matching platform's glassmorphism aesthetic
- Accessible via `/quiz` route with link in "Outils" navigation menu

## External Dependencies

### Core Framework
- **Flask 3.0.0**: Web application framework
- **Werkzeug 3.1.3**: WSGI utilities and password hashing

### Database
- **PostgreSQL**: Primary data store
- **Flask-SQLAlchemy 3.1.1**: ORM for database operations
- **psycopg2-binary 2.9.9**: PostgreSQL adapter
- **Alembic 1.13.0**: Database migration tool

### Authentication & Admin
- **Flask-Login 0.6.3**: User session management
- **Flask-Admin 1.6.1**: Administrative interface

### Deployment & Configuration
- **python-dotenv 1.0.0**: Environment variable management
- **gunicorn 21.2.0**: Production WSGI HTTP server

### Security & API Integration
- **requests 2.32.5**: HTTP library for external API calls
- **Have I Been Pwned API v3**: Email breach detection service

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Flask session encryption key
- `FLASK_DEBUG`: Debug mode toggle
- `ADMIN_PASSWORD`: Admin account password
- `PORT`: Application port
- `HIBP_API_KEY`: Have I Been Pwned API key for breach analysis (required for email breach checking feature)