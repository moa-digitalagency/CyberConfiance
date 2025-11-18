# CyberConfiance

## Overview
CyberConfiance is a French-language Flask-based cybersecurity awareness platform. It offers educational content on best practices, threat scenarios, security tools, and news through a public website and an admin panel for content management. The platform aims to educate general users, from beginners to intermediate, in accessible language, enhancing their cybersecurity knowledge.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Application Structure
The application uses a modular Flask architecture with a factory pattern and blueprints for public and admin routes. A `ContentService` class centralizes data retrieval logic, abstracting database interactions from route handlers.

### Data Architecture
SQLAlchemy ORM manages PostgreSQL database operations. The schema includes models for `User`, `Article`, `Rule`, `Tool`, `Scenario`, `Resource`, `News`, `Contact`, and `GlossaryTerm`, supporting timestamps and content publication states.

### Authentication & Authorization
Flask-Login handles session-based authentication with Werkzeug for secure password hashing. Flask-Admin views are protected by `SecureModelView`, ensuring only authenticated administrators can access content management features. A default admin account is created in development, with production requiring the `ADMIN_PASSWORD` environment variable.

### Frontend Architecture
Jinja2 templates use a base layout (`base.html`) for consistency. The design features a professional dark theme with glassmorphism effects, CSS custom properties, gradient accents, smooth animations, scroll-triggered effects, and parallax scrolling. Typography uses the Inter font, and the design is fully responsive with CSS Grid and Flexbox. Navigation includes dropdown menus with enhanced glassmorphism.

### Content Management
Flask-Admin provides CRUD operations for all content models via an intuitive interface. A `published` field in the `Article` model supports a draft/published workflow.

### Data Persistence System
A JSON-based seeding system ensures content persists across deployments:
- **Seed Files**: `data/rules_seed.json` and `data/scenarios_seed.json` serve as single sources of truth for content
- **Idempotent Seeding**: The `utils/seed_data.py` module provides `seed_rules()` and `seed_scenarios()` functions that:
  - Update existing records when found (by title)
  - Create new records when not found
  - Only update fields present in JSON (preserving manually added fields like `solution`)
- **Automatic Initialization**: `init_db.py` runs on application startup to seed/update database with latest JSON content
- **Benefits**: Easy content updates via JSON editing, persistent data across workflow restarts, no code changes needed for content modifications

### UI/UX Decisions
The platform features a minimalist design inspired by ChatflowAI, utilizing a pure black background, colorful glow orb effects, minimalist typography (San Francisco / System Font stack with negative letter-spacing), and a simplified color palette (black, white, grays, and vibrant accents). UI elements are clean with subtle borders and generous spacing. Animations are subtle and scroll-triggered.

**Recent Design Updates (Nov 2025):**
- Hero section height: 60vh (increased from previous 42vh for better visual balance)
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

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Flask session encryption key
- `FLASK_DEBUG`: Debug mode toggle
- `ADMIN_PASSWORD`: Admin account password
- `PORT`: Application port