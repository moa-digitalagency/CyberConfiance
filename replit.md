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

### UI/UX Decisions
The platform features a minimalist design inspired by ChatflowAI, utilizing a pure black background, colorful glow orb effects, minimalist typography (San Francisco / System Font stack with negative letter-spacing), and a simplified color palette (black, white, grays, and vibrant accents). UI elements are clean with subtle borders and generous spacing. Animations are subtle and scroll-triggered. Recent enhancements include edge-to-edge hero layouts, elaborated SVG icons, alternating section backgrounds, and individual pages for rules with a responsive grid display.

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