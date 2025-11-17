# CyberConfiance

## Overview

CyberConfiance is a French-language cybersecurity awareness platform built with Flask. The application provides educational content about cybersecurity best practices through multiple content types: golden rules, threat scenarios, security tools, glossary terms, resources, and news. It features a public-facing website for content consumption and a secure admin panel for content management.

The platform targets general users seeking to improve their cybersecurity knowledge, from beginners to intermediate users, with content presented in accessible, everyday language.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Application Structure

**Modular Flask Application**: The application follows a factory pattern with blueprints for separation of concerns. The `create_app()` function in `app/__init__.py` initializes all components (database, admin panel, authentication) and registers route blueprints.

**Routing Strategy**: Two main blueprints separate public routes (`main.py`) and admin routes (`admin_routes.py`). Public routes handle content display pages, while admin routes configure Flask-Admin model views with authentication checks.

**Service Layer Pattern**: The `ContentService` class in `app/services/__init__.py` provides static methods for data retrieval operations, abstracting database queries from route handlers. This centralizes business logic and simplifies route handlers.

### Data Architecture

**ORM Pattern**: SQLAlchemy manages all database operations through model classes defined in `app/models/__init__.py`. Models include:
- User (authentication and authorization)
- Article (blog-style content)
- Rule (cybersecurity best practices)
- Tool (recommended security tools)
- Scenario (threat scenarios and solutions)
- Resource (educational materials)
- News (cybersecurity news items)
- Contact (contact form submissions)
- GlossaryTerm (terminology definitions)

**Database Schema**: PostgreSQL database with relationships managed through SQLAlchemy ORM. The schema supports timestamped records (`created_at`, `updated_at`), ordering fields, and content publication states.

### Authentication & Authorization

**Flask-Login Integration**: User authentication uses Flask-Login with session-based authentication. The `User` model implements `UserMixin` for compatibility.

**Password Security**: Passwords are hashed using Werkzeug's `generate_password_hash` and `check_password_hash` functions. The User model provides `set_password()` and `check_password()` methods.

**Admin Access Control**: Flask-Admin views extend `SecureModelView`, which overrides `is_accessible()` to verify both authentication status and admin privileges. Non-admin users are redirected to the login page.

**Environment-Based Initialization**: In development mode (`FLASK_DEBUG=True`), a default admin account is created with username "admin" and password "admin123". In production, the `ADMIN_PASSWORD` environment variable must be set to define the admin password securely.

### Frontend Architecture

**Template Inheritance**: Jinja2 templates use a base template (`base.html`) that defines the common layout, navigation, and footer. All content pages extend this base, overriding the `content` and `title` blocks.

**Static Assets**: Modern dark-themed CSS in `app/static/css/style.css` with glassmorphism effects and responsive design. Enhanced JavaScript in `app/static/js/main.js` handles scroll animations, parallax effects, intersection observers, and interactive user feedback.

**Design System**: Professional dark mode theme with:
- Glassmorphism cards with backdrop blur effects
- CSS custom properties (CSS variables) for consistent theming
- Gradient accents (purple/blue/pink palette)
- Smooth animations and transitions
- Scroll-triggered animations using Intersection Observer API
- Interactive hover effects and button animations
- Parallax scrolling on hero section
- Floating particles and visual effects

**Typography**: Inter font family from Google Fonts for modern, clean readability

**Responsive Design**: The CSS uses CSS Grid and Flexbox layouts with mobile-first approach for responsive behavior across devices.

### Content Management

**Flask-Admin Interface**: The admin panel provides CRUD operations for all content models through automatically generated views. Each model view is registered with the Flask-Admin instance and protected by authentication checks.

**Content Publication Workflow**: The Article model includes a `published` boolean field to support draft/published workflows, allowing admins to prepare content before making it public.

## External Dependencies

### Core Framework
- **Flask 3.0.0**: Web application framework
- **Werkzeug 3.1.3**: WSGI utilities including password hashing

### Database
- **PostgreSQL**: Primary data store (configured via `DATABASE_URL` environment variable)
- **Flask-SQLAlchemy 3.1.1**: ORM layer for database operations
- **psycopg2-binary 2.9.9**: PostgreSQL adapter for Python
- **Alembic 1.13.0**: Database migration tool (configured but migrations directory not yet populated)

### Authentication & Admin
- **Flask-Login 0.6.3**: User session management
- **Flask-Admin 1.6.1**: Administrative interface with Bootstrap 3 theme

### Deployment & Configuration
- **python-dotenv 1.0.0**: Environment variable management from `.env` files
- **gunicorn 21.2.0**: Production WSGI HTTP server

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string (required)
- `SECRET_KEY`: Flask session encryption key (defaults to development value)
- `FLASK_DEBUG`: Debug mode toggle (defaults to False)
- `ADMIN_PASSWORD`: Admin account password (required in production, defaults to "admin123" in development)
- `PORT`: Application port (defaults to 5000)

## Recent Changes (November 17, 2025)

### Enhanced Navigation and Homepage Sections (Latest - November 17, 2025)
Complete navigation and homepage improvements:

- **Navigation Menu Completed**: Added Glossaire, Ressources, and Actualités to main navigation menu - all 9 menu items now visible
- **Advanced Glassmorphism Menu**: Enhanced header with advanced glassmorphism effects including:
  - Backdrop blur (30px) with saturation boost (180%)
  - Layered box shadows for depth
  - Hover effects with blurred overlays on menu items
  - Smooth transitions and transform effects
- **Animated Security Background**: Implemented floating security elements background with:
  - Animated symbols (🔒 🛡️ 🔐 ⚡ 🔑) and binary code (10101, 01010)
  - 120-second slow floating animation
  - Subtle opacity (0.03) for non-intrusive effect
  - Continuous loop with translateY and translateX
- **Complete Homepage Sections**: Added descriptive sections for ALL menu items on homepage:
  - 8 sections in 3-column grid layout
  - Each section links to corresponding page
  - Sections: À propos, Règles, Scénarios, Outils, Glossaire, Ressources, Actualités, Contact
  - Consistent glassmorphism styling on all cards
  - Numbered sections (01-08) for clear organization

### Minimalist Redesign - ChatflowAI Style (November 17, 2025)
Complete platform redesign inspired by ChatflowAI's minimalist aesthetic:

- **Pure Black Background (#000000)**: Ultra-minimal design with pure black background and subtle texture overlay
- **Colorful Glow Orb Effect**: Animated blob with radial gradient (green, purple, pink) in hero section with pulsing animation
- **Minimalist Typography**:
  - San Francisco / System Font stack
  - Negative letter-spacing (-2px to -3px) for modern look
  - Large font sizes (5rem for hero h1)
  - Ultra-generous spacing between sections
- **Classic Horizontal Navigation**: Replaced hamburger menu with horizontal navigation bar featuring subtle borders
- **Simplified Color Palette**:
  - Primary: Black (#000000), White (#ffffff)
  - Grays: #999999, #666666, #1a1a1a
  - Accents: Green (#00ff88), Purple (#9945ff), Pink (#ff00ff)
- **Minimal UI Elements**:
  - Cards with subtle 1px borders (#1a1a1a)
  - Process grid with 2x2 layout separated by thin lines
  - Interactive project list with hover effects
  - Clean, borderless buttons with simple hover states
- **Refined Animations**: Subtle scroll-triggered fade-ins without excessive motion
- **Generous White Space**: Large padding (8rem sections) for breathing room
- **Monochromatic Design**: Focus on typography and spacing over color

### Security Enhancements
- Implemented Flask-Login authentication for admin panel access
- Added SecureModelView to protect all Flask-Admin routes
- User model with Werkzeug password hashing
- Runtime security check on every startup detects default admin credentials in production mode
- Production deployment configured with gunicorn

### Application Features Completed
- All 8 database models implemented (User, Article, Rule, Tool, Scenario, Resource, News, Contact, GlossaryTerm)
- 9 public pages (home, about, rules, scenarios, tools, glossary, resources, news, contact)
- Login/logout functionality
- Sample data initialization for testing
- Comprehensive README with deployment instructions
- Modern, responsive design with professional dark theme and glassmorphism