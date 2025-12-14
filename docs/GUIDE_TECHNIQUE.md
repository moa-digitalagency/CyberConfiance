# Guide Technique Complet - CyberConfiance

Ce document regroupe toute la documentation technique de la plateforme CyberConfiance, incluant l'architecture, les services d'analyse, les integrations API et les procedures de deploiement.

**Version**: 2.1  
**Derniere mise a jour**: Decembre 2025

---

## Table des Matieres

1. [Architecture Generale](#1-architecture-generale)
2. [Structure du Projet](#2-structure-du-projet)
3. [Services d'Analyse](#3-services-danalyse)
4. [Integrations API](#4-integrations-api)
5. [Base de Donnees](#5-base-de-donnees)
6. [Configuration et Deploiement](#6-configuration-et-deploiement)
7. [Securite](#7-securite)
8. [Maintenance](#8-maintenance)

---

## 1. Architecture Generale

### Vue d'ensemble

CyberConfiance est une application Flask de sensibilisation a la cybersecurite avec des outils d'analyse de menaces. L'application utilise une architecture modulaire avec separation claire entre les couches.

### Stack Technologique

| Composant | Technologie |
|-----------|-------------|
| Backend | Python 3.12 + Flask 3.x |
| ORM | SQLAlchemy + Flask-SQLAlchemy |
| Base de donnees | PostgreSQL (Neon) |
| Admin | Flask-Admin |
| Auth | Flask-Login |
| Forms | Flask-WTF |
| i18n | Flask-Babel |
| Rate Limiting | Flask-Limiter |
| PDF | PyMuPDF (fitz) |
| QR Code | OpenCV + pyzbar |
| Production | Gunicorn |

### Diagramme d'Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                            │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         FLASK APPLICATION                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      Routes (Blueprints)                     │   │
│  │  main.py │ pages.py │ outils.py │ auth.py │ admin_*.py      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                   │                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                        SERVICES                              │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐   │   │
│  │  │  QRCode   │ │ Security  │ │  GitHub   │ │  Breach   │   │   │
│  │  │ Analyzer  │ │ Analyzer  │ │ Analyzer  │ │ Analyzer  │   │   │
│  │  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘   │   │
│  │        │             │             │             │          │   │
│  │        ▼             ▼             ▼             ▼          │   │
│  │  ┌─────────────────────────────────────────────────────┐   │   │
│  │  │               API INTEGRATIONS                       │   │   │
│  │  │  VirusTotal │ GSB │ URLhaus │ URLScan │ HIBP       │   │   │
│  │  └─────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                   │                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                        MODELS                                │   │
│  │  User │ Analysis │ Content │ Settings │ Logs │ Request      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                   │                                  │
└───────────────────────────────────│──────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         PostgreSQL Database                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Structure du Projet

### Arborescence Complete

```
cyberconfiance/
│
├── main.py                     # Point d'entree de l'application
├── __init__.py                 # Factory Flask + configuration app
├── config.py                   # Configuration (dev/prod)
├── check_env.py                # Verification variables d'environnement
├── init_db.py                  # Initialisation et migration DB
│
├── models/                     # Modeles SQLAlchemy (9 fichiers)
│   ├── __init__.py             # Exports
│   ├── base.py                 # Base declarative
│   ├── user.py                 # User, AdminUser
│   ├── analysis.py             # QRCodeAnalysis, SecurityAnalysis, etc.
│   ├── content.py              # Rule, Scenario, Glossary, Tool, News, etc.
│   ├── contact.py              # Contact, Newsletter
│   ├── logs.py                 # ActivityLog, SecurityLog, ThreatLog
│   ├── settings.py             # SiteSettings, SEOMetadata, PageContent
│   └── request.py              # RequestSubmission
│
├── routes/                     # Routes Flask (11 fichiers)
│   ├── __init__.py             # Exports blueprints
│   ├── main.py                 # Routes principales (/, /about, etc.)
│   ├── pages.py                # Pages statiques
│   ├── content.py              # Contenu dynamique
│   ├── outils.py               # Outils d'analyse
│   ├── auth.py                 # Authentification
│   ├── admin_panel.py          # Panel admin principal
│   ├── admin_routes.py         # Routes admin
│   ├── admin_requests.py       # Gestion requetes admin
│   ├── request_forms.py        # Formulaires de demande
│   └── admin/                  # Sous-module admin (5 fichiers)
│       ├── __init__.py
│       ├── dashboard.py
│       ├── content.py
│       ├── history.py
│       └── settings.py
│
├── services/                   # Services metier (38 fichiers)
│   ├── __init__.py
│   ├── file_upload_service.py
│   ├── qrcode_analyzer_service.py
│   ├── request_submission_service.py
│   │
│   ├── github/                 # Analyseur GitHub (3 fichiers)
│   │   ├── __init__.py
│   │   ├── analyzer.py         # Service principal (1502 lignes)
│   │   └── patterns.py         # Patterns de detection (500+ lignes)
│   │
│   ├── analyzers/              # Analyseurs modulaires (9 fichiers)
│   │   ├── __init__.py
│   │   ├── base_analyzer.py
│   │   ├── security_analyzer.py
│   │   ├── dependency_analyzer.py
│   │   ├── architecture_analyzer.py
│   │   ├── documentation_analyzer.py
│   │   ├── performance_analyzer.py
│   │   ├── git_analyzer.py
│   │   └── ai_patterns_analyzer.py
│   │
│   ├── security/               # Services securite (8 fichiers)
│   │   ├── __init__.py
│   │   ├── analyzer.py         # Orchestrateur
│   │   ├── virustotal.py
│   │   ├── google_safe_browsing.py
│   │   ├── urlhaus.py
│   │   ├── urlscan.py
│   │   ├── tracker_detector.py
│   │   └── url_shortener.py
│   │
│   ├── qrcode/                 # Analyseur QR (4 fichiers)
│   │   ├── __init__.py
│   │   ├── analyzer.py
│   │   ├── decoder.py
│   │   └── patterns.py
│   │
│   ├── prompt/                 # Analyseur prompt (2 fichiers)
│   │   ├── __init__.py
│   │   └── analyzer.py
│   │
│   ├── breach/                 # Verification fuites (2 fichiers)
│   │   ├── __init__.py
│   │   └── hibp.py
│   │
│   ├── quiz/                   # Service quiz (2 fichiers)
│   │   ├── __init__.py
│   │   └── service.py
│   │
│   └── pdf/                    # Generation PDF (8 fichiers)
│       ├── __init__.py
│       ├── base.py
│       ├── service.py
│       ├── qrcode_report.py
│       ├── security_report.py
│       ├── breach_report.py
│       ├── github_report.py
│       └── quiz_report.py
│
├── templates/                  # Templates Jinja2 (68 fichiers)
│   ├── base.html               # Template de base
│   ├── index.html              # Page d'accueil
│   ├── about.html, contact.html, glossary.html, etc.
│   │
│   ├── admin/                  # Templates admin (26 fichiers)
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   └── ...
│   │
│   ├── outils/                 # Templates outils (12 fichiers)
│   │   ├── qrcode_analyzer.html
│   │   ├── security_analyzer.html
│   │   ├── github_analyzer.html
│   │   ├── prompt_analyzer.html
│   │   ├── breach_analyzer.html
│   │   ├── quiz.html
│   │   └── ...
│   │
│   ├── programmes/             # Templates programmes (6 fichiers)
│   │   └── ...
│   │
│   └── services/               # Templates services (6 fichiers)
│       └── ...
│
├── static/                     # Fichiers statiques
│   ├── css/                    # Styles (3 fichiers)
│   │   ├── style.css
│   │   ├── theme-light.css
│   │   └── theme-dark.css
│   │
│   ├── js/                     # JavaScript (4 fichiers)
│   │   ├── main.js
│   │   ├── quiz.js
│   │   ├── theme-switcher.js
│   │   └── theme-lang-switcher.js
│   │
│   └── img/                    # Images (4 fichiers)
│       ├── logo.png
│       ├── logo_dark.png
│       ├── hero-bg.jpg
│       └── og-default.png
│
├── utils/                      # Utilitaires (8 fichiers)
│   ├── __init__.py
│   ├── document_code_generator.py
│   ├── hibp_checker.py
│   ├── i18n.py
│   ├── logging_utils.py
│   ├── metadata_collector.py
│   ├── security_utils.py
│   └── seed_data.py
│
├── data/                       # Donnees seed (6 fichiers JSON)
│   ├── rules_seed.json
│   ├── scenarios_seed.json
│   ├── glossary_seed.json
│   ├── tools_seed.json
│   ├── news_seed.json
│   └── quiz_questions.json
│
├── migrations/                 # Scripts migration (6 fichiers)
│   └── ...
│
├── docs/                       # Documentation (3 fichiers MD)
│   ├── GITHUB_ANALYZER_TECHNICAL.md
│   ├── GUIDE_TECHNIQUE.md
│   └── GUIDE_UTILISATEUR.md
│
├── requirements.txt            # Dependances Python
├── README.md                   # Documentation principale
├── replit.md                   # Documentation Replit
├── robots.txt                  # SEO
├── babel.cfg                   # Configuration i18n
└── deploy_vps.sh               # Script deploiement VPS
```

### Statistiques du Projet

| Type | Nombre | Lignes (approx.) |
|------|--------|------------------|
| Fichiers Python | 42 | ~9,000 |
| Templates HTML | 68 | ~8,000 |
| Fichiers CSS | 3 | ~1,500 |
| Fichiers JS | 4 | ~500 |
| Fichiers JSON (data) | 6 | ~2,000 |
| Documentation MD | 4 | ~1,500 |
| **Total** | **127** | **~22,500** |

---

## 3. Services d'Analyse

### 3.1 QRCodeAnalyzerService

**Fichier:** `services/qrcode_analyzer_service.py` + `services/qrcode/`

Service complet d'analyse de QR codes avec protection anti-quishing.

#### Pipeline d'Analyse

```
Image QR Code
      │
      ▼
┌─────────────────────┐
│ 1. DECODAGE         │ OpenCV QRCodeDetector (8 techniques preprocessing)
│                     │ Fallback: pyzbar
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 2. EXTRACTION URL   │ Validation format URL
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 3. RESOLUTION       │ Suivi redirections (HTTP 301/302/307/308)
│    REDIRECTIONS     │ Detection meta refresh, JS redirects
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 4. DETECTION        │ 40+ services IP logger connus
│    IP LOGGERS       │ Analyse patterns URL suspects
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 5. DETECTION        │ 100+ raccourcisseurs d'URL
│    TRACKERS         │ Parametres UTM, fbclid, gclid
│                     │ Fingerprinting detection
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 6. ANALYSE APIs     │ VirusTotal, Google Safe Browsing
│    SECURITE         │ URLhaus, URLScan.io
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 7. CONSOLIDATION    │ Score de risque global
│    RESULTATS        │ Recommandations
└─────────────────────┘
```

#### Domaines IP Logger detectes (40+)

```
grabify.link, iplogger.org, 2no.co, blasze.tk, yip.su,
ps3cfw.com, lovebird.guru, iptrackeronline.com, ipgrabber.ru,
ipsniff.net, iptracker.link, iplogger.ru, iplogger.info,
shorturl.at/danger, urlz.fr/tracker, ...
```

### 3.2 SecurityAnalyzerService

**Fichier:** `services/security/analyzer.py`

Orchestrateur principal coordonnant toutes les analyses de securite multi-sources.

#### Sources Integrees

| Variable | Service | Fonction |
|----------|---------|----------|
| `SECURITY_ANALYSIS_API_KEY` | VirusTotal | Analyse multi-moteurs (70+ AV) |
| `SECURITY_ANALYSIS_API_KEY_1` | Google Safe Browsing | Phishing/Malware temps reel |
| `SECURITY_ANALYSIS_API_KEY_2` | URLhaus (abuse.ch) | Base de malware |
| `SECURITY_ANALYSIS_API_KEY_3` | URLScan.io | Analyse comportementale |

#### Types d'Analyse

| Type | Description | API Utilisee |
|------|-------------|--------------|
| hash | Hash de fichier (MD5/SHA) | VirusTotal |
| domain | Nom de domaine | VirusTotal + GSB |
| ip | Adresse IP | VirusTotal |
| url | URL complete | Toutes les sources |

### 3.3 GitHubCodeAnalyzerService

**Fichier:** `services/github/analyzer.py`

Voir documentation complete: `docs/GITHUB_ANALYZER_TECHNICAL.md`

Resume:
- Clone depots GitHub publics
- Analyse 200+ patterns de vulnerabilites
- Detecte 50+ langages et 30+ frameworks
- Identifie patterns "vibecoding" IA
- Score global sur 100

### 3.4 PromptAnalyzerService

**Fichier:** `services/prompt/analyzer.py`

Detection des injections de prompts et patterns dangereux.

#### Patterns detectes

- Tentatives d'injection de prompt
- Code dangereux cache (eval, exec)
- Techniques d'obfuscation
- URLs/IPs suspectes dans le texte
- Tentatives de jailbreak

### 3.5 BreachAnalyzerService (HIBP)

**Fichier:** `services/breach/hibp.py`

Integration Have I Been Pwned pour verification des fuites de donnees.

---

## 4. Integrations API

### 4.1 VirusTotal API v3

**Variable:** `SECURITY_ANALYSIS_API_KEY`

| Caracteristique | Valeur |
|-----------------|--------|
| Moteurs AV | 70+ |
| Limite gratuite | 4 req/min, 500/jour |
| Documentation | https://developers.virustotal.com/ |

```python
import vt
client = vt.Client(api_key)
url_id = vt.url_id(url)
url_obj = client.get_object(f"/urls/{url_id}")
```

### 4.2 Google Safe Browsing API v4

**Variable:** `SECURITY_ANALYSIS_API_KEY_1`

| Caracteristique | Valeur |
|-----------------|--------|
| Limite gratuite | 10,000 req/jour |
| Types de menaces | MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE |
| Documentation | https://developers.google.com/safe-browsing |

### 4.3 URLhaus API (abuse.ch)

**Variable:** `SECURITY_ANALYSIS_API_KEY_2`

| Caracteristique | Valeur |
|-----------------|--------|
| Limite | Illimitee (pas de cle requise) |
| Types | malware_download, phishing, cryptominer, trojan, botnet |
| Documentation | https://urlhaus-api.abuse.ch/ |

### 4.4 URLScan.io API

**Variable:** `SECURITY_ANALYSIS_API_KEY_3`

| Caracteristique | Valeur |
|-----------------|--------|
| Limite gratuite | 5,000/jour |
| Fonctionnalites | Screenshots, trackers, brand detection |
| Documentation | https://urlscan.io/docs/api/ |

### 4.5 Have I Been Pwned API

**Variable:** `HIBP_API_KEY`

| Caracteristique | Valeur |
|-----------------|--------|
| Cout | ~$3.50/mois |
| Fonctionnalites | Recherche fuites par email, details breaches |
| Documentation | https://haveibeenpwned.com/API/v3 |

---

## 5. Base de Donnees

### Modeles Principaux

#### Analyses

```python
QRCodeAnalysis
├── id, document_code
├── original_filename
├── extracted_url, final_url
├── redirect_chain (JSON)
├── threat_level, threat_detected
├── threat_details (JSON)
├── ip_loggers_found (JSON)
├── trackers_found (JSON)
├── pdf_report, pdf_generated_at
├── ip_address, user_agent
└── created_at

SecurityAnalysis
├── id
├── analysis_type (file|url|domain|ip)
├── input_value, input_type
├── threat_level, threat_detected
├── api_results (JSON)
├── pdf_report
└── created_at

BreachAnalysis
├── id, document_code
├── email, breach_count, risk_level
├── breaches (JSON)
├── pdf_report
└── created_at

PromptAnalysis
├── id, document_code
├── prompt_text, prompt_length
├── threat_level, injection_detected
├── dangerous_patterns (JSON)
├── analysis_results (JSON)
└── created_at

GitHubAnalysis
├── id, document_code
├── repo_url, repo_name, repo_owner
├── branch, commit_hash
├── overall_score, security_score, dependency_score
├── architecture_score, performance_score, documentation_score
├── risk_level
├── security_findings (JSON)
├── languages_detected (JSON)
├── frameworks_detected (JSON)
└── created_at

QuizResult
├── id, document_code
├── score, category_scores (JSON)
├── email, pdf_report
└── created_at
```

#### Contenu

```python
User
├── id, username, email, password_hash
├── is_admin, is_active
└── created_at

Rule, Scenario, Glossary, Tool, AttackType, News
├── id, title/name, description/content
├── category/severity/icon
├── is_active, order_index
└── created_at, updated_at

Contact
├── id, name, email, subject, message
├── is_read, is_archived
└── created_at

Newsletter
├── id, email, is_active
└── created_at

RequestSubmission
├── id, document_code
├── request_type, status
├── form_data (JSON)
├── submitted_documents (JSON)
└── created_at
```

#### Configuration

```python
SiteSettings
├── id, key, value, category
└── updated_at

SEOMetadata
├── id, page_path
├── title, description, keywords
├── og_title, og_description, og_image
└── updated_at

PageContent
├── id, page_key, section_key
├── title, content
└── updated_at
```

#### Logs

```python
ActivityLog
├── id, action, details
├── ip_address, user_agent
└── created_at

SecurityLog
├── id, event_type, severity
├── details, ip_address
└── created_at

ThreatLog
├── id, threat_type, threat_level
├── source_url, detection_source
├── details
└── created_at
```

---

## 6. Configuration et Deploiement

### Variables d'Environnement

#### Obligatoires (Production)

```bash
ADMIN_PASSWORD=VotreMotDePasseSecurise123!
DATABASE_URL=postgresql://user:password@host:5432/database_name
SECURITY_ANALYSIS_API_KEY=votre_cle_virustotal
```

#### Recommandees

```bash
SECURITY_ANALYSIS_API_KEY_1=votre_cle_google_safe_browsing
SECURITY_ANALYSIS_API_KEY_2=votre_cle_urlhaus  # Optionnel (gratuit sans cle)
SECURITY_ANALYSIS_API_KEY_3=votre_cle_urlscan
HIBP_API_KEY=votre_cle_hibp
FLASK_DEBUG=False
SECRET_KEY=votre_cle_secrete_aleatoire_32_chars
```

### Deploiement Replit

L'application est configuree pour Replit avec:
- Workflow `CyberConfiance` qui lance `python main.py`
- Port 5000 expose automatiquement
- PostgreSQL Neon integre

### Deploiement VPS (Linux)

#### Prerequisites

- Ubuntu 22.04+ ou Debian 11+
- Python 3.11+
- PostgreSQL 14+
- Nginx
- Systemd

#### Installation

```bash
# 1. Cloner et configurer
cd /var/www
sudo git clone <repo_url> cyberconfiance
cd cyberconfiance

# 2. Environnement virtuel
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Configuration
cp .env.example .env
nano .env  # Editer les variables

# 4. Base de donnees
python init_db.py

# 5. Demarrer
gunicorn --bind=0.0.0.0:5000 --workers=4 main:app
```

#### Service Systemd

```ini
# /etc/systemd/system/cyberconfiance.service
[Unit]
Description=CyberConfiance Web Application
After=network.target postgresql.service

[Service]
Type=notify
User=www-data
WorkingDirectory=/var/www/cyberconfiance
Environment="PATH=/var/www/cyberconfiance/venv/bin"
EnvironmentFile=/var/www/cyberconfiance/.env
ExecStart=/var/www/cyberconfiance/venv/bin/gunicorn \
    --bind=127.0.0.1:5000 \
    --workers=4 \
    --reuse-port \
    --timeout=60 \
    main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## 7. Securite

### Pratiques Implementees

1. **Pas d'execution de contenu**
   - URLs analysees sans ouverture navigateur
   - Fichiers hashes sans execution

2. **Protection SSRF**
   - Validation URLs avant requetes
   - Blocage adresses privees/localhost

3. **Rate Limiting**
   - Protection abus API
   - Limitation par IP

4. **Validation Entrees**
   - Sanitization URLs
   - Verification formats fichiers
   - Limite uploads (10 MB)

5. **Gestion Secrets**
   - Variables d'environnement
   - Jamais de cles en dur

6. **CSRF Protection**
   - Flask-WTF CSRF actif

### Checklist Production

- [ ] Mot de passe admin change
- [ ] `FLASK_DEBUG=False`
- [ ] HTTPS (certificat SSL)
- [ ] Firewall configure
- [ ] Dependances a jour
- [ ] Sauvegardes DB automatiques
- [ ] fail2ban configure

---

## 8. Maintenance

### Verification au Demarrage

Le script `check_env.py` verifie automatiquement:
1. Variables requises presentes
2. APIs de securite configurees
3. Resume de configuration

### Commandes Utiles

```bash
# Initialisation DB
python init_db.py

# Verification
python init_db.py --check

# Reset (DANGER)
python init_db.py --reset
```

### Sauvegardes PostgreSQL

```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/cyberconfiance"
mkdir -p $BACKUP_DIR
pg_dump cyberconfiance | gzip > $BACKUP_DIR/backup_$DATE.sql.gz
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete
```

### Mise a jour

```bash
cd /var/www/cyberconfiance
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
python init_db.py
sudo systemctl restart cyberconfiance
```

---

*Documentation CyberConfiance v2.1 - Decembre 2025*
