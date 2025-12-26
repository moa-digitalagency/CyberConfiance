# Architecture Technique - CyberConfiance

Ce document decrit l'architecture technique de la plateforme CyberConfiance, ses composants, leurs interactions et les choix de conception.

**Version**: 2.1  
**Mise a jour**: Decembre 2025

---

## Vue d'Ensemble

CyberConfiance utilise une architecture MVC (Modele-Vue-Controleur) basee sur Flask, avec une separation claire entre les couches de presentation, logique metier et acces aux donnees.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NAVIGATEUR CLIENT                               │
│                    (HTML/CSS/JS + Formulaires)                          │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         APPLICATION FLASK                               │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                        ROUTES (Blueprints)                       │   │
│  │  main │ pages │ content │ auth │ request_forms │ admin_*        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                   │                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                          SERVICES                                │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│  │  │ QRCode  │ │Security │ │ GitHub  │ │ Prompt  │ │ Breach  │   │   │
│  │  │Analyzer │ │Analyzer │ │Analyzer │ │Analyzer │ │Analyzer │   │   │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘   │   │
│  │       └───────────┴───────────┴───────────┴───────────┘         │   │
│  │                              │                                   │   │
│  │       ┌──────────────────────┴──────────────────────┐           │   │
│  │       │              API INTEGRATIONS                │           │   │
│  │       │  VirusTotal │ GSB │ URLhaus │ URLScan │ HIBP │           │   │
│  │       └──────────────────────────────────────────────┘           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                   │                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                           MODELS                                 │   │
│  │  User │ Analysis │ Content │ Settings │ Logs │ Request          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        PostgreSQL (Neon)                                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Couche Presentation

### Templates (Jinja2)

Organisation des templates en 68 fichiers :

```
templates/
├── base.html                  # Template de base avec navigation
├── index.html                 # Page d'accueil
├── about.html                 # A propos
├── contact.html               # Formulaire de contact
│
├── outils/                    # Templates des outils (12 fichiers)
│   ├── qrcode_analyzer.html
│   ├── security_analyzer.html
│   ├── github_analyzer.html
│   ├── prompt_analyzer.html
│   ├── breach_analyzer.html
│   ├── quiz.html
│   ├── quiz_results.html
│   └── attack_types.html
│
├── services/                  # Pages de services (6 fichiers)
│   ├── sensibilisation.html
│   ├── factchecking.html
│   ├── cyberconsultation.html
│   └── cybercrime_report_form.html
│
├── programmes/                # Programmes de sensibilisation (6 fichiers)
│
└── admin/                     # Interface d'administration (26 fichiers)
    ├── base.html
    ├── dashboard.html
    ├── *_history.html         # Historiques d'analyses
    └── *_detail.html          # Details d'analyses
```

### Fonctionnalites Frontend

| Composant | Fichier | Description |
|-----------|---------|-------------|
| Theme switcher | `theme-switcher.js` | Bascule entre themes clair/sombre |
| Language switcher | `theme-lang-switcher.js` | Bascule FR/EN |
| Quiz interactif | `quiz.js` | Logique du quiz cybersecurite |
| Styles principaux | `style.css` | Styles globaux (~1500 lignes) |

### Theming

Deux themes disponibles :
- **Theme sombre** (defaut) : Fond bleu marine fonce (#0a0a14)
- **Theme clair** : Fond blanc avec accents bleus

Logos adaptatifs :
- `logo.png` : Logo clair pour theme sombre
- `logo_dark.png` : Logo sombre pour theme clair et PDFs

---

## Couche Logique Metier

### Routes (Blueprints Flask)

| Blueprint | Fichier | Responsabilite |
|-----------|---------|----------------|
| `main` | `routes/main.py` | Routes principales (analyseurs, quiz, contact) |
| `pages` | `routes/pages.py` | Pages statiques (about, services) |
| `content` | `routes/content.py` | Contenu dynamique (regles, scenarios, glossaire) |
| `auth` | `routes/auth.py` | Authentification admin |
| `request_forms` | `routes/request_forms.py` | Formulaires de demande |
| `admin_panel` | `routes/admin_panel.py` | Dashboard admin |
| `admin_routes` | `routes/admin_routes.py` | Routes admin generales |
| `admin_requests` | `routes/admin_requests.py` | Gestion des demandes |

### Services

Architecture modulaire avec separation des responsabilites :

```
services/
├── qrcode/                    # Analyse QR codes
│   ├── analyzer.py            # Service principal (1392 lignes)
│   ├── decoder.py             # Decodage multi-techniques
│   └── patterns.py            # Patterns de detection
│
├── security/                  # Analyse de securite multi-sources
│   ├── analyzer.py            # Orchestrateur
│   ├── virustotal.py
│   ├── google_safe_browsing.py
│   ├── urlhaus.py
│   ├── urlscan.py
│   ├── tracker_detector.py
│   └── url_shortener.py
│
├── github/                    # Analyse de code GitHub
│   ├── analyzer.py            # Service principal (~1800 lignes)
│   └── patterns.py            # 200+ patterns de vulnerabilites
│
├── analyzers/                 # Analyseurs modulaires pour GitHub
│   ├── base_analyzer.py
│   ├── security_analyzer.py
│   ├── dependency_analyzer.py
│   ├── architecture_analyzer.py
│   ├── documentation_analyzer.py
│   ├── performance_analyzer.py
│   ├── git_analyzer.py
│   └── ai_patterns_analyzer.py
│
├── prompt/                    # Analyse de prompts
│   └── analyzer.py
│
├── breach/                    # Verification fuites (HIBP)
│   └── hibp.py
│
├── quiz/                      # Service quiz
│   └── service.py
│
└── pdf/                       # Generation de rapports PDF
    ├── base.py                # Classe de base
    ├── service.py             # Orchestrateur
    ├── qrcode_report.py
    ├── security_report.py
    ├── breach_report.py
    ├── github_report.py
    └── quiz_report.py
```

---

## Couche Donnees

### Modeles SQLAlchemy

#### Analyses

| Modele | Table | Champs principaux |
|--------|-------|-------------------|
| `QRCodeAnalysis` | `qrcode_analyses` | extracted_url, final_url, threat_level, redirect_chain |
| `SecurityAnalysis` | `security_analyses` | input_value, input_type, analysis_results, threat_detected |
| `BreachAnalysis` | `breach_analyses` | email, breach_count, risk_level, breaches_data |
| `PromptAnalysis` | `prompt_analyses` | prompt_text, injection_detected, dangerous_patterns |
| `GitHubCodeAnalysis` | `github_code_analyses` | repo_url, overall_score, security_findings |
| `QuizResult` | `quiz_results` | email, overall_score, category_scores, hibp_summary |

#### Contenu

| Modele | Table | Description |
|--------|-------|-------------|
| `Rule` | `rules` | 20 regles d'or de cybersecurite |
| `Scenario` | `scenarios` | Scenarios de menaces |
| `GlossaryTerm` | `glossary` | Definitions des termes |
| `Tool` | `tools` | Outils recommandes |
| `AttackType` | `attack_types` | Types d'attaques (42+) |
| `News` | `news` | Actualites cybersecurite |
| `Article` | `articles` | Articles de blog |
| `Resource` | `resources` | Ressources externes |

#### Configuration

| Modele | Table | Description |
|--------|-------|-------------|
| `SiteSettings` | `site_settings` | Parametres du site (logos, textes) |
| `SEOMetadata` | `seo_metadata` | Meta-donnees SEO par page |
| `PageContent` | `page_contents` | Contenu editable des pages |

#### Utilisateurs et Logs

| Modele | Table | Description |
|--------|-------|-------------|
| `User` | `users` | Utilisateurs (admin principalement) |
| `Contact` | `contacts` | Messages du formulaire de contact |
| `Newsletter` | `newsletter` | Inscriptions newsletter |
| `RequestSubmission` | `request_submissions` | Demandes de service |
| `ActivityLog` | `activity_logs` | Journal d'activite |
| `SecurityLog` | `security_logs` | Journal de securite |
| `ThreatLog` | `threat_logs` | Menaces detectees |

---

## Flux de Donnees

### Analyse de QR Code

```
Image QR → Decoder → URL Extraction → Redirect Follower
                                            │
            ┌───────────────────────────────┘
            │
            ▼
     ┌──────────────────┐
     │  IP Logger Check  │ (40+ domaines connus)
     │  Tracker Check    │ (100+ raccourcisseurs)
     │  Pattern Check    │ (phishing, TLDs suspects)
     └─────────┬────────┘
               │
               ▼
     ┌──────────────────┐
     │  API Security     │
     │  - VirusTotal     │
     │  - Google SB      │
     │  - URLhaus        │
     │  - URLScan.io     │
     └─────────┬────────┘
               │
               ▼
     ┌──────────────────┐
     │  Score & Report   │
     │  - Threat Level   │
     │  - Save to DB     │
     │  - PDF Generation │
     └──────────────────┘
```

### Analyse GitHub

```
Repo URL → Clone (depth=100) → File Scanning
                                    │
     ┌──────────────────────────────┘
     │
     ├─→ Security Patterns (200+ patterns)
     │     - SQL Injection
     │     - XSS
     │     - Command Injection
     │     - Secrets exposed
     │
     ├─→ Dependency Analysis
     │     - Vulnerable packages
     │     - Outdated versions
     │
     ├─→ Architecture Analysis
     │     - Structure
     │     - Tests presence
     │     - CI/CD
     │
     ├─→ Documentation Analysis
     │     - README quality
     │     - API docs
     │
     ├─→ AI Patterns ("Vibecoding")
     │     - TODOs/FIXMEs
     │     - Empty implementations
     │     - AI-generated patterns
     │
     └─→ Score Calculation
           │
           ▼
     ┌──────────────────┐
     │  Weighted Score   │
     │  - Security: 35%  │
     │  - Deps: 15%      │
     │  - Arch: 15%      │
     │  - Toxic: 10%     │
     │  - Perf: 10%      │
     │  - Git: 5%        │
     │  - Doc: 10%       │
     └──────────────────┘
```

---

## Securite

### Protection CSRF

Tous les formulaires POST sont proteges via Flask-WTF :

```python
csrf = CSRFProtect()
csrf.init_app(app)
```

### Rate Limiting

Limites par defaut :
- 200 requetes par jour
- 50 requetes par heure

### Detection de Menaces

Chaque formulaire passe par `PromptAnalyzerService` pour detecter :
- Injections de code
- Tentatives d'obfuscation
- URLs/IPs suspectes
- Patterns malveillants

### Validation SSRF

Protection contre les attaques SSRF dans les analyseurs :
- Verification des schemas (http/https uniquement)
- Blocage des adresses locales/privees
- Resolution DNS controlee

### Logging

Trois niveaux de journalisation :
1. **ActivityLog** : Actions utilisateur normales
2. **SecurityLog** : Evenements de securite
3. **ThreatLog** : Menaces detectees avec metadata complete

---

## Performance

### Caching

Headers anti-cache pour les pages dynamiques :

```python
response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
```

### Database

- Indexation sur `document_code` pour toutes les analyses
- Relations optimisees avec lazy loading
- Connexion poolee via SQLAlchemy

### PDF Generation

- Generation a la demande (non pre-calculee)
- Stockage en base (LargeBinary)
- Cache apres premiere generation

---

## Internationalisation

Support bilingue FR/EN via Flask-Babel :

```python
def get_locale():
    if 'language' in session:
        return session['language']
    return request.accept_languages.best_match(['fr', 'en']) or 'fr'
```

Stockage de la preference en session avec persistance.

---

## Deploiement

### Developpement

```bash
FLASK_DEBUG=True python main.py
```

### Production

```bash
gunicorn --bind 0.0.0.0:5000 \
         --workers 4 \
         --timeout 120 \
         main:app
```

### Variables d'Environnement Requises

```bash
DATABASE_URL=postgresql://...
ADMIN_PASSWORD=...
SECRET_KEY=...  # Genere automatiquement si absent
```

---

## Extensibilite

### Ajout d'un Nouvel Analyseur

1. Creer le service dans `services/<nom>/`
2. Creer le modele dans `models/analysis.py`
3. Ajouter la route dans `routes/main.py`
4. Creer le template dans `templates/outils/`
5. Ajouter le generateur PDF dans `services/pdf/`
6. Mettre a jour l'admin pour l'historique

### Ajout d'une Source de Securite

1. Creer le service dans `services/security/`
2. Integrer dans `SecurityAnalyzerService`
3. Ajouter la variable d'environnement
4. Mettre a jour la documentation

---

*Architecture CyberConfiance v2.1 - Decembre 2025*
