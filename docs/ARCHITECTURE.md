# Architecture Technique - CyberConfiance

## Vue d'ensemble

CyberConfiance est une application Flask de sensibilisation à la cybersécurité avec des outils d'analyse de menaces.

## Structure du projet

```
cyberconfiance/
├── main.py                 # Point d'entrée de l'application
├── __init__.py             # Factory de l'application Flask
├── config.py               # Configuration de l'application
├── check_env.py            # Vérification des variables d'environnement
│
├── models/                 # Modèles de base de données SQLAlchemy
│   ├── __init__.py
│   ├── user.py
│   ├── analysis.py
│   └── ...
│
├── routes/                 # Routes Flask (Blueprints)
│   ├── __init__.py
│   ├── main.py
│   ├── tools.py
│   ├── admin.py
│   └── api.py
│
├── services/               # Services métier
│   ├── __init__.py
│   ├── security_analyzer.py       # Orchestrateur d'analyse
│   ├── qrcode_analyzer_service.py # Analyse QR codes
│   ├── tracker_detector_service.py # Détection trackers
│   ├── urlscan_service.py          # Intégration URLScan.io
│   ├── url_shortener_service.py    # Gestion URLs courtes
│   ├── google_safe_browsing_service.py
│   ├── urlhaus_service.py
│   ├── virustotal_service.py
│   ├── pdf_service.py              # Génération rapports PDF
│   └── ...
│
├── templates/              # Templates Jinja2
│   ├── base.html
│   ├── tools/
│   │   ├── qr_analyzer.html
│   │   ├── security_analyzer.html
│   │   └── ...
│   └── ...
│
├── static/                 # Fichiers statiques
│   ├── css/
│   ├── js/
│   └── img/
│
├── migrations/             # Migrations Alembic
│
├── data/                   # Données seed et fixtures
│
└── docs/                   # Documentation
```

## Services d'analyse

### SecurityAnalyzerService

Orchestrateur principal qui coordonne tous les services de sécurité.

```python
class SecurityAnalyzerService:
    def __init__(self):
        self.google_safe_browsing = GoogleSafeBrowsingService()
        self.urlhaus = URLhausService()
        self.url_shortener = URLShortenerService()
        self.urlscan = URLScanService()
        self.tracker_detector = TrackerDetectorService()
    
    def analyze(self, input_value, input_type):
        # Analyse multi-sources
        pass
```

### Flux de données

```
Entrée (URL/Domaine/Hash)
         │
         ▼
┌────────────────────┐
│ SecurityAnalyzer   │
│    (Orchestrateur) │
└────────┬───────────┘
         │
    ┌────┴────┬────────┬────────┬────────┐
    ▼         ▼        ▼        ▼        ▼
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│  VT   │ │  GSB  │ │URLhaus│ │URLScan│ │Tracker│
└───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘
    │         │        │        │        │
    └────┬────┴────────┴────────┴────────┘
         │
         ▼
┌────────────────────┐
│ Résultat combiné   │
│ avec score global  │
└────────────────────┘
```

### Analyse parallèle

Les vérifications sont effectuées en parallèle pour optimiser le temps de réponse:

```python
with ThreadPoolExecutor(max_workers=3) as executor:
    futures = {
        executor.submit(check_google_safe_browsing): 'google_safe_browsing',
        executor.submit(check_urlhaus): 'urlhaus',
        executor.submit(check_urlscan): 'urlscan'
    }
    for future in as_completed(futures):
        source = futures[future]
        multi_source_results[source] = future.result()
```

## Base de données

### PostgreSQL avec SQLAlchemy

- **ORM**: SQLAlchemy avec Flask-SQLAlchemy
- **Migrations**: Alembic
- **Pool**: Gestion automatique des connexions

### Modèles principaux

- `User` - Utilisateurs et administrateurs
- `SecurityAnalysis` - Historique des analyses
- `QRCodeAnalysis` - Analyses de QR codes
- `Rule` - Règles de sensibilisation
- `Scenario` - Scénarios d'attaque
- `News` - Actualités cybersécurité

## Configuration

### Variables d'environnement requises

```bash
# Base de données
DATABASE_URL=postgresql://...

# APIs de sécurité
SECURITY_ANALYSIS_API_KEY=...     # VirusTotal
SECURITY_ANALYSIS_API_KEY_1=...   # Google Safe Browsing
SECURITY_ANALYSIS_API_KEY_2=...   # URLhaus
SECURITY_ANALYSIS_API_KEY_3=...   # URLScan.io

# Application
SECRET_KEY=...
ADMIN_PASSWORD=...
```

### Modes de fonctionnement

- **Développement**: Debug activé, logs détaillés
- **Production**: Optimisations, logs minimaux

## Génération de rapports PDF

Le service `PDFService` utilise PyMuPDF (fitz) pour générer des rapports détaillés.

### Structure des rapports

1. En-tête avec logo et code document
2. Informations de l'analyse
3. Niveau de menace (code couleur)
4. Chaîne de redirection
5. Problèmes de sécurité détectés
6. Sources d'analyse
7. Recommandations
8. QR code de vérification

## Internationalisation

- **Flask-Babel** pour les traductions
- Langues supportées: Français (principal), Anglais
- Fichiers de traduction dans `translations/`

## Sécurité de l'application

### Protection CSRF
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

### Rate Limiting
```python
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["100 per hour"])
```

### Session sécurisée
```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
```

## Déploiement

### Gunicorn (Production)
```bash
gunicorn --bind=0.0.0.0:5000 --reuse-port main:app
```

### Variables de production
```bash
FLASK_DEBUG=False
ADMIN_PASSWORD=<strong_password>
```
