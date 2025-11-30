# Guide Technique Complet - CyberConfiance

Ce document regroupe toute la documentation technique de la plateforme CyberConfiance, incluant l'architecture, les services d'analyse, les integrations API et les procedures de deploiement.

---

## Table des Matieres

1. [Architecture Generale](#1-architecture-generale)
2. [Services d'Analyse](#2-services-danalyse)
3. [Integrations API](#3-integrations-api)
4. [Base de Donnees](#4-base-de-donnees)
5. [Configuration et Deploiement](#5-configuration-et-deploiement)
6. [Securite](#6-securite)
7. [Maintenance](#7-maintenance)

---

## 1. Architecture Generale

### Vue d'ensemble

CyberConfiance est une application Flask de sensibilisation a la cybersecurite avec des outils d'analyse de menaces.

### Structure du projet

```
cyberconfiance/
├── main.py                 # Point d'entree de l'application
├── __init__.py             # Factory de l'application Flask
├── config.py               # Configuration de l'application
├── check_env.py            # Verification des variables d'environnement
├── init_db.py              # Initialisation et migration de la base de donnees
│
├── models/                 # Modeles de base de donnees SQLAlchemy
│   └── __init__.py         # User, Rule, Scenario, QRCodeAnalysis, PromptAnalysis, etc.
│
├── routes/                 # Routes Flask (Blueprints)
│   ├── main.py             # Routes principales
│   ├── admin_panel.py      # Panneau d'administration
│   ├── admin_requests.py   # Gestion des requetes
│   └── request_forms.py    # Formulaires de demande
│
├── services/               # Services metier
│   ├── security_analyzer.py        # Orchestrateur d'analyse multi-sources
│   ├── qrcode_analyzer_service.py  # Analyse QR codes (anti-quishing)
│   ├── prompt_analyzer_service.py  # Analyse prompts (anti-injection)
│   ├── tracker_detector_service.py # Detection trackers et IP loggers
│   ├── url_shortener_service.py    # Gestion URLs raccourcies
│   ├── urlscan_service.py          # Integration URLScan.io
│   ├── google_safe_browsing_service.py
│   ├── urlhaus_service.py
│   └── pdf_service.py              # Generation rapports PDF
│
├── templates/              # Templates Jinja2
├── static/                 # Fichiers statiques (CSS, JS, images)
├── data/                   # Donnees seed et fixtures
└── docs/                   # Documentation
```

### Diagramme de flux des services

```
                    +----------------------+
                    |    Flask Application |
                    +----------+-----------+
                               |
          +--------------------+--------------------+
          |                    |                    |
+---------v--------+  +--------v--------+  +-------v--------+
| QRCodeAnalyzer   |  | SecurityAnalyzer|  | BreachAnalyzer |
| Service          |  | Service         |  | Service        |
+--------+---------+  +--------+--------+  +-------+--------+
         |                     |                   |
         v                     v                   v
+------------------+  +------------------+  +---------------+
| TrackerDetector  |  | Multi-API        |  | HIBP API      |
| URLShortener     |  | Analysis Engine  |  | Integration   |
| PatternAnalyzer  |  | (VT, GSB, etc.)  |  +---------------+
+------------------+  +------------------+
```

---

## 2. Services d'Analyse

### 2.1 QRCodeAnalyzerService

**Fichier:** `services/qrcode_analyzer_service.py`

Service complet d'analyse de QR codes avec protection anti-quishing.

#### Fonctionnalites

1. **Decodage du QR Code**
   - Detecteur OpenCV QRCodeDetector (principal) avec 8 techniques de preprocessing
   - Fallback pyzbar avec multiples methodes de traitement
   - Formats supportes: PNG, JPEG, GIF, WebP, BMP

2. **Analyse des URL**
   - Detection de 100+ raccourcisseurs d'URL (bit.ly, goo.gl, t.co, etc.)
   - Suivi complet de la chaine de redirections (HTTP 301, 302, 307, 308)
   - Detection des redirections JavaScript (18+ patterns)
   - Detection des meta refresh et redirections HTTP header

3. **Detection des Trackers et IP Loggers**
   - Base de donnees de 40+ services d'IP logging connus
   - Detection des parametres de tracking (UTM, fbclid, gclid, etc.)
   - Analyse de fingerprinting (canvas, WebGL, audio)
   - Detection des pixels de tracking et iframes cachees

#### Structure des Resultats

```python
{
    'success': True,
    'extracted_url': 'https://...',
    'final_url': 'https://...',
    'redirect_chain': [...],
    'threat_level': 'critical|high|medium|low|safe',
    'consolidated_summary': {
        'ip_logger_detected': True/False,
        'ip_logger_details': [...],
        'trackers_detected': True/False,
        'tracker_count': int,
        'key_findings': [...],
        'recommendations': [...],
        'overall_verdict': 'critical|high|medium|low|safe'
    }
}
```

### 2.2 SecurityAnalyzerService

**Fichier:** `services/security_analyzer.py`

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

#### Logique de Priorite

1. Si VirusTotal detecte >= 5 moteurs positifs → `threat_level = 'critique'`
2. Si Google Safe Browsing detecte une menace → `threat_level = 'eleve'`
3. Si URLhaus trouve l'URL dans sa base → `threat_level = 'critique'`
4. Agregation des resultats avec score de confiance

### 2.3 TrackerDetectorService

**Fichier:** `services/tracker_detector_service.py`

Service de detection exhaustive des trackers, IP loggers et techniques de fingerprinting.

#### Domaines IP Logger detectes

```
grabify.link, grabify.org, grabify.icu
iplogger.org, iplogger.com
2no.co, blasze.tk, yip.su
ps3cfw.com, lovebird.guru
iptrackeronline.com, ipgrabber.ru
... et 30+ autres services
```

#### Domaines Tracker detectes

```
doubleclick.net, google-analytics.com
facebook.com/tr, analytics.twitter.com
hotjar.com, mixpanel.com, amplitude.com
segment.io, hubspot.com, intercom.io
fullstory.com, logrocket.com, heap.io
```

#### Indicateurs de Fingerprinting

```
fingerprintjs, fpjs.io
canvas-fingerprint, webgl-fingerprint
audio-fingerprint, font-fingerprint
evercookie, supercookie
```

#### Score de Menace

| Score | Niveau | Description |
|-------|--------|-------------|
| 0-9 | Safe | Aucune menace detectee |
| 10-29 | Low | Risque faible (parametres de tracking) |
| 30-49 | Medium | Risque modere (trackers standard) |
| 50-79 | High | Risque eleve (fingerprinting) |
| 80+ | Critical | Danger (IP logger confirme) |

### 2.4 URLShortenerService

**Fichier:** `services/url_shortener_service.py`

Service d'expansion et d'analyse des URLs raccourcies.

#### Services detectes (100+)

- **Generaux**: bit.ly, tinyurl.com, is.gd, cutt.ly, short.io
- **Reseaux Sociaux**: t.co (Twitter), lnkd.in (LinkedIn), fb.me (Facebook)
- **Medias**: youtu.be, spoti.fi, amzn.to
- **Presse**: nyti.ms, wapo.st, cnn.it, bbc.in, reut.rs
- **Monetises (Risque eleve)**: adf.ly, ouo.io, bc.vc, sh.st

#### Niveaux de risque par service

- **Tres faible**: amzn.to, youtu.be, spoti.fi (services officiels)
- **Faible**: bit.ly, tinyurl.com (services populaires)
- **Moyen**: is.gd, cutt.ly (services generiques)
- **Eleve**: adf.ly, ouo.io (monetisation/pub)
- **Critique**: domaines inconnus ou suspects

### 2.5 PromptAnalyzerService

**Fichier:** `services/prompt_analyzer_service.py`

Service de detection des injections de prompts et patterns dangereux.

#### Fonctionnalites

- Detection des patterns d'injection de prompt
- Analyse de code dangereux (eval, exec)
- Detection d'obfuscation
- Extraction et analyse des URLs/IPs dans le texte
- Detection des tentatives de jailbreak

### 2.6 PDFReportService

**Fichier:** `services/pdf_service.py`

Generation de rapports PDF forensiques.

#### Structure des Rapports

1. **Page de Couverture** - Logo, titre, date, QR code de verification
2. **Resume Executif** - Verdict global, score de risque
3. **Details de l'Analyse** - Chaine de redirection, problemes detectes
4. **Sources de Verification** - Resultats par API (VT, GSB, URLhaus, URLScan)
5. **Recommandations** - Actions a entreprendre, conseils de securite

---

## 3. Integrations API

### 3.1 VirusTotal API v3

**Variable:** `SECURITY_ANALYSIS_API_KEY`

| Caracteristique | Valeur |
|-----------------|--------|
| Moteurs AV | 70+ |
| Limite gratuite | 4 req/min, 500/jour |
| Documentation | https://developers.virustotal.com/ |

#### Endpoints utilises

```python
# Analyse d'URL
url_id = vt.url_id(url)
url_obj = client.get_object(f"/urls/{url_id}")

# Analyse de domaine
domain_obj = client.get_object(f"/domains/{domain}")

# Analyse de fichier (hash)
file_obj = client.get_object(f"/files/{file_hash}")
```

### 3.2 Google Safe Browsing API v4

**Variable:** `SECURITY_ANALYSIS_API_KEY_1`

| Caracteristique | Valeur |
|-----------------|--------|
| Limite gratuite | 10,000 req/jour |
| Documentation | https://developers.google.com/safe-browsing |

#### Types de menaces detectees

- `MALWARE` - Logiciels malveillants
- `SOCIAL_ENGINEERING` - Phishing et ingenierie sociale
- `UNWANTED_SOFTWARE` - Logiciels indesirables
- `POTENTIALLY_HARMFUL_APPLICATION` - Applications dangereuses

### 3.3 URLhaus API (abuse.ch)

**Variable:** `SECURITY_ANALYSIS_API_KEY_2`

| Caracteristique | Valeur |
|-----------------|--------|
| Limite | Illimitee |
| Documentation | https://urlhaus-api.abuse.ch/ |

#### Types de menaces

- `malware_download` - Telechargement de malware
- `phishing` - Pages de phishing
- `cryptominer` - Scripts de minage
- `trojan` - Chevaux de Troie
- `botnet` - Serveurs C&C de botnets

### 3.4 URLScan.io API

**Variable:** `SECURITY_ANALYSIS_API_KEY_3`

| Caracteristique | Valeur |
|-----------------|--------|
| Limite gratuite | 5K/jour |
| Documentation | https://urlscan.io/docs/api/ |

#### Donnees retournees

```python
{
    'threat_score': int,           # Score 0-100
    'is_malicious': bool,          # Verdict global
    'brands_detected': list,       # Marques usurpees (1500+ marques)
    'trackers_detected': list,     # Trackers trouves
    'ip_logger_indicators': list,  # Indicateurs d'IP logging
    'screenshot_url': str,         # URL de la capture d'ecran
}
```

### 3.5 Have I Been Pwned API

**Variable:** `HIBP_API_KEY`

| Caracteristique | Valeur |
|-----------------|--------|
| Cout | ~$3.50/mois |
| Documentation | https://haveibeenpwned.com/API/v3 |

#### Fonctionnalites

- Recherche de fuites par email
- Details des breaches
- Types de donnees compromises
- Recommandations personnalisees

---

## 4. Base de Donnees

### Modeles Principaux

```
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

PromptAnalysis
├── id, document_code
├── prompt_text, prompt_length
├── threat_level, threat_detected
├── injection_detected
├── code_detected
├── obfuscation_detected
├── dangerous_patterns (JSON)
├── analysis_results (JSON)
├── pdf_report, pdf_generated_at
├── ip_address, user_agent
└── created_at

SecurityAnalysis
├── id
├── analysis_type (file|url|domain)
├── input_value, input_type
├── threat_level, threat_detected
├── api_results (JSON)
├── pdf_report, pdf_generated_at
└── created_at

BreachAnalysis
├── id, document_code
├── email
├── breach_count, risk_level
├── breaches (JSON)
├── pdf_report, pdf_generated_at
├── ip_address
└── created_at
```

### Autres Tables

- `users` - Utilisateurs et administrateurs
- `rules` - Regles de sensibilisation
- `scenarios` - Scenarios d'attaque
- `glossary` - Termes du glossaire
- `tools` - Outils de securite
- `news` - Actualites
- `contacts` - Messages de contact
- `quiz_results` - Resultats de quiz
- `attack_types` - Types d'attaques
- `newsletter` - Abonnes newsletter
- `activity_logs` - Journaux d'activite
- `security_logs` - Journaux de securite
- `threat_logs` - Journaux de menaces
- `site_settings` - Parametres du site
- `seo_metadata` - Metadonnees SEO
- `request_submissions` - Soumissions de demandes

---

## 5. Configuration et Deploiement

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
SECURITY_ANALYSIS_API_KEY_2=votre_cle_urlhaus
SECURITY_ANALYSIS_API_KEY_3=votre_cle_urlscan
HIBP_API_KEY=votre_cle_hibp
FLASK_DEBUG=False
SECRET_KEY=votre_cle_secrete_aleatoire
```

### Deploiement VPS (Linux)

#### Prerequisites

- Ubuntu 22.04+ ou Debian 11+
- Python 3.11+
- PostgreSQL
- Nginx
- Systemd

#### Installation

```bash
# 1. Installer les dependances
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip postgresql nginx

# 2. Configurer PostgreSQL
sudo -u postgres psql
CREATE DATABASE cyberconfiance;
CREATE USER cyberconf WITH PASSWORD 'votre_mot_de_passe';
GRANT ALL PRIVILEGES ON DATABASE cyberconfiance TO cyberconf;
\q

# 3. Cloner et configurer
cd /var/www
sudo git clone https://github.com/votre-repo/cyberconfiance.git
cd cyberconfiance
sudo python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Initialiser la base de donnees
python init_db.py
```

#### Configuration Systemd

Creer `/etc/systemd/system/cyberconfiance.service`:

```ini
[Unit]
Description=CyberConfiance Web Application
After=network.target postgresql.service

[Service]
Type=notify
User=www-data
Group=www-data
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

#### Configuration Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name votre-domaine.com;

    ssl_certificate /etc/letsencrypt/live/votre-domaine.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/votre-domaine.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /var/www/cyberconfiance/static;
        expires 30d;
    }
}
```

### Deploiement Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    postgresql-client libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_DEBUG=False
ENV PORT=5000

EXPOSE 5000

CMD ["gunicorn", "--bind=0.0.0.0:5000", "--reuse-port", "--workers=2", "main:app"]
```

---

## 6. Securite

### Pratiques Implementees

1. **Pas d'execution de contenu**
   - Les URLs sont analysees sans etre ouvertes dans un navigateur
   - Les fichiers sont hashes sans etre executes

2. **Protection SSRF**
   - Validation des URLs avant requetes
   - Blocage des adresses privees et localhost
   - Protection contre le DNS rebinding

3. **Rate Limiting**
   - Protection contre les abus d'API
   - Limitation par IP

4. **Validation des Entrees**
   - Sanitization des URLs
   - Verification des formats de fichier
   - Limite de taille des uploads (10 MB)

5. **Gestion des Secrets**
   - Variables d'environnement
   - Jamais de cles en dur dans le code

### Checklist de Securite Production

- [ ] Changez le mot de passe admin par defaut
- [ ] Configurez `ADMIN_PASSWORD` different de `admin123`
- [ ] Verifiez que `FLASK_DEBUG=False` en production
- [ ] Utilisez HTTPS (certificat SSL)
- [ ] Configurez un firewall (UFW sur Ubuntu)
- [ ] Mettez a jour regulierement les dependances
- [ ] Activez les sauvegardes automatiques de la base
- [ ] Configurez fail2ban

---

## 7. Maintenance

### Verification au Demarrage

Le script `check_env.py` verifie automatiquement:
1. Presence des variables requises
2. Etat des APIs de securite configurees
3. Affichage du resume de configuration

### Initialisation de la Base de Donnees

```bash
python init_db.py           # Initialisation normale
python init_db.py --check   # Verification des modeles
python init_db.py --reset   # Reinitialisation complete (DANGER!)
python init_db.py --verify-libs  # Verification des bibliotheques
```

### Ajout de nouveaux IP Loggers/Trackers

Modifier `services/tracker_detector_service.py`:

```python
self.ip_logger_domains = [
    # ... domaines existants
    'nouveau-ip-logger.com',
]

self.tracker_domains = [
    # ... trackers existants
    'nouveau-tracker.com',
]
```

### Sauvegardes PostgreSQL

```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/cyberconfiance"
mkdir -p $BACKUP_DIR

pg_dump cyberconfiance | gzip > $BACKUP_DIR/backup_$DATE.sql.gz

# Garder seulement les 30 dernieres sauvegardes
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete
```

### Mise a jour du code

```bash
cd /var/www/cyberconfiance
sudo git pull origin main
source venv/bin/activate
pip install -r requirements.txt
python init_db.py
sudo systemctl restart cyberconfiance
```

---

*Documentation CyberConfiance v2.0 - Novembre 2025*
