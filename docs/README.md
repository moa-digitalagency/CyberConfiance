# CyberConfiance - Plateforme de Sensibilisation et Protection Cyber

## Presentation

CyberConfiance est une plateforme web de sensibilisation a la cybersecurite destinee au grand public, aux entreprises et aux institutions. Elle propose des outils d'analyse de menaces, du contenu educatif et des services de consultation specialises.

**Version actuelle**: 2.1  
**Mise a jour**: Decembre 2025

---

## Objectifs de la Plateforme

### Mission Principale

Democratiser l'acces a la cybersecurite en offrant des outils gratuits et accessibles pour detecter les menaces avant qu'elles ne causent des dommages.

### Publics Cibles

| Public | Besoins adresses |
|--------|------------------|
| Particuliers | Protection contre le phishing, arnaques QR code, fuites de donnees |
| Entreprises | Sensibilisation des employes, verification de code source, consultation |
| Developpeurs | Analyse de depots GitHub, detection de vulnerabilites |
| Institutions | Signalement de cybercriminalite, fact-checking |

---

## Fonctionnalites Principales

### 1. Outils d'Analyse

| Outil | Description | Public |
|-------|-------------|--------|
| **Analyseur QR Code** | Detection des IP loggers, trackers et liens malveillants dans les QR codes | Tous |
| **Analyseur de Securite** | Verification de fichiers, URLs et domaines via 70+ moteurs antivirus | Tous |
| **Analyseur de Fuite d'Email** | Verification si une adresse email a ete compromise | Tous |
| **Analyseur de Prompt** | Detection des injections dans les textes soumis a l'IA | Developpeurs |
| **Analyseur GitHub** | Audit de securite de depots de code open source (BETA) | Developpeurs |
| **Quiz Cybersecurite** | Evaluation des connaissances avec recommandations personnalisees | Tous |

### 2. Contenu Educatif

- **20 Regles d'Or** : Fondamentaux de la securite numerique
- **Scenarios de Menaces** : Descriptions detaillees des attaques courantes
- **Glossaire** : Definitions des termes techniques
- **Types d'Attaques** : Catalogue de 42+ types d'attaques avec prevention
- **Outils Essentiels** : Liste d'outils de protection recommandes
- **Actualites** : Veille sur les menaces emergentes

### 3. Services Professionnels

| Service | Description |
|---------|-------------|
| **Sensibilisation** | Formations et ateliers pour entreprises et institutions |
| **Fact-Checking** | Verification d'informations et d'arnaques potentielles |
| **Cyberconsultation** | Accompagnement personnalise pour victimes de cybermenaces |
| **Signalement Cybercriminalite** | Formulaire structure pour signaler les crimes en ligne |
| **Enquete OSINT** | Investigation sur sources ouvertes |

---

## Architecture Technique

### Stack Technologique

| Composant | Technologie |
|-----------|-------------|
| Backend | Python 3.11 + Flask 3.x |
| Base de donnees | PostgreSQL (Neon) |
| ORM | SQLAlchemy + Flask-SQLAlchemy |
| Authentification | Flask-Login |
| Administration | Flask-Admin |
| Rate Limiting | Flask-Limiter |
| Generation PDF | PyMuPDF (fitz) |
| Analyse QR | OpenCV + pyzbar |
| Production | Gunicorn |

### APIs Externes

| Service | Usage |
|---------|-------|
| VirusTotal | Analyse multi-moteurs (70+ AV) |
| Google Safe Browsing | Detection phishing/malware temps reel |
| URLhaus (abuse.ch) | Base de donnees malware |
| URLScan.io | Analyse comportementale avec screenshots |
| Have I Been Pwned | Verification fuites de donnees |

---

## Structure du Projet

```
cyberconfiance/
├── main.py                  # Point d'entree
├── __init__.py              # Factory Flask
├── config.py                # Configuration
│
├── models/                  # Modeles de donnees (9 fichiers)
├── routes/                  # Routes Flask (11 fichiers)
├── services/                # Services metier (38 fichiers)
├── templates/               # Templates Jinja2 (68 fichiers)
├── static/                  # CSS, JS, images
├── utils/                   # Utilitaires
├── data/                    # Donnees seed (JSON)
├── migrations/              # Scripts de migration
└── docs/                    # Documentation
```

### Statistiques

| Type | Fichiers | Lignes estimees |
|------|----------|-----------------|
| Python | 42 | ~9,000 |
| Templates HTML | 68 | ~8,000 |
| CSS | 3 | ~1,500 |
| JavaScript | 4 | ~500 |
| **Total** | ~120 | ~20,000+ |

---

## Documentation Disponible

| Document | Contenu |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture technique detaillee |
| [SERVICES.md](SERVICES.md) | Documentation des services d'analyse |
| [API_INTEGRATIONS.md](API_INTEGRATIONS.md) | Integrations API externes |
| [ADMINISTRATION.md](ADMINISTRATION.md) | Guide d'administration |
| [GUIDE_UTILISATEUR.md](GUIDE_UTILISATEUR.md) | Guide pour les utilisateurs finaux |
| [GUIDE_TECHNIQUE.md](GUIDE_TECHNIQUE.md) | Documentation technique complete |
| [GITHUB_ANALYZER_TECHNICAL.md](GITHUB_ANALYZER_TECHNICAL.md) | Documentation de l'analyseur GitHub |

---

## Installation et Deploiement

### Prerequis

- Python 3.11+
- PostgreSQL (ou Neon pour le cloud)
- Cles API pour les services externes (optionnelles mais recommandees)

### Variables d'Environnement

```bash
# Obligatoires en production
DATABASE_URL=postgresql://...
ADMIN_PASSWORD=VotreMotDePasse

# APIs de securite
SECURITY_ANALYSIS_API_KEY=xxx      # VirusTotal
SECURITY_ANALYSIS_API_KEY_1=xxx    # Google Safe Browsing
SECURITY_ANALYSIS_API_KEY_2=xxx    # URLhaus
SECURITY_ANALYSIS_API_KEY_3=xxx    # URLScan.io
HIBP_API_KEY=xxx                   # Have I Been Pwned

# Optionnel
GITHUB_TOKEN=xxx                   # Pour l'analyseur GitHub
```

### Demarrage

```bash
# Installation des dependances
pip install -r requirements.txt

# Lancement en developpement
python main.py

# Lancement en production
gunicorn --bind 0.0.0.0:5000 --workers 4 main:app
```

---

## Securite

### Mesures Implementees

- Protection CSRF sur tous les formulaires
- Rate limiting (200/jour, 50/heure par defaut)
- Detection automatique des injections dans les formulaires
- Validation SSRF sur les URLs analysees
- Logs de securite et d'audit
- Hashage des mots de passe (Werkzeug)
- Sessions securisees

### Bonnes Pratiques

- Ne jamais exposer les cles API dans le code
- Toujours utiliser HTTPS en production
- Configurer un mot de passe admin personnalise
- Activer les notifications pour les logs de menaces

---

## Contribution

Pour contribuer au projet :

1. Examiner l'architecture existante
2. Respecter les conventions de code en place
3. Tester les modifications localement
4. Documenter les changements

---

## Support

- Documentation: `/docs/`
- Contact: Formulaire de contact sur la plateforme
- Signalement de bugs: Via le systeme de support

---

*CyberConfiance - Votre securite numerique accessible a tous*
