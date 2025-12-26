# Services d'Analyse - CyberConfiance

Ce document decrit en detail les services d'analyse de la plateforme, leurs pipelines de traitement, et les patterns detectes.

**Version**: 2.1  
**Mise a jour**: Decembre 2025

---

## Vue d'Ensemble des Services

| Service | Fichier Principal | Fonction |
|---------|-------------------|----------|
| QRCodeAnalyzerService | `services/qrcode/analyzer.py` | Analyse de QR codes anti-quishing |
| SecurityAnalyzerService | `services/security/analyzer.py` | Analyse multi-sources de securite |
| GitHubCodeAnalyzerService | `services/github/analyzer.py` | Audit de code open source |
| PromptAnalyzerService | `services/prompt/analyzer.py` | Detection d'injections |
| HaveIBeenPwnedService | `services/breach/hibp.py` | Verification de fuites |
| QuizService | `services/quiz/service.py` | Evaluation de connaissances |
| PDFReportService | `services/pdf/service.py` | Generation de rapports |

---

## 1. QRCodeAnalyzerService

### Description

Service complet de protection contre le "quishing" (QR code phishing). Detecte les IP loggers, trackers, redirections malveillantes et sites dangereux caches dans les QR codes.

### Pipeline d'Analyse

```
┌─────────────────────────────────────────────────────────────────┐
│ ETAPE 1: DECODAGE DU QR CODE                                    │
│─────────────────────────────────────────────────────────────────│
│ Techniques utilisees (8 methodes de preprocessing):             │
│ 1. OpenCV QRCodeDetector direct                                 │
│ 2. Conversion en niveaux de gris                                │
│ 3. Seuillage binaire (OTSU)                                     │
│ 4. Seuillage adaptatif                                          │
│ 5. Redimensionnement (2x, 3x)                                   │
│ 6. Inversion des couleurs                                       │
│ 7. Fallback: pyzbar                                             │
│ 8. Fallback: ZBar avec parametres ajustes                       │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ ETAPE 2: EXTRACTION ET VALIDATION URL                           │
│─────────────────────────────────────────────────────────────────│
│ - Verification du format URL                                    │
│ - Ajout du schema si manquant                                   │
│ - Validation SSRF (blocage IPs privees/locales)                 │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ ETAPE 3: SUIVI DES REDIRECTIONS                                 │
│─────────────────────────────────────────────────────────────────│
│ Types de redirections detectees:                                │
│ - HTTP 301, 302, 303, 307, 308                                  │
│ - Meta refresh HTML                                             │
│ - JavaScript location changes                                   │
│ - setTimeout/setInterval redirects                              │
│ Maximum: 20 redirections                                        │
│ Timeout: 15 secondes par requete                                │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ ETAPE 4: DETECTION IP LOGGERS                                   │
│─────────────────────────────────────────────────────────────────│
│ 40+ domaines IP logger connus:                                  │
│ grabify.link, iplogger.org, 2no.co, blasze.tk, yip.su,         │
│ ps3cfw.com, lovebird.guru, ipsniff.net, iptracker.link,        │
│ iplogger.ru, iplogger.info, shorturl.at, urlz.fr, ...          │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ ETAPE 5: DETECTION TRACKERS ET RACCOURCISSEURS                  │
│─────────────────────────────────────────────────────────────────│
│ - 100+ raccourcisseurs d'URL connus                             │
│ - Parametres de tracking (utm_*, fbclid, gclid, ...)           │
│ - Detection fingerprinting                                      │
│ - Analyse des sous-domaines suspects                            │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ ETAPE 6: ANALYSE SECURITE MULTI-SOURCES                         │
│─────────────────────────────────────────────────────────────────│
│ APIs consultees:                                                │
│ - VirusTotal (70+ moteurs antivirus)                            │
│ - Google Safe Browsing (phishing/malware)                       │
│ - URLhaus (base de malware abuse.ch)                            │
│ - URLScan.io (analyse comportementale)                          │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ ETAPE 7: CONSOLIDATION ET SCORING                               │
│─────────────────────────────────────────────────────────────────│
│ Niveaux de menace:                                              │
│ - safe: Aucun probleme detecte                                  │
│ - low: Elements mineurs (trackers, raccourcisseurs)             │
│ - medium: Redirections suspectes ou TLDs douteux                │
│ - high: IP logger ou patterns phishing detectes                 │
│ - critical: Malware confirme par APIs de securite               │
└─────────────────────────────────────────────────────────────────┘
```

### Patterns de Detection

#### Mots-cles Phishing

```python
phishing_keywords = [
    'login', 'signin', 'verify', 'update', 'confirm',
    'account', 'secure', 'banking', 'password', 'credential',
    'suspended', 'unusual', 'activity', 'urgent', 'immediately'
]
```

#### TLDs Suspects

```python
suspicious_tlds = [
    '.tk', '.ml', '.ga', '.cf', '.gq',      # Gratuits, abus frequent
    '.top', '.xyz', '.club', '.work',        # Nouveaux TLDs suspects
    '.cam', '.fun', '.monster', '.space'     # TLDs a faible reputation
]
```

---

## 2. SecurityAnalyzerService

### Description

Orchestrateur central coordonnant les analyses de securite multi-sources pour fichiers, URLs et domaines.

### Types d'Analyse

| Type | Description | APIs Utilisees |
|------|-------------|----------------|
| `hash` | Hash de fichier (MD5, SHA-1, SHA-256) | VirusTotal |
| `url` | URL complete | Toutes |
| `domain` | Nom de domaine | VirusTotal, Google SB |
| `ip` | Adresse IP | VirusTotal |
| `file` | Fichier uploade | Calcul hash + VirusTotal |

### Resultats

Structure de reponse :

```python
{
    'threat_detected': True/False,
    'threat_level': 'safe|low|medium|high|critical',
    'malicious': 5,              # Nombre de detections
    'total': 70,                 # Nombre total de moteurs
    'sources': {
        'virustotal': {...},
        'google_safe_browsing': {...},
        'urlhaus': {...},
        'urlscan': {...}
    },
    'recommendations': [...]
}
```

---

## 3. GitHubCodeAnalyzerService

### Description

Service d'audit de securite pour depots GitHub. Analyse statique du code avec detection de 200+ patterns de vulnerabilites.

### Categories de Detection

#### 3.1 Secrets et Credentials (36 patterns)

| Pattern | Exemple | Severite |
|---------|---------|----------|
| AWS Keys | `AKIAIOSFODNN7EXAMPLE` | Critical |
| API Keys generiques | `api_key = "sk-abc..."` | Critical |
| GitHub PAT | `ghp_xxxx...` | Critical |
| OpenAI Keys | `sk-xxxxxxxx...` | Critical |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` | Critical |
| Database URLs | `postgres://user:pass@host` | Critical |
| JWT Tokens | `eyJhbG...` | High |

#### 3.2 Injection SQL (16 patterns)

| Pattern | Risque |
|---------|--------|
| String formatting dans execute() | Critical |
| f-strings dans queries | Critical |
| Concatenation dans cursor.execute() | Critical |
| Template literals avec variables | Critical |

#### 3.3 XSS - Cross-Site Scripting (19 patterns)

| Pattern | Framework | Severite |
|---------|-----------|----------|
| innerHTML = ... + variable | Vanilla JS | High |
| dangerouslySetInnerHTML | React | Medium |
| v-html= | Vue.js | Medium |
| \|safe filter | Django/Jinja2 | Medium |
| eval() avec concatenation | Tous | Critical |

#### 3.4 Command Injection (17 patterns)

| Pattern | Langage | Severite |
|---------|---------|----------|
| os.system() avec variables | Python | Critical |
| shell=True dans subprocess | Python | Critical |
| child_process.exec() | Node.js | Critical |
| shell_exec() | PHP | Critical |

#### 3.5 Path Traversal (17 patterns)

| Pattern | Description |
|---------|-------------|
| open() avec input utilisateur | Python |
| send_file() avec concatenation | Flask |
| require() dynamique | Node.js |
| include() avec variable | PHP |

#### 3.6 Patterns IA "Vibecoding" (31 patterns)

Detection de code genere par IA non verifie :

| Pattern | Signification | Severite |
|---------|---------------|----------|
| `# TODO: implement` | Fonctionnalite non implementee | Low |
| `# FIXME` | Bug connu non corrige | Medium |
| `except: pass` | Exception silencieuse | High |
| `raise NotImplementedError` | Placeholder | Medium |
| `debugger;` | Debug laisse | Medium |
| `lorem ipsum` | Contenu placeholder | Low |

### Calcul des Scores

```
Score Global = security * 0.35
             + dependencies * 0.15
             + architecture * 0.15
             + toxic_ai * 0.10
             + performance * 0.10
             + git_hygiene * 0.05
             + documentation * 0.10
```

Penalites par severite :
- Critical: -15 points
- High: -10 points
- Medium: -5 points
- Low: -2 points
- Info: -1 point

---

## 4. PromptAnalyzerService

### Description

Detection des tentatives d'injection de prompts et de code malveillant dans les textes soumis.

### Patterns Detectes

| Categorie | Exemples |
|-----------|----------|
| Injection de prompt | "Ignore previous instructions", "You are now..." |
| Code dangereux | `eval()`, `exec()`, `Function()` |
| Obfuscation | Base64 suspect, Unicode abuse |
| URLs suspectes | IPs directes, ports non standards |
| Jailbreak | Tentatives de contournement des limites |

### Utilisation

Le service est utilise automatiquement sur :
- Formulaire de contact
- Formulaires de demande de service
- Signalement de cybercriminalite

En cas de detection, l'utilisateur est redirige vers une page d'avertissement et l'incident est enregistre.

---

## 5. HaveIBeenPwnedService

### Description

Verification si une adresse email a ete compromise dans des fuites de donnees connues.

### Fonctionnalites

- Recherche dans la base HIBP (14+ milliards de comptes)
- Details des fuites (date, donnees exposees)
- Recommandations personnalisees selon le niveau de risque

### Niveaux de Risque

| Fuites | Niveau | Recommandations |
|--------|--------|-----------------|
| 0 | safe | Continuer les bonnes pratiques |
| 1-2 | low | Changer les mots de passe concernes |
| 3-5 | medium | Activer 2FA, revoir tous les mots de passe |
| 6+ | high | Actions urgentes, surveillance des comptes |

---

## 6. QuizService

### Description

Evaluation des connaissances en cybersecurite avec questions categorisees et recommandations personnalisees.

### Categories Evaluees

1. Mots de passe et authentification
2. Navigation et emails
3. Reseaux sociaux
4. Appareils et donnees
5. Phishing et arnaques

### Scoring

- Score global sur 100
- Score par categorie
- Integration avec HIBP pour verification email
- Recommandations basees sur les faiblesses identifiees

---

## 7. PDFReportService

### Description

Generation de rapports PDF professionnels pour chaque type d'analyse.

### Types de Rapports

| Type | Service | Contenu |
|------|---------|---------|
| QR Code | `qrcode_report.py` | Redirections, menaces, recommandations |
| Securite | `security_report.py` | Resultats multi-sources, detections |
| Fuite | `breach_report.py` | Liste des fuites, actions recommandees |
| GitHub | `github_report.py` | Score, vulnerabilites, recommandations |
| Quiz | `quiz_report.py` | Scores, analyse, conseils |

### Structure des PDFs

1. **Page de couverture** : Titre, date, code document
2. **Resume executif** : Verdict global, niveau de risque
3. **Details** : Analyse complete avec preuves
4. **Recommandations** : Actions a entreprendre
5. **Pied de page** : Code de verification, timestamp, IP source

### Generation

Les PDFs sont :
- Generes a la demande (premier telechargement)
- Stockes en base pour reutilisation
- Identifies par un code document unique

---

## Limites et Considerations

### Rate Limiting APIs

| Service | Limite Gratuite |
|---------|-----------------|
| VirusTotal | 4 req/min, 500/jour |
| Google Safe Browsing | 10,000/jour |
| URLhaus | Illimite |
| URLScan.io | 5,000/jour |
| HIBP | Variable selon plan |

### Temps de Reponse

| Service | Temps Moyen |
|---------|-------------|
| QR Code Analysis | 3-8 secondes |
| Security Analysis | 2-5 secondes |
| GitHub Analysis | 30-120 secondes (selon taille) |
| Prompt Analysis | < 1 seconde |
| Breach Check | 1-2 secondes |

### Limitations Connues

- L'analyseur GitHub est en BETA et peut avoir des faux positifs
- Les APIs peuvent etre indisponibles temporairement
- Certains raccourcisseurs d'URL bloquent les robots
- Les fichiers > 200 MB ne sont pas supportes

---

*Services CyberConfiance v2.1 - Decembre 2025*
