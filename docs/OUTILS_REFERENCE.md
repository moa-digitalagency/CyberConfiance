# Documentation Technique des Outils CyberConfiance

Ce document décrit tous les outils et services de sécurité disponibles dans la plateforme CyberConfiance.

---

## Table des Matières

1. [TrackerDetectorService](#1-trackerdetectorservice)
2. [URLScanService](#2-urlscanservice)
3. [QRCodeAnalyzerService](#3-qrcodeanalyzerservice)
4. [SecurityAnalyzerService](#4-securityanalyzerservice)
5. [URLShortenerService](#5-urlshortenerservice)
6. [GoogleSafeBrowsingService](#6-googlesafebrowsingservice)
7. [URLhausService](#7-urlhausservice)
8. [VirusTotalService](#8-virustotalservice)
9. [HaveIBeenPwnedService](#9-haveibeenpwnedservice)
10. [Architecture Globale](#10-architecture-globale)

---

## 1. TrackerDetectorService

### Description
Service de détection exhaustive des trackers, IP loggers, réseaux publicitaires et techniques de fingerprinting. C'est le cœur de l'analyse de confidentialité.

### Fichier
`services/tracker_detector_service.py`

### Fonctionnalités

#### Détection d'IP Loggers
- **Liste de domaines malveillants** : 40+ domaines d'IP loggers connus (Grabify, IPLogger, 2no.co, Blasze, etc.)
- **Analyse comportementale** : Détection de patterns suspects dans les URLs

#### Détection de Trackers
- **Trackers analytiques** : Google Analytics, Mixpanel, Amplitude, Segment, Heap
- **Trackers de réseaux sociaux** : Facebook Pixel, Twitter Analytics, LinkedIn Insight
- **Trackers marketing** : HubSpot, Marketo, Pardot
- **Outils de session recording** : Hotjar, FullStory, LogRocket, MouseFlow

#### Réseaux Publicitaires
- **Régies publicitaires** : DoubleClick, Criteo, Taboola, AdRoll, MediaMath
- **DSPs et DMPs** : The Trade Desk, LiveRamp, BlueKai, Oracle Data Cloud

#### Fingerprinting
- **Canvas fingerprinting** : Détection de scripts de fingerprinting canvas
- **WebGL fingerprinting** : Identification via WebGL
- **Audio fingerprinting** : Fingerprinting audio
- **Evercookies et Supercookies** : Détection de cookies persistants

#### Paramètres de Tracking
- **UTM parameters** : utm_source, utm_medium, utm_campaign, etc.
- **Click IDs** : gclid (Google), fbclid (Facebook), msclkid (Microsoft)
- **Identifiants de session** : session_id, visitor_id, etc.

### Méthodes Principales

```python
analyze_url(url: str) -> Dict
```
Analyse complète d'une URL unique.
- **Retourne** : is_ip_logger, is_tracker, is_ad_network, has_fingerprinting, threat_score, detections, recommendations

```python
analyze_redirect_chain(redirect_chain: List[Dict]) -> Dict
```
Analyse une chaîne de redirection complète.
- **Retourne** : ip_loggers_found, trackers_found, tracking_params_all, suspicious_redirects, threat_level

```python
analyze_html_content(html_content: str, base_url: str) -> Dict
```
Analyse le contenu HTML pour détecter trackers intégrés.
- **Retourne** : tracking_scripts, tracking_pixels, fingerprinting_scripts, hidden_iframes

### Score de Menace

| Score | Niveau | Description |
|-------|--------|-------------|
| 0-9 | Safe | Aucune menace détectée |
| 10-29 | Low | Risque faible (paramètres de tracking) |
| 30-49 | Medium | Risque modéré (trackers standard) |
| 50-79 | High | Risque élevé (fingerprinting) |
| 80+ | Critical | Danger (IP logger confirmé) |

---

## 2. URLScanService

### Description
Intégration avec l'API URLScan.io pour l'analyse comportementale des URLs en temps réel.

### Fichier
`services/urlscan_service.py`

### Configuration
```
Variable d'environnement: SECURITY_ANALYSIS_API_KEY_3
```

### Fonctionnalités

- **Scan en temps réel** : Soumission d'URLs pour analyse complète
- **Capture d'écran** : Screenshot automatique de la page
- **Analyse des requêtes** : Détection de requêtes malveillantes
- **Verdicts communautaires** : Votes de la communauté

### Méthodes Principales

```python
scan_url(url: str, visibility: str = "unlisted") -> Dict
```
Lance un scan complet de l'URL.

**Paramètres de visibilité** :
- `public` : Visible par tous
- `unlisted` : Non listé mais accessible avec lien
- `private` : Privé (requiert clé API)

**Retourne** :
- `uuid` : Identifiant unique du scan
- `screenshot_url` : URL de la capture d'écran
- `threat_score` : Score de menace (0-100)
- `threat_level` : safe/low/medium/high/critical
- `page` : Informations sur la page (URL, domain, IP, country)
- `stats` : Statistiques (requêtes, IPs uniques, pays)
- `verdicts` : Verdicts de sécurité
- `brands_detected` : Marques usurpées détectées
- `trackers_detected` : Trackers identifiés

```python
quick_search(domain: str) -> Dict
```
Recherche rapide de scans existants pour un domaine.

### Flux de Traitement

1. Soumission de l'URL via API POST
2. Réception de l'UUID de scan
3. Polling du résultat (max 60s, interval 3s)
4. Parsing et structuration des résultats

---

## 3. QRCodeAnalyzerService

### Description
Service complet d'analyse de QR codes avec protection anti-quishing.

### Fichier
`services/qrcode_analyzer_service.py`

### Fonctionnalités

#### Décodage QR
- Support des formats : PNG, JPG, GIF, BMP, WebP
- Utilisation de pyzbar pour le décodage
- Fallback en niveaux de gris si nécessaire

#### Analyse de Sécurité
- Validation SSRF (Server-Side Request Forgery)
- Détection des URLs raccourcies
- Analyse des patterns de phishing
- Vérification des listes noires

#### Suivi des Redirections
- Maximum 20 redirections suivies
- Détection des redirections HTTP (301, 302, 307, 308)
- Détection des redirections JavaScript
- Détection des meta refresh
- Analyse des iframes pleine page

### Méthodes Principales

```python
decode_qr_from_image(image_data) -> Tuple[str, Optional[str]]
```
Décode un QR code depuis des données image.

```python
analyze_qr_image(image_data, filename=None) -> Dict
```
Analyse complète d'un QR code.

**Retourne** :
- `extracted_url` : URL extraite du QR
- `final_url` : URL finale après redirections
- `redirect_chain` : Chaîne de redirections détaillée
- `threat_level` : Niveau de menace global
- `issues` : Liste des problèmes détectés
- `tracker_analysis` : Résultats de TrackerDetector
- `multi_api_analysis` : Résultats multi-sources

```python
follow_redirects_safely(url: str) -> Dict
```
Suit les redirections de manière sécurisée.

### Mots-clés de Phishing Détectés
- login, signin, verify, account, secure
- password, banking, paypal, amazon
- wallet, crypto, bitcoin, coinbase

### Extensions Suspectes
- .xyz, .top, .club, .online, .site
- .click, .link, .tk, .ml, .cf

---

## 4. SecurityAnalyzerService

### Description
Service central orchestrant toutes les analyses de sécurité multi-sources.

### Fichier
`services/security_analyzer.py`

### Sources Intégrées
1. VirusTotal (SECURITY_ANALYSIS_API_KEY)
2. Google Safe Browsing
3. URLhaus
4. URLScan.io (SECURITY_ANALYSIS_API_KEY_3)
5. TrackerDetector (interne)

### Types d'Analyse

| Type | Description | API Utilisée |
|------|-------------|--------------|
| hash | Hash de fichier (MD5/SHA) | VirusTotal |
| domain | Nom de domaine | VirusTotal + GSB |
| ip | Adresse IP | VirusTotal |
| url | URL complète | Toutes les sources |
| text | Texte brut | Analyse interne |

### Méthodes Principales

```python
analyze(input_value: str, input_type: str) -> Dict
```
Point d'entrée principal pour toutes les analyses.

```python
_combine_url_results(url, multi_source_results, shortener_info) -> Dict
```
Combine les résultats de toutes les sources.

### Calcul du Niveau de Menace

Le niveau de menace final est le maximum des niveaux de toutes les sources :

| Sources avec menace | Niveau résultant |
|---------------------|------------------|
| IP Logger détecté | critique |
| VirusTotal malveillant | critique/élevé |
| Google Safe Browsing | critique |
| URLhaus trouvé | critique |
| Fingerprinting | élevé |
| Trackers multiples | modéré |

---

## 5. URLShortenerService

### Description
Service de détection et d'expansion des URLs raccourcies.

### Fichier
`services/url_shortener_service.py`

### Raccourcisseurs Détectés (100+)

#### Généraux
bit.ly, tinyurl.com, is.gd, cutt.ly, short.io

#### Réseaux Sociaux
t.co (Twitter), lnkd.in (LinkedIn), fb.me (Facebook)

#### Médias
youtu.be, spoti.fi, amzn.to

#### Presse
nyti.ms, wapo.st, cnn.it, bbc.in, reut.rs

#### Monétisés (Risque élevé)
adf.ly, ouo.io, bc.vc, sh.st

### Méthodes Principales

```python
is_shortened_url(url: str) -> Tuple[bool, Optional[str]]
```
Détecte si une URL est raccourcie.

```python
expand_url(url: str, follow_all: bool = True) -> Dict
```
Expand une URL raccourcie et suit toutes les redirections.

**Retourne** :
- `original_url` : URL initiale
- `final_url` : URL finale
- `redirect_chain` : Toutes les redirections
- `multiple_shorteners` : Si plusieurs raccourcisseurs imbriqués

---

## 6. GoogleSafeBrowsingService

### Description
Intégration avec l'API Google Safe Browsing v4.

### Fichier
`services/google_safe_browsing_service.py`

### Types de Menaces Détectées

| Type | Description |
|------|-------------|
| MALWARE | Logiciels malveillants |
| SOCIAL_ENGINEERING | Phishing et ingénierie sociale |
| UNWANTED_SOFTWARE | Logiciels indésirables |
| POTENTIALLY_HARMFUL | Applications potentiellement dangereuses |

### Configuration
```
Variable d'environnement: GOOGLE_SAFE_BROWSING_API_KEY (optionnel)
```

---

## 7. URLhausService

### Description
Intégration avec la base de données URLhaus d'abuse.ch.

### Fichier
`services/urlhaus_service.py`

### Fonctionnalités
- Base de données de malware URLs
- Pas de clé API requise
- Données mises à jour en temps réel

### Types de Menaces
- Malware distribution
- Phishing
- Command & Control (C2)
- Ransomware

---

## 8. VirusTotalService

### Description
Intégration avec l'API VirusTotal v3.

### Fichier
`services/virustotal_service.py` (via security_analyzer.py)

### Configuration
```
Variable d'environnement: SECURITY_ANALYSIS_API_KEY
```

### Fonctionnalités
- Analyse de fichiers (par hash)
- Analyse de domaines
- Analyse d'adresses IP
- Analyse d'URLs
- 70+ moteurs antivirus

---

## 9. HaveIBeenPwnedService

### Description
Vérification des fuites de données via HIBP.

### Fichier
`services/__init__.py` (HaveIBeenPwnedService)

### Configuration
```
Variable d'environnement: HIBP_API_KEY
```

### Fonctionnalités
- Recherche de fuites par email
- Détails des breaches
- Types de données compromises
- Recommandations personnalisées

---

## 10. Architecture Globale

### Diagramme de Flux

```
┌─────────────────────────────────────────────────────────────┐
│                        QR Code Image                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   QRCodeAnalyzerService                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 1. Décodage QR (pyzbar)                                 ││
│  │ 2. Extraction URL                                        ││
│  │ 3. Détection raccourcisseur → URLShortenerService       ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   TrackerDetectorService                     │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ • IP Loggers (40+ domaines)                             ││
│  │ • Trackers (60+ services)                               ││
│  │ • Ad Networks (25+ régies)                              ││
│  │ • Fingerprinting (12+ indicateurs)                      ││
│  │ • Tracking Params (35+ paramètres)                      ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   SecurityAnalyzerService                    │
│  ┌──────────────┬──────────────┬──────────────┬───────────┐│
│  │  VirusTotal  │  Google SB   │   URLhaus    │ URLScan   ││
│  │  (70+ AV)    │  (4 types)   │  (Malware)   │ (Comport.)││
│  └──────────────┴──────────────┴──────────────┴───────────┘│
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Combinaison des Résultats                  ││
│  │         (Niveau de menace le plus élevé)                ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      Rapport Final                           │
│  • Niveau de menace global                                  │
│  • Détails par source                                       │
│  • Recommandations                                          │
│  • Génération PDF                                           │
└─────────────────────────────────────────────────────────────┘
```

### Variables d'Environnement

| Variable | Service | Obligatoire |
|----------|---------|-------------|
| SECURITY_ANALYSIS_API_KEY | VirusTotal | Oui |
| SECURITY_ANALYSIS_API_KEY_3 | URLScan.io | Non |
| HIBP_API_KEY | Have I Been Pwned | Non |
| GOOGLE_SAFE_BROWSING_API_KEY | Google Safe Browsing | Non |
| DATABASE_URL | PostgreSQL | Oui |
| SECRET_KEY | Flask Sessions | Recommandé |

---

## Maintenance et Mises à Jour

### Ajout de nouveaux IP Loggers
Modifier `tracker_detector_service.py` :
```python
self.ip_logger_domains = [
    # ... domaines existants
    'nouveau-ip-logger.com',
]
```

### Ajout de nouveaux Trackers
```python
self.tracker_domains = [
    # ... trackers existants
    'nouveau-tracker.com',
]
```

### Ajout de nouveaux Raccourcisseurs
Modifier `url_shortener_service.py` :
```python
self.shortener_domains = [
    # ... domaines existants
    'nouveau-shortener.io',
]
```

---

*Documentation générée pour CyberConfiance v1.0*
*Dernière mise à jour : Novembre 2024*
