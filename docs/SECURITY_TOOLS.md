# Outils de Sécurité - CyberConfiance

Ce document décrit tous les outils d'analyse de sécurité intégrés dans la plateforme CyberConfiance.

## Vue d'ensemble

CyberConfiance utilise une approche multi-sources pour analyser les menaces. Chaque URL, domaine ou fichier est vérifié par plusieurs services indépendants pour maximiser la détection.

---

## 1. VirusTotal API

### Description
VirusTotal agrège plus de 70 moteurs antivirus et services de détection pour analyser les fichiers, URLs, domaines et adresses IP.

### Fonctionnalités
- Analyse d'URLs avec 70+ moteurs de détection
- Vérification de hash de fichiers
- Analyse de domaines et IPs
- Historique des analyses

### Configuration
- **Variable d'environnement**: `SECURITY_ANALYSIS_API_KEY`
- **Documentation API**: https://developers.virustotal.com/

### Données retournées
```python
{
    'malicious': int,      # Nombre de détections malveillantes
    'suspicious': int,     # Nombre de détections suspectes
    'harmless': int,       # Nombre de sources considérant comme sûr
    'total': int,          # Total des sources consultées
    'categories': dict,    # Catégories du site
    'threat_level': str    # Niveau de menace calculé
}
```

---

## 2. Google Safe Browsing API

### Description
Service de Google qui protège contre le phishing, les malwares et les logiciels indésirables.

### Fonctionnalités
- Détection de phishing
- Détection de malwares
- Détection de logiciels indésirables
- Détection d'applications potentiellement dangereuses

### Configuration
- **Variable d'environnement**: `SECURITY_ANALYSIS_API_KEY_1`
- **Documentation API**: https://developers.google.com/safe-browsing

### Types de menaces détectées
- `MALWARE` - Logiciels malveillants
- `SOCIAL_ENGINEERING` - Phishing et ingénierie sociale
- `UNWANTED_SOFTWARE` - Logiciels indésirables
- `POTENTIALLY_HARMFUL_APPLICATION` - Applications dangereuses

---

## 3. URLhaus (abuse.ch)

### Description
Projet de abuse.ch qui maintient une base de données d'URLs malveillantes utilisées pour distribuer des malwares.

### Fonctionnalités
- Détection de distribution de malwares
- Identification des types de menaces (trojans, ransomware, etc.)
- Informations sur les payloads associés

### Configuration
- **Variable d'environnement**: `SECURITY_ANALYSIS_API_KEY_2`
- **Documentation API**: https://urlhaus-api.abuse.ch/

### Types de menaces
- `malware_download` - Téléchargement de malware
- `phishing` - Pages de phishing
- `cryptominer` - Scripts de minage
- `trojan` - Chevaux de Troie
- `botnet` - Serveurs C&C de botnets

---

## 4. URLScan.io

### Description
Service d'analyse comportementale qui scanne les URLs dans un environnement sandbox et capture les comportements.

### Fonctionnalités
- Capture d'écran de la page
- Analyse du DOM et des scripts
- Détection des trackers et pixels
- Analyse des requêtes réseau
- Détection d'usurpation de marque (1500+ marques)
- Score de menace comportemental

### Configuration
- **Variable d'environnement**: `SECURITY_ANALYSIS_API_KEY_3`
- **Documentation API**: https://urlscan.io/docs/api/

### Données retournées
```python
{
    'threat_score': int,           # Score 0-100
    'is_malicious': bool,          # Verdict global
    'brands_detected': list,       # Marques usurpées
    'trackers_detected': list,     # Trackers trouvés
    'ip_logger_indicators': list,  # Indicateurs d'IP logging
    'screenshot_url': str,         # URL de la capture d'écran
    'stats': {
        'total_requests': int,
        'malicious_requests': int,
        'ads_blocked': int
    }
}
```

---

## 5. TrackerDetectorService (Interne)

### Description
Service développé en interne pour la détection exhaustive des trackers, IP loggers et techniques de suivi.

### Fonctionnalités
- **Détection d'IP Loggers**: Grabify, iplogger, 2no.co, etc.
- **Détection de Trackers**: Google Analytics, Facebook Pixel, etc.
- **Détection de Fingerprinting**: Canvas, WebGL, Audio fingerprinting
- **Analyse des paramètres de tracking**: UTM, gclid, fbclid, etc.
- **Détection de pixels de tracking**: Images 1x1, balises invisibles
- **Analyse des chaînes de redirection**: Détection à chaque étape

### Domaines IP Logger détectés
```
grabify.link, grabify.org, grabify.icu
iplogger.org, iplogger.com
2no.co, blasze.tk, yip.su
ps3cfw.com, lovebird.guru
iptrackeronline.com, ipgrabber.ru
```

### Domaines Tracker détectés
```
doubleclick.net, google-analytics.com
facebook.com/tr, analytics.twitter.com
hotjar.com, mixpanel.com, amplitude.com
segment.io, hubspot.com, intercom.io
fullstory.com, logrocket.com, heap.io
```

### Indicateurs de Fingerprinting
```
fingerprintjs, fpjs.io
canvas-fingerprint, webgl-fingerprint
audio-fingerprint, font-fingerprint
evercookie, supercookie
```

### Paramètres de tracking surveillés
```
utm_source, utm_medium, utm_campaign
gclid, fbclid, msclkid
_ga, _gid, _gac
click_id, tracking_id, campaign_id
visitor_id, session_id
```

---

## 6. URLShortenerService (Interne)

### Description
Service d'expansion et d'analyse des URLs raccourcies.

### Fonctionnalités
- Détection de 100+ services de raccourcissement
- Expansion récursive des URLs
- Suivi de la chaîne de redirection complète
- Détection de raccourcisseurs multiples (technique d'obfuscation)
- Évaluation du risque par service

### Services détectés
```
bit.ly, tinyurl.com, t.co, goo.gl
ow.ly, buff.ly, is.gd, cutt.ly
shorturl.at, rb.gy, short.io
adf.ly, ouo.io (ad-based - risque élevé)
linktr.ee, smarturl.it
amzn.to, spoti.fi (légitimes)
```

### Niveaux de risque par service
- **Très faible**: amzn.to, youtu.be, spoti.fi (services officiels)
- **Faible**: bit.ly, tinyurl.com (services populaires)
- **Moyen**: is.gd, cutt.ly (services génériques)
- **Élevé**: adf.ly, ouo.io (monétisation/pub)
- **Critique**: domaines inconnus ou suspects

---

## 7. QRCodeAnalyzerService

### Description
Service complet d'analyse des QR codes combinant décodage et analyse de sécurité.

### Fonctionnalités
- Décodage de QR codes depuis images
- Suivi des redirections HTTP et JavaScript
- Détection des meta refresh
- Analyse des patterns suspects dans les URLs
- Intégration de tous les services de sécurité

### Flux d'analyse
1. Décodage du QR code
2. Extraction de l'URL
3. Détection URL raccourcie
4. Analyse des patterns suspects
5. Détection des trackers/IP loggers
6. Suivi des redirections
7. Analyse multi-API (VT, GSB, URLhaus, URLScan)
8. Vérification blacklist
9. Calcul du niveau de menace final

---

## Architecture d'intégration

```
┌─────────────────────────────────────────────────────────────┐
│                    QRCodeAnalyzerService                     │
│                   SecurityAnalyzerService                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  VirusTotal  │  │ Google Safe  │  │   URLhaus    │
│     API      │  │  Browsing    │  │    API       │
└──────────────┘  └──────────────┘  └──────────────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  URLScan.io  │  │   Tracker    │  │     URL      │
│     API      │  │  Detector    │  │  Shortener   │
└──────────────┘  └──────────────┘  └──────────────┘
```

---

## Calcul du niveau de menace

### Niveaux
- **Critique**: IP logger détecté, malware confirmé, blacklisté
- **Élevé**: Phishing détecté, fingerprinting, menaces multiples
- **Modéré**: Trackers détectés, URL suspecte, redirections
- **Faible**: Paramètres de tracking, risques mineurs
- **Sûr**: Aucune menace détectée

### Formule de score
```python
score = 0

# IP Logger: +80
# Fingerprinting: +50
# Trackers: +30
# Paramètres tracking: +10
# Pixel tracking: +25
# Réseaux pub: +20

if score >= 80: level = 'critical'
elif score >= 50: level = 'high'
elif score >= 30: level = 'medium'
elif score >= 10: level = 'low'
else: level = 'safe'
```

---

## Recommandations de sécurité

### IP Logger détecté
1. Ne cliquez pas sur ce lien
2. Votre adresse IP et localisation seront capturées
3. Ne partagez pas ce lien

### Fingerprinting détecté
1. Ce site identifie votre appareil de manière unique
2. Utilisez un navigateur avec protection anti-fingerprint
3. Considérez l'utilisation de Tor Browser

### Trackers détectés
1. Utilisez un bloqueur de trackers
2. Considérez l'utilisation d'un VPN
3. Nettoyez régulièrement vos cookies

### Phishing détecté
1. Ne saisissez aucune information personnelle
2. Vérifiez l'URL officielle auprès de l'organisme
3. Signalez le site aux autorités

---

## Mise à jour des listes

Les listes de domaines malveillants, trackers et IP loggers sont maintenues dans:
- `services/tracker_detector_service.py`
- `services/url_shortener_service.py`

Pour ajouter un nouveau domaine:
1. Identifier la catégorie (ip_logger, tracker, ad_network)
2. Ajouter à la liste appropriée
3. Tester avec une URL contenant ce domaine
4. Redémarrer l'application
