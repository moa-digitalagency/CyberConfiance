# Integrations API - CyberConfiance

Ce document detaille les integrations avec les APIs externes de securite utilisees par la plateforme.

**Version**: 2.1  
**Mise a jour**: Decembre 2025

---

## Vue d'Ensemble

CyberConfiance integre 5 sources de donnees de securite pour offrir une analyse multi-couches des menaces.

| Service | Variable | Obligatoire | Cout |
|---------|----------|-------------|------|
| VirusTotal | `SECURITY_ANALYSIS_API_KEY` | Recommande | Gratuit (limite) |
| Google Safe Browsing | `SECURITY_ANALYSIS_API_KEY_1` | Optionnel | Gratuit |
| URLhaus | `SECURITY_ANALYSIS_API_KEY_2` | Optionnel | Gratuit |
| URLScan.io | `SECURITY_ANALYSIS_API_KEY_3` | Optionnel | Gratuit |
| Have I Been Pwned | `HIBP_API_KEY` | Optionnel | ~$3.50/mois |

---

## 1. VirusTotal API v3

### Description

Service de reference pour l'analyse de fichiers et URLs via 70+ moteurs antivirus.

### Configuration

```bash
SECURITY_ANALYSIS_API_KEY=votre_cle_virustotal
```

### Obtenir une Cle

1. Creer un compte sur https://www.virustotal.com
2. Aller dans "API Key" dans les parametres du profil
3. Copier la cle API

### Limites

| Plan | Requetes/minute | Requetes/jour |
|------|-----------------|---------------|
| Gratuit | 4 | 500 |
| Premium | Variable | Variable |

### Fonctionnalites Utilisees

| Endpoint | Usage |
|----------|-------|
| `/urls/{id}` | Analyse d'URL |
| `/files/{id}` | Analyse de fichier par hash |
| `/domains/{domain}` | Reputation de domaine |
| `/ip_addresses/{ip}` | Reputation d'IP |

### Exemple de Reponse

```python
{
    'malicious': 5,
    'suspicious': 2,
    'harmless': 63,
    'undetected': 0,
    'timeout': 0,
    'categories': {
        'Google Safebrowsing': 'safe',
        'Kaspersky': 'malware',
        ...
    }
}
```

### Implementation

Fichier : `services/security/virustotal.py`

```python
import vt

client = vt.Client(api_key)
url_id = vt.url_id(url)
url_obj = client.get_object(f"/urls/{url_id}")
```

---

## 2. Google Safe Browsing API v4

### Description

Base de donnees Google de sites de phishing et malware, mise a jour en temps reel.

### Configuration

```bash
SECURITY_ANALYSIS_API_KEY_1=votre_cle_google
```

### Obtenir une Cle

1. Aller sur https://console.cloud.google.com
2. Creer un projet ou selectionner un existant
3. Activer "Safe Browsing API" dans la bibliotheque d'APIs
4. Creer une cle API dans "Identifiants"

### Limites

| Plan | Requetes/jour |
|------|---------------|
| Gratuit | 10,000 |

### Types de Menaces Detectees

| Type | Description |
|------|-------------|
| MALWARE | Sites distribuant des logiciels malveillants |
| SOCIAL_ENGINEERING | Phishing et arnaques |
| UNWANTED_SOFTWARE | Logiciels indesirables |
| POTENTIALLY_HARMFUL_APPLICATION | Applications potentiellement dangereuses |

### Implementation

Fichier : `services/security/google_safe_browsing.py`

```python
def check_url(url, api_key):
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "cyberconfiance", "clientVersion": "2.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(f"{endpoint}?key={api_key}", json=payload)
    return response.json()
```

---

## 3. URLhaus API (abuse.ch)

### Description

Base de donnees communautaire de distribution de malware geree par abuse.ch.

### Configuration

```bash
SECURITY_ANALYSIS_API_KEY_2=optionnel  # Pas de cle requise
```

### Caracteristiques

- **Gratuit et sans limite**
- Mise a jour en continu par la communaute
- Focus sur les URLs de distribution de malware

### Types de Menaces

| Tag | Description |
|-----|-------------|
| malware_download | Telechargement de malware |
| phishing | Site de phishing |
| cryptominer | Minage de cryptomonnaie |
| trojan | Cheval de Troie |
| botnet | Reseau de bots |
| ransomware | Logiciel de rancon |

### Implementation

Fichier : `services/security/urlhaus.py`

```python
def check_url(url):
    response = requests.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url}
    )
    data = response.json()
    return {
        'found': data.get('query_status') == 'ok',
        'threat_type': data.get('threat'),
        'tags': data.get('tags', [])
    }
```

---

## 4. URLScan.io API

### Description

Service d'analyse comportementale avec capture d'ecran et detection de trackers.

### Configuration

```bash
SECURITY_ANALYSIS_API_KEY_3=votre_cle_urlscan
```

### Obtenir une Cle

1. Creer un compte sur https://urlscan.io
2. Aller dans Account > API Key
3. Copier la cle

### Limites

| Plan | Requetes/jour | Scans/jour |
|------|---------------|------------|
| Gratuit | 5,000 | 50 (publics) |
| Premium | Variable | Variable |

### Fonctionnalites

| Feature | Description |
|---------|-------------|
| Screenshots | Capture d'ecran du site |
| Trackers | Detection des trackers |
| Technologies | Stack technologique detecte |
| Brand Detection | Identification de marques imitees |
| Certificates | Analyse SSL/TLS |

### Implementation

Fichier : `services/security/urlscan.py`

```python
def submit_scan(url, api_key):
    response = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers={"API-Key": api_key},
        json={"url": url, "visibility": "public"}
    )
    return response.json()

def get_result(scan_id, api_key):
    response = requests.get(
        f"https://urlscan.io/api/v1/result/{scan_id}/",
        headers={"API-Key": api_key}
    )
    return response.json()
```

---

## 5. Have I Been Pwned API v3

### Description

Base de donnees de fuites de donnees contenant 14+ milliards de comptes compromis.

### Configuration

```bash
HIBP_API_KEY=votre_cle_hibp
```

### Obtenir une Cle

1. Aller sur https://haveibeenpwned.com/API/Key
2. Acheter une cle API (~$3.50/mois)
3. La cle est liee a votre email

### Limites

| Plan | Requetes/minute |
|------|-----------------|
| Standard | 10 |

### Endpoints Utilises

| Endpoint | Usage |
|----------|-------|
| `/breachedaccount/{email}` | Fuites pour un email |
| `/breach/{name}` | Details d'une fuite specifique |

### Donnees Retournees

```python
{
    'Name': 'LinkedIn',
    'BreachDate': '2012-05-05',
    'PwnCount': 164611595,
    'DataClasses': [
        'Email addresses',
        'Passwords'
    ],
    'IsSensitive': False,
    'IsVerified': True
}
```

### Implementation

Fichier : `services/breach/hibp.py`

```python
def check_email(email, api_key):
    response = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers={
            "hibp-api-key": api_key,
            "user-agent": "CyberConfiance"
        },
        params={"truncateResponse": "false"}
    )
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return []  # Pas de fuite
    else:
        raise Exception(f"HIBP Error: {response.status_code}")
```

---

## 6. GitHub API (Optionnel)

### Description

Utilisee pour l'analyseur de code GitHub afin d'acceder a l'API Code Scanning.

### Configuration

```bash
GITHUB_TOKEN=votre_token_github
```

### Obtenir un Token

1. Aller dans Settings > Developer settings > Personal access tokens
2. Creer un "Fine-grained token" avec permissions :
   - `public_repo` (lecture)
   - `code_scanning_alerts` (optionnel)

### Avantages

| Sans Token | Avec Token |
|------------|------------|
| 60 req/heure | 5000 req/heure |
| Pas de Code Scanning | Acces Code Scanning |
| Depots publics uniquement | Depots prives possibles |

---

## Gestion des Erreurs

### Strategie de Fallback

Si une API est indisponible, le systeme :
1. Continue avec les autres sources
2. Retourne un resultat partiel
3. Indique les sources non disponibles

### Codes d'Erreur Geres

| Code | Signification | Action |
|------|---------------|--------|
| 401 | Cle invalide | Log erreur, continuer sans |
| 403 | Limite atteinte | Log warning, continuer sans |
| 429 | Rate limit | Attendre et reessayer |
| 500+ | Erreur serveur | Continuer sans cette source |

### Logging

Chaque appel API est enregistre avec :
- Timestamp
- Service appele
- Resultat (succes/echec)
- Temps de reponse
- Message d'erreur (si applicable)

---

## Bonnes Pratiques

### Securite des Cles

- Ne jamais exposer les cles dans le code
- Utiliser les variables d'environnement
- Rotation reguliere des cles
- Limiter les permissions au minimum

### Performance

- Mise en cache des resultats (60 secondes)
- Appels paralleles aux APIs
- Timeout de 10 secondes par API
- Circuit breaker pour APIs instables

### Conformite

- Respecter les CGU de chaque service
- Ne pas stocker les donnees sensibles plus longtemps que necessaire
- Informer les utilisateurs de l'utilisation de services tiers

---

## Tableau Recapitulatif

| Service | Endpoint | Limite Gratuite | Latence Moyenne |
|---------|----------|-----------------|-----------------|
| VirusTotal | api.virustotal.com | 500/jour | 1-3s |
| Google SB | safebrowsing.googleapis.com | 10,000/jour | 200-500ms |
| URLhaus | urlhaus-api.abuse.ch | Illimite | 500ms-1s |
| URLScan.io | urlscan.io/api | 5,000/jour | 2-5s |
| HIBP | haveibeenpwned.com/api | 10/min | 500ms-1s |

---

*Integrations API CyberConfiance v2.1 - Decembre 2025*
