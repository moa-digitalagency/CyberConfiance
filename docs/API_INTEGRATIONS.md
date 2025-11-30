# Intégrations API - CyberConfiance

Ce document détaille toutes les intégrations API externes utilisées par CyberConfiance.

## Résumé des APIs

| Service | Variable d'environnement | Gratuit | Limite |
|---------|-------------------------|---------|--------|
| VirusTotal | `SECURITY_ANALYSIS_API_KEY` | Oui | 4 req/min |
| Google Safe Browsing | `SECURITY_ANALYSIS_API_KEY_1` | Oui | 10K/jour |
| URLhaus | `SECURITY_ANALYSIS_API_KEY_2` | Oui | Illimité |
| URLScan.io | `SECURITY_ANALYSIS_API_KEY_3` | Oui | 5K/jour |

---

## 1. VirusTotal API v3

### Obtenir une clé API
1. Créer un compte sur https://www.virustotal.com
2. Aller dans Profil → API Key
3. Copier la clé

### Configuration
```bash
SECURITY_ANALYSIS_API_KEY=your_virustotal_api_key
```

### Endpoints utilisés

#### Analyse d'URL
```python
import vt

client = vt.Client(api_key)
url_id = vt.url_id(url)
url_obj = client.get_object(f"/urls/{url_id}")
```

#### Analyse de domaine
```python
domain_obj = client.get_object(f"/domains/{domain}")
```

#### Analyse de fichier (hash)
```python
file_obj = client.get_object(f"/files/{file_hash}")
```

### Limites
- **Gratuit**: 4 requêtes/minute, 500/jour, 15.5K/mois
- **Premium**: Limites plus élevées

### Gestion des erreurs
```python
try:
    url_obj = client.get_object(f"/urls/{url_id}")
except vt.APIError as e:
    if e.code == 'NotFoundError':
        # URL non dans la base, soumettre pour analyse
        analysis = client.scan_url(url)
```

---

## 2. Google Safe Browsing API v4

### Obtenir une clé API
1. Aller sur https://console.cloud.google.com
2. Créer un projet
3. Activer "Safe Browsing API"
4. Créer des identifiants (Clé API)

### Configuration
```bash
SECURITY_ANALYSIS_API_KEY_1=your_google_api_key
```

### Endpoint
```
POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}
```

### Requête
```python
payload = {
    "client": {
        "clientId": "cyberconfiance",
        "clientVersion": "1.0.0"
    },
    "threatInfo": {
        "threatTypes": [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": url}]
    }
}

response = requests.post(
    f"{base_url}?key={api_key}",
    json=payload,
    timeout=10
)
```

### Réponse (menace détectée)
```json
{
    "matches": [
        {
            "threatType": "MALWARE",
            "platformType": "ANY_PLATFORM",
            "threat": {"url": "http://malicious.com"}
        }
    ]
}
```

### Limites
- **Gratuit**: 10,000 requêtes/jour

---

## 3. URLhaus API (abuse.ch)

### Obtenir une clé API
1. Aller sur https://urlhaus.abuse.ch
2. S'inscrire
3. Demander une clé API

### Configuration
```bash
SECURITY_ANALYSIS_API_KEY_2=your_urlhaus_api_key
```

### Endpoint
```
POST https://urlhaus-api.abuse.ch/v1/url/
```

### Requête
```python
headers = {'Auth-Key': api_key}
data = {'url': url}

response = requests.post(
    f"{base_url}/url/",
    headers=headers,
    data=data,
    timeout=10
)
```

### Réponse (URL malveillante)
```json
{
    "query_status": "ok",
    "url": "http://malicious.com/malware.exe",
    "url_status": "online",
    "threat": "malware_download",
    "tags": ["exe", "trojan"],
    "payloads": [
        {
            "filename": "malware.exe",
            "file_type": "exe",
            "signature": "TrojanGeneric"
        }
    ]
}
```

### Limites
- **Gratuit**: Pas de limite documentée

---

## 4. URLScan.io API

### Obtenir une clé API
1. Créer un compte sur https://urlscan.io
2. Aller dans Profil → Add API key
3. Copier la clé

### Configuration
```bash
SECURITY_ANALYSIS_API_KEY_3=your_urlscan_api_key
```

### Soumettre un scan

```python
headers = {
    'Content-Type': 'application/json',
    'API-Key': api_key
}

data = {
    'url': url,
    'visibility': 'unlisted',  # public, unlisted, private
    'tags': ['cyberconfiance', 'security-check']
}

response = requests.post(
    'https://urlscan.io/api/v1/scan/',
    headers=headers,
    json=data,
    timeout=15
)

uuid = response.json()['uuid']
```

### Récupérer les résultats

```python
# Attendre que l'analyse soit terminée (polling)
result = requests.get(
    f'https://urlscan.io/api/v1/result/{uuid}/',
    timeout=10
)
```

### Réponse
```json
{
    "task": {
        "uuid": "...",
        "reportURL": "https://urlscan.io/result/...",
        "screenshotURL": "https://urlscan.io/screenshots/..."
    },
    "page": {
        "url": "https://example.com",
        "domain": "example.com",
        "ip": "93.184.216.34",
        "country": "US"
    },
    "verdicts": {
        "overall": {
            "malicious": false,
            "score": 0
        },
        "brands": []
    },
    "stats": {
        "requests": 42,
        "malicious": 0,
        "adBlocked": 5
    }
}
```

### Limites
- **Gratuit**: Quotas par minute/heure/jour
- Vérifier: https://urlscan.io/user/quotas/

### Recherche historique

```python
response = requests.get(
    'https://urlscan.io/api/v1/search/',
    params={
        'q': f'domain:{domain}',
        'size': 5
    },
    timeout=10
)
```

---

## 5. Have I Been Pwned API (Optionnel)

### Configuration
```bash
HIBP_API_KEY=your_hibp_api_key
```

### Endpoint
```
GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
```

### Limites
- **Payant**: ~$3.50/mois

---

## Gestion des erreurs communes

### Timeout
```python
try:
    response = requests.get(url, timeout=10)
except requests.exceptions.Timeout:
    return {'error': True, 'message': 'Délai dépassé'}
```

### Rate Limiting
```python
if response.status_code == 429:
    return {'error': True, 'message': 'Limite de requêtes atteinte'}
```

### Clé invalide
```python
if response.status_code == 401:
    return {'error': True, 'message': 'Clé API invalide'}
```

---

## Bonnes pratiques

1. **Ne jamais exposer les clés API** dans le code
2. **Utiliser des variables d'environnement** pour la configuration
3. **Implémenter des timeouts** sur toutes les requêtes
4. **Gérer les limites de rate** avec retry exponential
5. **Logger les erreurs** sans exposer les clés
6. **Valider les entrées** avant d'appeler les APIs
7. **Cacher les résultats** pour éviter les requêtes répétées
