# Guide Technique - CyberConfiance

## Architecture des Services d'Analyse

### Vue d'ensemble

CyberConfiance utilise une architecture modulaire avec plusieurs services specialises qui communiquent entre eux pour fournir des analyses de securite completes.

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
| PatternAnalyzer  |  | (VirusTotal,     |  +---------------+
+------------------+  | Google, URLhaus) |
                      +------------------+
```

---

## Service: QRCodeAnalyzerService

### Localisation
`services/qrcode_analyzer_service.py`

### Fonctionnement

1. **Decodage du QR Code**
   - Utilise la bibliotheque `zbar` pour decoder les images QR
   - Supporte les formats: PNG, JPEG, GIF, WebP
   - Extraction des donnees brutes (URL, texte, vCard, etc.)

2. **Analyse des URL**
   - Detection des raccourcisseurs d'URL (bit.ly, goo.gl, etc.)
   - Suivi complet de la chaine de redirections (HTTP 301, 302, 307)
   - Detection des redirections JavaScript dans le code source

3. **Detection des Trackers**
   - Base de donnees de 50+ services d'IP logging connus
   - Detection des parametres de tracking (UTM, fbclid, etc.)
   - Analyse de fingerprinting (canvas, WebGL, etc.)

4. **Consolidation des Resultats**
   ```python
   def _create_consolidated_summary(self, result: dict) -> dict:
       """
       Agrege tous les resultats d'analyse en un verdict unique.
       Elimine les redondances entre:
       - tracker_analysis (URL initiale)
       - chain_tracker_analysis (chaine de redirection)
       - multi_api_analysis (APIs externes)
       """
   ```

### Structure des Resultats

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

---

## Service: SecurityAnalyzerService

### Localisation
`services/security_analyzer.py`

### APIs Integrees

| Variable | Service | Fonction |
|----------|---------|----------|
| `SECURITY_ANALYSIS_API_KEY` | VirusTotal | Analyse multi-moteurs (70+) |
| `SECURITY_ANALYSIS_API_KEY_1` | Google Safe Browsing | Phishing/Malware temps reel |
| `SECURITY_ANALYSIS_API_KEY_2` | URLhaus (abuse.ch) | Base de malware |
| `SECURITY_ANALYSIS_API_KEY_3` | URLScan.io | Analyse comportementale |

### Fonctionnement Multi-API

```python
def analyze(self, target, analysis_type):
    """
    Analyse un fichier, URL ou domaine via plusieurs APIs.
    
    Args:
        target: Hash de fichier, URL ou domaine
        analysis_type: 'file', 'url', 'domain'
    
    Returns:
        {
            'threat_detected': bool,
            'threat_level': str,
            'sources_checked': int,
            'sources_with_threat': int,
            'all_threats': [...],
            'source_results': {...}
        }
    """
```

### Logique de Priorite

1. Si VirusTotal detecte >= 5 moteurs positifs → `threat_level = 'critique'`
2. Si Google Safe Browsing detecte une menace → `threat_level = 'eleve'`
3. Si URLhaus trouve l'URL dans sa base → `threat_level = 'critique'`
4. Agregation des resultats avec score de confiance

---

## Service: TrackerDetectorService

### Localisation
`services/tracker_detector.py`

### Base de Donnees IP Loggers

Services detectes automatiquement:
- grabify.link, iplogger.org, blasze.tk
- 2no.co, iplogger.com, ps3cfw.com
- urlz.fr, yip.su, cutt.us
- Et 40+ autres services connus

### Detection de Fingerprinting

Indicateurs recherches:
- Parametres Canvas/WebGL
- Enumeration des plugins
- Proprietes d'ecran/fenetre
- AudioContext fingerprinting

---

## Service: PDFReportService

### Localisation
`services/pdf_service.py`

### Structure des Rapports

1. **Page de Couverture**
   - Logo, titre, date
   - QR code de verification

2. **Resume Executif**
   - Verdict global
   - Score de risque

3. **Details de l'Analyse**
   - Chaine de redirection
   - Problemes detectes
   - Sources de verification

4. **Recommandations**
   - Actions a entreprendre
   - Conseils de securite

---

## Configuration Environnement

### Variables Requises (Production)

```bash
ADMIN_PASSWORD=xxxxx
DATABASE_URL=postgresql://...
SECURITY_ANALYSIS_API_KEY=xxxxx
```

### Variables Optionnelles

```bash
SECURITY_ANALYSIS_API_KEY_1=xxxxx  # Google Safe Browsing
SECURITY_ANALYSIS_API_KEY_2=xxxxx  # URLhaus
SECURITY_ANALYSIS_API_KEY_3=xxxxx  # URLScan.io
HIBP_API_KEY=xxxxx                  # Have I Been Pwned
```

### Verification au Demarrage

Le script `check_env.py` verifie automatiquement:
1. Presence des variables requises
2. Etat des APIs de securite configurees
3. Affichage du resume de configuration

---

## Base de Donnees

### Modeles Principaux

```
QRCodeAnalysis
├── id
├── extracted_url
├── final_url
├── redirect_chain (JSON)
├── threat_level
├── threat_detected
├── threat_details (JSON)
├── ip_loggers_found (JSON)
├── trackers_found (JSON)
├── created_at
└── ip_address

SecurityAnalysis
├── id
├── analysis_type (file|url|domain)
├── target
├── threat_level
├── threat_detected
├── api_results (JSON)
└── created_at

BreachAnalysis
├── id
├── email
├── breach_count
├── risk_level
├── breaches (JSON)
└── created_at
```

---

## Endpoints API

### QR Code Analysis

```
POST /outils/qrcode-analyzer
Content-Type: multipart/form-data

file: <image_qr>

Response:
{
    "success": true,
    "results": {...},
    "analysis_id": 123
}
```

### Security Analysis

```
POST /outils/security-analyzer
Content-Type: application/json

{
    "type": "url|file|domain",
    "target": "https://..."
}

Response:
{
    "threat_detected": true,
    "threat_level": "high",
    "details": {...}
}
```

### PDF Generation

```
GET /outils/qrcode-analyzer/pdf/<analysis_id>

Response: application/pdf
```

---

## Tests

### Execution des Tests

```bash
python -m pytest tests/ -v
```

### Tests Unitaires Disponibles

- `test_qrcode_analyzer.py` - Service QR code
- `test_security_analyzer.py` - Service securite
- `test_tracker_detector.py` - Detection trackers

---

## Securite

### Pratiques Implementees

1. **Pas d'execution de contenu**
   - Les URLs sont analysees sans etre ouvertes
   - Les fichiers sont hashes sans etre executes

2. **Rate Limiting**
   - Protection contre les abus d'API
   - Limitation par IP

3. **Validation des Entrees**
   - Sanitization des URLs
   - Verification des formats de fichier

4. **Gestion des Secrets**
   - Variables d'environnement
   - Jamais de cles en dur dans le code
