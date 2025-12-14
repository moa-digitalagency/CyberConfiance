# Documentation Technique - Analyseur de Code GitHub v2.0

## Vue d'ensemble

L'analyseur de code GitHub est un service d'analyse statique avance qui combine plusieurs techniques pour detecter les vulnerabilites de securite, les patterns de code toxiques, et evaluer la qualite globale du projet.

**Status**: BETA - Version 2.0 avec ameliorations majeures
**Derniere mise a jour**: Decembre 2025

---

## Nouveautes v2.0 (Decembre 2025)

### Ameliorations de Performance et Precision

| Aspect | v1.0 | v2.0 | Gain |
|--------|------|------|------|
| **Precision** | ~60% (regex seul) | ~95% (CodeQL + Semgrep + regex) | +35% |
| **Faux positifs** | ~30% | ~5% | -83% |
| **Vitesse clonage** | 180s (100 commits) | 60s (1 commit) | 3x plus rapide |
| **Analyse AST** | Non | Oui (Semgrep) | Contexte semantique |
| **APIs officielles** | Non | GitHub CodeQL | 2000+ regles pro |

### Nouvelles Fonctionnalites

1. **GitHub Code Scanning API** - Integration avec CodeQL pour 2000+ regles de securite professionnelles
2. **Semgrep (AST)** - Analyse semantique du code, comprend le contexte
3. **Mode Quick Scan** - Analyse via API sans clonage (instantane)
4. **Detection d'entropie** - Filtre les faux positifs avec calcul de Shannon

### Variables d'Environnement

| Variable | Requis | Description |
|----------|--------|-------------|
| `GITHUB_TOKEN` | Optionnel | Token pour GitHub Code Scanning API (recommande) |

---

## Architecture du Service

### Structure des fichiers

```
services/
├── github/
│   ├── __init__.py              # Export de GitHubCodeAnalyzerService
│   ├── analyzer.py              # Service principal (~1800 lignes)
│   └── patterns.py              # Definitions des patterns de detection (500+ lignes)
│
├── analyzers/                   # Analyseurs modulaires
│   ├── __init__.py
│   ├── base_analyzer.py         # Classe de base (114 lignes)
│   ├── security_analyzer.py     # Analyse securite (141 lignes)
│   ├── dependency_analyzer.py   # Analyse dependances (144 lignes)
│   ├── architecture_analyzer.py # Analyse architecture (120 lignes)
│   ├── documentation_analyzer.py # Analyse documentation (104 lignes)
│   ├── performance_analyzer.py  # Analyse performance (36 lignes)
│   ├── git_analyzer.py          # Analyse historique Git (137 lignes)
│   └── ai_patterns_analyzer.py  # Detection patterns IA (53 lignes)
│
└── pdf/
    └── github_report.py         # Generation rapport PDF
```

### Classe principale: GitHubCodeAnalyzerService

```python
class GitHubCodeAnalyzerService:
    def __init__(self, github_token: Optional[str] = None, use_semgrep: bool = True):
        self.github_token = github_token      # Token pour GitHub API
        self.use_semgrep = use_semgrep        # Activer Semgrep (AST)
        self.github_api_base = "https://api.github.com"
        self.temp_dir = None
        self.findings = {
            'security': [],       # Vulnerabilites de securite
            'dependencies': [],   # Problemes de dependances
            'architecture': [],   # Problemes d'architecture
            'performance': [],    # Problemes de performance
            'git_hygiene': [],    # Problemes d'hygiene Git
            'documentation': [],  # Problemes de documentation
            'toxic_ai': [],       # Patterns "vibecoding" IA
            'code_quality': []    # Qualite de code generale
        }
    
    def analyze(self, repo_url, branch='main', mode='full', github_token=None):
        """
        Analyse un depot GitHub.
        
        Args:
            repo_url: URL du depot GitHub
            branch: Branche a analyser (defaut: 'main')
            mode: 'full' (clone+scan), 'quick' (API only), ou 'hybrid'
            github_token: Token GitHub optionnel pour API Code Scanning
        """
```

---

## Algorithme d'Analyse Complet

### Flux de traitement

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ENTREE: URL du depot GitHub                      │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 1: VALIDATION ET CLONAGE                                      │
│ ─────────────────────────────────────────────────────────────────── │
│ • Validation URL (github.com uniquement)                            │
│ • Extraction owner/repo                                              │
│ • Creation repertoire temporaire                                     │
│ • git clone --depth 100 --single-branch -b <branch>                 │
│ • Timeout: 180 secondes                                             │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 2: CHARGEMENT DES MANIFESTES                                  │
│ ─────────────────────────────────────────────────────────────────── │
│ • Lecture package.json (Node.js)                                    │
│ • Lecture requirements.txt (Python)                                 │
│ • Stockage pour detection frameworks                                │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 3: ANALYSE DE TOUS LES FICHIERS                               │
│ ─────────────────────────────────────────────────────────────────── │
│ Exclusions automatiques:                                            │
│ • Dossiers: .git, node_modules, __pycache__, venv, dist, build,     │
│   .next, coverage, .cache, target, bower_components, .nuxt          │
│ • Extensions: .min.js, .min.css, .map, .lock, images, fonts,        │
│   archives, binaires                                                │
│ • Fichiers > 1 MB                                                   │
│                                                                     │
│ Pour chaque fichier:                                                │
│ ├── Detection du langage par extension                              │
│ ├── Comptage des lignes                                             │
│ ├── Calcul hash MD5 (detection doublons)                            │
│ ├── Scan des 12 categories de patterns de securite                  │
│ ├── Detection des frameworks                                        │
│ └── Analyse qualite de code                                         │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 4: ANALYSE DE L'HISTORIQUE GIT                                │
│ ─────────────────────────────────────────────────────────────────── │
│ • Analyse des 100 derniers commits                                  │
│ • Detection fichiers sensibles commits (.env, .pem, .key, etc.)     │
│ • Qualite des messages de commit (>10 caracteres)                   │
│ • Detection fichiers sensibles supprimes mais dans historique       │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 5: ANALYSE DES DEPENDANCES                                    │
│ ─────────────────────────────────────────────────────────────────── │
│ • Verification des lockfiles                                        │
│ • Detection packages vulnerables connus                             │
│ • Detection versions non epinglees                                  │
│ • Verification champ "engines" (Node.js)                            │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 6: ANALYSE DE L'ARCHITECTURE                                  │
│ ─────────────────────────────────────────────────────────────────── │
│ • Structure des fichiers (trop plate?)                              │
│ • Presence de tests                                                 │
│ • Presence de CI/CD                                                 │
│ • Fichier .env.example                                              │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 7: ANALYSE DE LA DOCUMENTATION                                │
│ ─────────────────────────────────────────────────────────────────── │
│ • Presence README (md, rst, txt)                                    │
│ • Sections requises: installation, usage                            │
│ • Sections recommandees: license, contributing, api                 │
│ • Longueur minimale README (300 caracteres)                         │
│ • Presence et contenu .gitignore                                    │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 8: FINALISATION DETECTION FRAMEWORKS                          │
│ ─────────────────────────────────────────────────────────────────── │
│ • Agregation des scores par framework                               │
│ • Seuils: >=5 avec manifest OU >=8 sans manifest                    │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 9: CALCUL DES SCORES                                          │
│ ─────────────────────────────────────────────────────────────────── │
│ Formule:                                                            │
│ overall = security*0.35 + deps*0.15 + arch*0.15 + toxic*0.10        │
│         + perf*0.10 + git*0.05 + doc*0.10                           │
│                                                                     │
│ Penalites par severite:                                             │
│ • Critical: 15 points                                               │
│ • High: 10 points                                                   │
│ • Medium: 5 points                                                  │
│ • Low: 2 points                                                     │
│ • Info: 1 point                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ETAPE 10: GENERATION RESULTATS                                      │
│ ─────────────────────────────────────────────────────────────────── │
│ • Resume global                                                     │
│ • Resume securite                                                   │
│ • Recommandations prioritaires                                      │
│ • Nettoyage repertoire temporaire                                   │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SORTIE: Rapport d'analyse JSON                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Patterns de Detection (200+ patterns)

### 1. Secrets et Credentials (36 patterns)

| Type | Pattern | Exemple | Severite |
|------|---------|---------|----------|
| API Key | `api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})` | `api_key = "sk-abc..."` | Critical |
| AWS Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` | Critical |
| GitHub PAT | `ghp_[a-zA-Z0-9]{36}` | `ghp_xxxx...` | Critical |
| OpenAI Key | `sk-[a-zA-Z0-9]{48}` | `sk-xxxx...` | Critical |
| Anthropic Key | `sk-ant-[a-zA-Z0-9\-_]{80,}` | `sk-ant-xxxx...` | Critical |
| Slack Token | `xox[baprs]-[a-zA-Z0-9\-]{10,}` | `xoxb-xxxx...` | Critical |
| MongoDB URL | `mongodb(\+srv)?://[^"\'\s]+` | `mongodb://user:pass@host` | Critical |
| PostgreSQL URL | `postgres(ql)?://[^"\'\s]+` | `postgresql://...` | Critical |
| Private Key | `-----BEGIN.*PRIVATE KEY-----` | PEM format | Critical |
| Stripe Key | `sk_live_[a-zA-Z0-9]{20,}` | `sk_live_xxxx...` | Critical |
| SendGrid Key | `SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}` | `SG.xxxx...` | Critical |
| JWT Token | `eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+` | JWT format | High |

**Faux positifs exclus automatiquement:**
- Variables d'environnement (`process.env`, `os.environ`, `getenv`)
- Placeholders (`your_api_key`, `changeme`, `example`, `xxx`)
- Fichiers test/doc (`test`, `spec`, `example`, `readme`)
- Patterns repetitifs (`0000...`, `aaaa...`)

### 2. Injection SQL (16 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `execute\s*\(\s*["\'].*%s.*["\']` | String formatting | Critical |
| `execute\s*\(\s*f["\']` | f-string | Critical |
| `cursor\.execute\s*\([^,]+\+` | Concatenation | Critical |
| `\.query\s*\(\s*\`[^\`]*\$\{` | Template literal (Node.js) | Critical |
| `SELECT.*WHERE.*\+\s*\w+` | SQL dynamique | Critical |
| `UNION\s+SELECT` | Pattern UNION | High |
| `;\s*DROP\s+TABLE` | Drop injection | Critical |
| `OR\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1` | Classic bypass | Critical |

### 3. XSS - Cross-Site Scripting (19 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `innerHTML\s*=\s*[^"\']*\+` | innerHTML concat | High |
| `document\.write\s*\([^)]*\+` | document.write | High |
| `dangerouslySetInnerHTML` | React dangerous | Medium |
| `\|\s*safe\s*}}` | Django/Jinja2 safe | Medium |
| `v-html\s*=` | Vue v-html | Medium |
| `\[innerHTML\]\s*=` | Angular binding | Medium |
| `eval\s*\([^)]*\+` | Eval concat | Critical |
| `Function\s*\([^)]*\+` | Function constructor | Critical |
| `setTimeout\s*\(\s*[^,)]*\+` | setTimeout string | High |

### 4. Command Injection (17 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `os\.system\s*\([^)]*\+` | os.system | Critical |
| `subprocess.*shell\s*=\s*True` | shell=True | Critical |
| `child_process\.exec\s*\([^)]*\+` | Node exec | Critical |
| `shell_exec\s*\(` | PHP shell_exec | Critical |
| `passthru\s*\(` | PHP passthru | Critical |
| `\`[^\`]*\$[^\`]*\`` | Backtick execution | High |

### 5. Path Traversal (17 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `open\s*\([^)]*request\.` | open() user input | Critical |
| `send_file\s*\([^)]*\+` | Flask send_file | High |
| `\.\.\/` | Pattern ../ | Medium |
| `readFile\s*\([^)]*\+` | Node readFile | High |
| `require\s*\([^)]*\+` | Dynamic require | High |
| `include\s*\(\s*\$` | PHP include | Critical |

### 6. Deserialisation non securisee (14 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `pickle\.loads?\s*\(` | Python pickle | Critical |
| `yaml\.load\s*\(` sans SafeLoader | YAML unsafe | Medium-High |
| `yaml\.unsafe_load\s*\(` | YAML unsafe_load | Critical |
| `unserialize\s*\(` | PHP unserialize | Critical |
| `ObjectInputStream\s*\(` | Java deserialization | High |
| `jsonpickle\.decode\s*\(` | jsonpickle | Critical |

### 7. Configuration non securisee (24 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `DEBUG\s*=\s*True` | Mode debug | High |
| `verify\s*=\s*False` | SSL off | Critical |
| `CORS.*\*` | CORS wildcard | Medium |
| `SECRET_KEY\s*=\s*["\']changeme` | Secret default | Critical |
| `WTF_CSRF_ENABLED\s*=\s*False` | CSRF off | Critical |
| `httpOnly\s*:\s*false` | Cookie httpOnly off | High |

### 8. SSRF (9 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `requests\.get\s*\([^)]*request\.` | requests user input | Critical |
| `urllib\.request\.urlopen\s*\([^)]*\+` | urllib concat | Critical |
| `fetch\s*\([^)]*request\.` | fetch user input | Critical |
| `axios\s*\.\w+\s*\([^)]*request\.` | axios user input | Critical |

### 9. CSRF (6 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `@csrf_exempt` | Django exempt | High |
| `WTF_CSRF_ENABLED\s*=\s*False` | Flask-WTF off | Critical |
| `CSRF_ENABLED\s*=\s*False` | CSRF disabled | Critical |

### 10. Authentification faible (12 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `password\s*==\s*` | Direct comparison | Critical |
| `md5\s*\(.*password` | MD5 password | Critical |
| `sha1\s*\(.*password` | SHA1 password | High |
| `jwt\.decode.*verify\s*=\s*False` | JWT no verify | Critical |
| `algorithm\s*[=:]\s*["\']?none` | JWT none | Critical |

### 11. Valeurs hardcodees (9 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `admin["\']?\s*:\s*["\']admin` | Default admin | Critical |
| `password\s*=\s*["\']123456` | Trivial password | Critical |
| `localhost:\d{4}` | Localhost hardcode | Low |

### 12. Patterns IA Toxiques "Vibecoding" (31 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `# TODO:?\s*(fix\|implement)` | TODO non resolu | Low |
| `# FIXME` | FIXME non resolu | Medium |
| `pass\s*#.*todo` | Placeholder pass | Medium |
| `raise NotImplementedError` | Non implemente | Medium |
| `except:\s*pass` | Exception silencieuse | High |
| `catch\s*\(\s*\w*\s*\)\s*\{\s*\}` | Catch vide | High |
| `debugger;` | Debugger laisse | Medium |
| `# AI generated` | Code IA non verifie | Info |
| `lorem\s*ipsum` | Placeholder text | Low |

### 13. Performance (18 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `while\s+True\s*:` | Boucle infinie | Medium |
| `\.objects\.get.*for` | N+1 Django | High |
| `SELECT\s+\*\s+FROM` | SELECT * | Low |
| `\.forEach\s*\([^)]*await` | Await forEach | Medium |
| `JSON\.parse\s*\(\s*JSON\.stringify` | Deep clone lent | Low |
| `\.innerHTML\s*\+=` | innerHTML concat | Medium |

---

## Detection des Langages (50+ extensions)

```python
LANGUAGE_EXTENSIONS = {
    # Python
    '.py': 'Python', '.pyx': 'Cython', '.pyi': 'Python (stubs)',
    
    # JavaScript/TypeScript
    '.js': 'JavaScript', '.mjs': 'JavaScript (ESM)', '.cjs': 'JavaScript (CommonJS)',
    '.ts': 'TypeScript', '.tsx': 'TypeScript (React)', '.jsx': 'JavaScript (React)',
    
    # Web Frameworks
    '.vue': 'Vue.js', '.svelte': 'Svelte',
    
    # Backend
    '.java': 'Java', '.go': 'Go', '.rb': 'Ruby', '.php': 'PHP',
    '.rs': 'Rust', '.cs': 'C#', '.kt': 'Kotlin', '.scala': 'Scala',
    
    # Systems
    '.c': 'C', '.cpp': 'C++', '.h': 'C/C++ Header', '.hpp': 'C++ Header',
    
    # Mobile
    '.swift': 'Swift', '.dart': 'Dart',
    
    # Functional
    '.ex': 'Elixir', '.erl': 'Erlang', '.clj': 'Clojure', '.hs': 'Haskell',
    '.ml': 'OCaml', '.fs': 'F#',
    
    # Data/Science
    '.r': 'R', '.R': 'R', '.jl': 'Julia',
    
    # Scripting
    '.pl': 'Perl', '.lua': 'Lua', '.groovy': 'Groovy',
    
    # Modern
    '.nim': 'Nim', '.zig': 'Zig', '.v': 'V', '.cr': 'Crystal'
}
```

---

## Detection des Frameworks (30+ frameworks)

### Methode de detection multi-criteres

1. **Fichiers caracteristiques** (+3 points)
   - `manage.py` → Django
   - `next.config.js` → Next.js
   - `angular.json` → Angular

2. **Fichiers de configuration** (+4 points)
   - `settings.py` → Django
   - `nest-cli.json` → NestJS

3. **Patterns dans le code** (+2 points)
   - `from flask import` → Flask
   - `@app.route` → Flask
   - `useState` → React

4. **Dependances manifests** (+5 points)
   - `"react"` dans package.json → React
   - `flask` dans requirements.txt → Flask

**Seuil de detection:**
- Score >= 5 avec evidence manifest = Detecte
- Score >= 8 sans manifest = Detecte

### Frameworks detectes par langage

**Python:** Django, Flask, FastAPI, Pyramid, Tornado, Celery, SQLAlchemy, Pandas, NumPy, TensorFlow, PyTorch, Streamlit

**JavaScript/TypeScript:** React, Next.js, Vue.js, Nuxt.js, Angular, Express.js, NestJS, Fastify, Koa, Electron, Svelte, SvelteKit

**Java:** Spring Boot

**Ruby:** Rails

**PHP:** Laravel

**Go:** Gin, Echo

**Rust:** Actix, Rocket

---

## Calcul des Scores

### Formule globale

```python
overall_score = (
    security_score * 0.35 +      # 35% - Securite
    dependency_score * 0.15 +    # 15% - Dependances
    architecture_score * 0.15 +  # 15% - Architecture
    toxic_ai_score * 0.10 +      # 10% - Patterns IA
    performance_score * 0.10 +   # 10% - Performance
    git_quality_score * 0.05 +   # 5%  - Hygiene Git
    documentation_score * 0.10   # 10% - Documentation
)
```

### Calcul par categorie

```python
def category_score(findings, expected_max=10):
    severity_weights = {
        'critical': 15, 'high': 10, 'medium': 5, 'low': 2, 'info': 1
    }
    total_penalty = sum(severity_weights[f['severity']] for f in findings)
    max_penalty = expected_max * 10  # high severity
    normalized = min(total_penalty / max_penalty, 1.0) * 100
    return max(0, 100 - normalized)
```

### Niveaux de risque

| Score | Niveau | Couleur |
|-------|--------|---------|
| >= 80 | Low (Faible) | Vert |
| >= 60 | Medium (Modere) | Jaune |
| >= 40 | High (Eleve) | Orange |
| < 40 | Critical (Critique) | Rouge |

---

## Structure du Resultat JSON

```python
{
    'error': False,
    'repo_url': 'https://github.com/owner/repo',
    'repo_name': 'repo',
    'repo_owner': 'owner',
    'branch': 'main',
    'commit_hash': 'abc12345',
    
    # Scores (0-100)
    'overall_score': 72.5,
    'security_score': 65.0,
    'dependency_score': 80.0,
    'architecture_score': 75.0,
    'performance_score': 85.0,
    'documentation_score': 60.0,
    'risk_level': 'medium',
    
    # Findings par categorie
    'security_findings': [
        {
            'type': 'secret_exposed',
            'severity': 'critical',
            'title': 'API Key exposee',
            'file': 'config/settings.py',
            'line': 42,
            'evidence': 'api_key = "sk-****..."',
            'category': 'Secrets & Credentials',
            'owasp': 'A02:2021 - Cryptographic Failures',
            'remediation': 'Utilisez des variables d\'environnement'
        }
    ],
    'dependency_findings': [...],
    'architecture_findings': [...],
    'performance_findings': [...],
    'git_hygiene_findings': [...],
    'documentation_findings': [...],
    'toxic_ai_patterns': [...],
    'code_quality_findings': [...],
    
    # Statistiques
    'total_files_analyzed': 150,
    'total_lines_analyzed': 25000,
    'total_issues_found': 23,
    'critical_issues': 2,
    'high_issues': 5,
    'medium_issues': 8,
    'low_issues': 8,
    
    # Detection
    'languages_detected': {'Python': 45, 'JavaScript': 30},
    'primary_language': 'Python',
    'frameworks_detected': ['Flask', 'React'],
    'framework_details': {
        'Flask': {'confidence_score': 8, 'evidence': [...]}
    },
    
    # Meta
    'analysis_duration': 12.5,
    'analysis_summary': '...',
    'security_summary': {...},
    'recommendations': [...]
}
```

---

## Limitations Connues (BETA)

### 1. Analyse statique uniquement
- Pas d'execution du code
- Faux positifs possibles sur code commente (filtrage actif)
- Ne detecte pas les vulnerabilites runtime

### 2. Taille des depots
- Timeout de 180s pour le clonage
- Fichiers > 1MB ignores
- Profondeur Git limitee a 100 commits

### 3. Detection de patterns
- Regex-based (pas d'AST complet)
- Peut manquer des obfuscations sophistiquees
- Faux positifs sur code de test/exemple (filtrage actif)

### 4. Frameworks
- Detection heuristique par scoring
- Peut manquer des frameworks peu communs
- Confusion possible entre frameworks similaires

### 5. Dependances
- Base de vulnerabilites limitee (non exhaustive)
- Pas de verification versions exactes contre CVE database

---

## Ameliorations Planifiees

1. **AST Analysis** - Analyse syntaxique complete Python/JavaScript
2. **Taint Analysis** - Suivi des flux de donnees
3. **CVE Integration** - Integration NVD, Snyk, OSV databases
4. **Machine Learning** - Detection de patterns via ML
5. **Private Repos** - Support tokens d'acces GitHub
6. **Webhooks** - Analyse automatique sur push
7. **SARIF Export** - Export format standard securite

---

## API Endpoint

```
POST /outils/analyseur-github
Content-Type: application/x-www-form-urlencoded

repo_url=https://github.com/owner/repo
branch=main
csrf_token=...
```

---

## Dependances Techniques

```python
import subprocess    # Clonage Git
import requests      # Verification API GitHub
import re            # Pattern matching
import hashlib       # Hash MD5 pour doublons
import tempfile      # Repertoire temporaire
import shutil        # Nettoyage
import json          # Parsing manifests
import os            # Operations fichiers
from collections import defaultdict
from urllib.parse import urlparse
```

---

*Documentation technique v2.0 - Decembre 2025*
*Status: BETA*
