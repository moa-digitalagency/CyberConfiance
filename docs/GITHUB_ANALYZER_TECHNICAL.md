# Documentation Technique - Analyseur de Code GitHub (BETA)

## Vue d'ensemble

L'analyseur de code GitHub est un service qui clone les depots publics GitHub et effectue une analyse statique complete pour detecter les vulnerabilites de securite, les patterns de code toxiques, et evaluer la qualite globale du projet.

**Status**: BETA - Algorithme en cours d'amelioration

---

## Architecture

### Fichiers principaux

```
services/github/
├── __init__.py          # Export de GitHubCodeAnalyzerService
├── analyzer.py          # Service principal (1502 lignes)
└── patterns.py          # Definitions des patterns de detection (500+ lignes)
```

### Classe principale

```python
class GitHubCodeAnalyzerService:
    def __init__(self):
        self.temp_dir = None
        self.findings = {
            'security': [],
            'dependencies': [],
            'architecture': [],
            'performance': [],
            'git_hygiene': [],
            'documentation': [],
            'toxic_ai': [],
            'code_quality': []
        }
        self.stats = {
            'total_files': 0,
            'total_lines': 0,
            'languages': defaultdict(int),
            'frameworks': defaultdict(lambda: {'score': 0, 'evidence': []}),
            'detected_frameworks': set(),
            'package_json': None,
            'requirements_txt': None,
        }
```

---

## Flux d'analyse

### 1. Clonage du depot

```python
def _clone_repository(self, repo_url, branch):
    # Verifie que l'URL est bien GitHub
    # Clone avec profondeur limitee (--depth 100)
    # Timeout: 180 secondes
    subprocess.run([
        'git', 'clone', '--depth', '100', 
        '--single-branch', '-b', branch, 
        repo_url, self.temp_dir
    ])
```

### 2. Chargement des manifestes

```python
def _load_package_manifests(self):
    # Charge package.json (Node.js)
    # Charge requirements.txt (Python)
    # Utilise pour la detection de frameworks
```

### 3. Analyse de tous les fichiers

```python
def _analyze_all_files(self):
    # Exclut: .git, node_modules, __pycache__, venv, dist, build, etc.
    # Exclut: .min.js, .min.css, images, fonts, archives, etc.
    # Limite: fichiers < 1 MB
    
    for each file:
        - Detection de langage par extension
        - Calcul du hash MD5 (detection doublons)
        - Scan des patterns de securite
        - Detection des frameworks
```

### 4. Analyse Git

```python
def _analyze_git_history(self):
    # Analyse des 100 derniers commits
    # Detection des fichiers sensibles dans l'historique
    # Qualite des messages de commit
```

### 5. Calcul des scores

```python
def _calculate_scores(self):
    # Poids des categories:
    SECURITY_WEIGHT = 0.35
    DEPENDENCIES_WEIGHT = 0.15
    ARCHITECTURE_WEIGHT = 0.15
    TOXIC_AI_WEIGHT = 0.10
    PERFORMANCE_WEIGHT = 0.10
    GIT_QUALITY_WEIGHT = 0.05
    DOCUMENTATION_WEIGHT = 0.10
```

---

## Patterns de Detection

### 1. Secrets et Credentials (36 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})` | API Key exposee | Critical |
| `AKIA[0-9A-Z]{16}` | AWS Access Key ID | Critical |
| `ghp_[a-zA-Z0-9]{36}` | GitHub Personal Access Token | Critical |
| `sk-[a-zA-Z0-9]{48}` | OpenAI API Key | Critical |
| `sk-ant-[a-zA-Z0-9\-_]{80,}` | Anthropic API Key | Critical |
| `xox[baprs]-[a-zA-Z0-9\-]{10,}` | Slack Token | Critical |
| `mongodb(\+srv)?://[^"\'\s]+` | MongoDB Connection String | Critical |
| `-----BEGIN.*PRIVATE KEY-----` | Cle privee | Critical |

**Faux positifs exclus:**
- Variables d'environnement (`process.env`, `os.environ`)
- Exemples/placeholders (`your_api_key`, `changeme`, `xxx`)
- Fichiers de test/documentation

### 2. Injection SQL (16 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `execute\s*\(\s*["\'].*%s.*["\']` | String formatting | Critical |
| `execute\s*\(\s*f["\']` | f-string | Critical |
| `cursor\.execute\s*\([^,]+\+` | Concatenation | Critical |
| `\.query\s*\(\s*\`[^\`]*\$\{` | Template literal (Node.js) | Critical |
| `UNION\s+SELECT` | Pattern UNION | High |

### 3. XSS (19 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `innerHTML\s*=\s*[^"\']*\+` | innerHTML concatenation | High |
| `document\.write\s*\([^)]*\+` | document.write | High |
| `dangerouslySetInnerHTML` | React dangerous | Medium |
| `v-html\s*=` | Vue v-html | Medium |
| `eval\s*\([^)]*\+` | Eval concatenation | Critical |

### 4. Command Injection (17 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `os\.system\s*\([^)]*\+` | os.system | Critical |
| `subprocess.*shell\s*=\s*True` | shell=True | Critical |
| `child_process\.exec\s*\([^)]*\+` | Node exec | Critical |
| `shell_exec\s*\(` | PHP shell_exec | Critical |

### 5. Path Traversal (17 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `open\s*\([^)]*request\.` | open() avec user input | Critical |
| `send_file\s*\([^)]*\+` | Flask send_file | High |
| `\.\.\/` | Pattern ../ | Medium |

### 6. Deserialisation non securisee (14 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `pickle\.loads?\s*\(` | Python pickle | Critical |
| `yaml\.load\s*\(` sans SafeLoader | YAML unsafe | Medium-High |
| `unserialize\s*\(` | PHP unserialize | Critical |

### 7. Configuration non securisee (24 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `DEBUG\s*=\s*True` | Mode debug | High |
| `verify\s*=\s*False` | SSL verification off | Critical |
| `CORS.*\*` | CORS wildcard | Medium |
| `SECRET_KEY\s*=\s*["\']changeme` | Secret par defaut | Critical |

### 8. SSRF (9 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `requests\.get\s*\([^)]*request\.` | User input to requests | Critical |
| `urllib\.request\.urlopen\s*\([^)]*\+` | urllib avec concat | Critical |

### 9. CSRF (6 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `@csrf_exempt` | Django exempt | High |
| `WTF_CSRF_ENABLED\s*=\s*False` | Flask-WTF off | Critical |

### 10. Authentification (12 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `password\s*==\s*` | Comparaison directe | Critical |
| `md5\s*\(.*password` | MD5 pour password | Critical |
| `jwt\.decode.*verify\s*=\s*False` | JWT sans verification | Critical |

### 11. Valeurs hardcodees (9 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `admin["\']?\s*:\s*["\']admin` | Credentials par defaut | Critical |
| `password\s*=\s*["\']123456` | Password trivial | Critical |

### 12. Patterns IA Toxiques "Vibecoding" (27 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `# TODO:?\s*(fix\|implement)` | TODO non resolu | Low |
| `# FIXME` | FIXME non resolu | Medium |
| `pass\s*#.*todo` | Placeholder pass | Medium |
| `raise NotImplementedError` | Non implemente | Medium |
| `except:\s*pass` | Exception silencieuse | High |
| `catch\s*\(\s*\w*\s*\)\s*\{\s*\}` | Catch block vide | High |
| `debugger;` | Debugger laisse | Medium |

### 13. Performance (18 patterns)

| Pattern | Description | Severite |
|---------|-------------|----------|
| `while\s+True\s*:` | Boucle infinie | Medium |
| `\.objects\.get.*for` | N+1 query Django | High |
| `SELECT\s+\*\s+FROM` | SELECT * | Low |
| `\.forEach\s*\([^)]*await` | Await dans forEach | Medium |

---

## Detection des Frameworks

### Langages supportes (50+)

```python
LANGUAGE_EXTENSIONS = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript (React)',
    '.jsx': 'JavaScript (React)',
    '.java': 'Java',
    '.go': 'Go',
    '.rb': 'Ruby',
    '.php': 'PHP',
    '.rs': 'Rust',
    '.cpp': 'C++',
    '.cs': 'C#',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
    '.vue': 'Vue.js',
    '.svelte': 'Svelte',
    # ... et 35+ autres
}
```

### Frameworks detectes

**Python:**
- Django, Flask, FastAPI, Pyramid, Tornado
- Celery, SQLAlchemy
- Pandas, NumPy, TensorFlow, PyTorch, Streamlit

**JavaScript/TypeScript:**
- React, Next.js, Vue.js, Nuxt.js, Angular
- Express.js, NestJS, Fastify, Koa
- Electron, Svelte, SvelteKit

**Autres:**
- Spring Boot (Java)
- Rails (Ruby)
- Laravel (PHP)
- Gin, Echo (Go)
- Actix, Rocket (Rust)

### Methode de detection

1. **Fichiers caracteristiques** (+3 points)
   - Ex: `manage.py` pour Django

2. **Fichiers de configuration** (+4 points)
   - Ex: `next.config.js` pour Next.js

3. **Patterns dans le code** (+2 points)
   - Ex: `from flask import` pour Flask

4. **Dependances package.json/requirements.txt** (+5 points)
   - Ex: `"react"` dans dependencies

**Seuil de detection:**
- >= 5 points avec evidence manifest = Detecte
- >= 8 points sans manifest = Detecte

---

## Calcul du Score Global

### Formule

```python
overall_score = (
    security_score * 0.35 +
    dependency_score * 0.15 +
    architecture_score * 0.15 +
    toxic_ai_score * 0.10 +
    performance_score * 0.10 +
    git_quality_score * 0.05 +
    documentation_score * 0.10
)
```

### Severite et penalites

| Severite | Penalite |
|----------|----------|
| Critical | -25 points |
| High | -15 points |
| Medium | -8 points |
| Low | -3 points |
| Info | -1 point |

### Niveaux de risque

| Score | Niveau |
|-------|--------|
| >= 80 | Excellent |
| >= 60 | Bon |
| >= 40 | Moyen |
| >= 20 | Risque |
| < 20 | Critique |

---

## Limitations connues (BETA)

### 1. Analyse statique uniquement
- Pas d'execution du code
- Faux positifs possibles sur code commente
- Ne detecte pas les vulnerabilites runtime

### 2. Taille des depots
- Timeout de 180s pour le clonage
- Fichiers > 1MB ignores
- Profondeur Git limitee a 100 commits

### 3. Detection de patterns
- Regex-based (pas d'AST complet)
- Peut manquer des obfuscations
- Faux positifs sur code de test/exemple

### 4. Frameworks
- Detection heuristique
- Peut manquer des frameworks peu communs
- Confusion possible entre frameworks similaires

---

## Ameliorations planifiees

1. **AST Analysis** - Analyse syntaxique complete pour Python/JavaScript
2. **Taint Analysis** - Suivi des flux de donnees
3. **Dependency Scanning** - Integration avec vulnerability databases (NVD, Snyk)
4. **Machine Learning** - Detection de patterns via ML
5. **Better False Positive Reduction** - Analyse contextuelle amelioree
6. **Private Repos** - Support des tokens d'acces
7. **Real-time Scanning** - Webhooks GitHub

---

## Structure des resultats

```python
{
    'error': False,
    'repo_url': 'https://github.com/owner/repo',
    'repo_name': 'repo',
    'repo_owner': 'owner',
    'branch': 'main',
    'commit_hash': 'abc12345',
    
    # Scores (0-100)
    'overall_score': 72,
    'security_score': 65,
    'dependency_score': 80,
    'architecture_score': 75,
    'performance_score': 85,
    'documentation_score': 60,
    'risk_level': 'bon',
    
    # Findings par categorie
    'security_findings': [...],
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
    
    # Meta
    'analysis_duration': 12.5,
    'analysis_summary': '...',
    'recommendations': [...]
}
```

---

## Format d'un finding

```python
{
    'type': 'secret_exposed',
    'severity': 'critical',
    'title': 'API Key exposee',
    'file': 'config/settings.py',
    'line': 42,
    'evidence': 'api_key = "sk-****..."',  # Redacted
    'category': 'Secrets & Credentials',
    'owasp': 'A02:2021 - Cryptographic Failures',
    'remediation': 'Utilisez des variables d\'environnement'
}
```

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

## Dependances

- `subprocess` - Clonage Git
- `requests` - Verification API GitHub
- `re` - Pattern matching
- `hashlib` - Hash MD5 pour doublons
- `tempfile` - Repertoire temporaire
- `shutil` - Nettoyage

---

*Documentation technique v1.0 - Decembre 2025*
*Status: BETA*
