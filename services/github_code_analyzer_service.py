import os
import re
import json
import math
import shutil
import tempfile
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
import requests


class GitHubCodeAnalyzerService:
    
    SECURITY_WEIGHT = 0.50
    DEPENDENCIES_WEIGHT = 0.10
    ARCHITECTURE_WEIGHT = 0.10
    TOXIC_AI_WEIGHT = 0.10
    PERFORMANCE_WEIGHT = 0.10
    GIT_QUALITY_WEIGHT = 0.05
    DOCUMENTATION_WEIGHT = 0.05
    
    SEVERITY_SCORES = {
        'info': 0,
        'low': 1,
        'medium': 3,
        'high': 6,
        'critical': 10
    }
    
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'API Key exposée', 'critical'),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'Secret Key exposée', 'critical'),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', 'Mot de passe hardcodé', 'critical'),
        (r'(?i)(token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'Token exposé', 'critical'),
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?', 'AWS Access Key exposée', 'critical'),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'AWS Secret Key exposée', 'critical'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token exposé', 'critical'),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained PAT exposé', 'critical'),
        (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key exposée', 'critical'),
        (r'sk-proj-[a-zA-Z0-9\-_]{80,}', 'OpenAI Project API Key exposée', 'critical'),
        (r'xox[baprs]-[a-zA-Z0-9\-]{10,}', 'Slack Token exposé', 'critical'),
        (r'(?i)(mongodb(\+srv)?://[^"\'\s]+)', 'MongoDB Connection String exposée', 'critical'),
        (r'(?i)(postgres(ql)?://[^"\'\s]+)', 'PostgreSQL Connection String exposée', 'critical'),
        (r'(?i)(mysql://[^"\'\s]+)', 'MySQL Connection String exposée', 'critical'),
        (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Clé privée exposée', 'critical'),
        (r'(?i)(stripe[_-]?secret[_-]?key|sk_live_)[a-zA-Z0-9]{20,}', 'Stripe Secret Key exposée', 'critical'),
        (r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}', 'SendGrid API Key exposée', 'critical'),
        (r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}', 'Bearer Token exposé', 'high'),
    ]
    
    SQL_INJECTION_PATTERNS = [
        (r'execute\s*\(\s*["\'].*%s.*["\']', 'Injection SQL potentielle via string formatting', 'critical'),
        (r'execute\s*\(\s*f["\']', 'Injection SQL via f-string', 'critical'),
        (r'execute\s*\(\s*["\'].*\+\s*\w+', 'Injection SQL via concaténation', 'critical'),
        (r'cursor\.execute\s*\([^,]+\+', 'Injection SQL via concaténation cursor', 'critical'),
        (r'\.raw\s*\(\s*["\'].*%s', 'Raw SQL avec interpolation non sécurisée', 'high'),
        (r'\.extra\s*\(\s*where\s*=\s*\[.*%', 'Django extra() avec interpolation', 'high'),
        (r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+\s*\w+', 'SQL dynamique avec concaténation', 'critical'),
        (r'INSERT\s+INTO\s+.*VALUES\s*\(.*%s', 'INSERT avec string formatting', 'high'),
        (r'UPDATE\s+.*SET\s+.*=\s*.*%s', 'UPDATE avec string formatting', 'high'),
    ]
    
    XSS_PATTERNS = [
        (r'innerHTML\s*=\s*[^"\']*\+', 'XSS via innerHTML avec concaténation', 'high'),
        (r'document\.write\s*\([^)]*\+', 'XSS via document.write', 'high'),
        (r'\.html\s*\(\s*[^)]*\+', 'XSS via jQuery .html()', 'high'),
        (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML utilisé', 'medium'),
        (r'\|\s*safe\s*}}', 'Django/Jinja2 safe filter - XSS potentiel', 'medium'),
        (r'Markup\s*\(', 'Flask Markup sans échappement', 'medium'),
        (r'v-html\s*=', 'Vue v-html directive - XSS potentiel', 'medium'),
        (r'\[innerHTML\]\s*=', 'Angular innerHTML binding', 'medium'),
        (r'eval\s*\([^)]*\+', 'Eval avec concaténation', 'critical'),
        (r'Function\s*\([^)]*\+', 'Function constructor avec input', 'critical'),
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        (r'os\.system\s*\([^)]*\+', 'Command injection via os.system', 'critical'),
        (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', 'Subprocess avec shell=True', 'critical'),
        (r'subprocess\.Popen\s*\([^)]*shell\s*=\s*True', 'Popen avec shell=True', 'critical'),
        (r'exec\s*\([^)]*\+', 'Exec avec concaténation', 'critical'),
        (r'eval\s*\(\s*request\.', 'Eval avec user input', 'critical'),
        (r'child_process\.exec\s*\([^)]*\+', 'Node exec avec concaténation', 'critical'),
        (r'spawn\s*\([^)]*\+', 'Spawn avec concaténation', 'high'),
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        (r'open\s*\([^)]*\+', 'Path traversal potentiel via open()', 'high'),
        (r'os\.path\.join\s*\([^)]*request\.', 'Path traversal via user input', 'high'),
        (r'send_file\s*\([^)]*\+', 'Path traversal via send_file', 'high'),
        (r'\.\./', 'Path traversal pattern détecté', 'medium'),
        (r'readFile\s*\([^)]*\+', 'Node readFile avec concaténation', 'high'),
    ]
    
    INSECURE_DESERIALIZATION_PATTERNS = [
        (r'pickle\.loads?\s*\(', 'Désérialisation pickle non sécurisée', 'critical'),
        (r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader', 'YAML load non sécurisé', 'high'),
        (r'yaml\.load\s*\([^)]*\)', 'YAML load sans SafeLoader', 'medium'),
        (r'marshal\.loads?\s*\(', 'Désérialisation marshal', 'high'),
        (r'unserialize\s*\(', 'PHP unserialize non sécurisé', 'critical'),
        (r'JSON\.parse\s*\([^)]*\)\s*\.\s*constructor', 'Prototype pollution potentielle', 'high'),
    ]
    
    INSECURE_CONFIG_PATTERNS = [
        (r'DEBUG\s*=\s*True', 'Mode DEBUG activé', 'high'),
        (r'FLASK_DEBUG\s*=\s*1', 'Flask DEBUG mode', 'high'),
        (r'verify\s*=\s*False', 'SSL verification désactivée', 'critical'),
        (r'CORS\s*\(\s*\w+\s*,\s*resources\s*=.*\*', 'CORS trop permissif', 'medium'),
        (r'Access-Control-Allow-Origin.*\*', 'CORS wildcard', 'medium'),
        (r'SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', 'Secret key trop courte', 'high'),
        (r'allowedHosts\s*:\s*\[?\s*["\']?\*', 'allowedHosts wildcard', 'medium'),
    ]
    
    TOXIC_AI_PATTERNS_REGEX = [
        (r'# TODO:?\s*(fix|implement|add|complete)', 'TODO non résolu', 'low'),
        (r'# FIXME', 'FIXME non résolu', 'medium'),
        (r'# HACK', 'Code hack temporaire', 'medium'),
        (r'pass\s*# ?(placeholder|todo|implement)', 'Placeholder pass statement', 'medium'),
        (r'raise NotImplementedError', 'Fonction non implémentée', 'medium'),
        (r'print\s*\(["\']debug', 'Debug print laissé', 'low'),
        (r'console\.log\s*\(["\']debug', 'Debug console.log', 'low'),
        (r'\.\.\..*# ?generated', 'Code généré non vérifié', 'medium'),
        (r'except:\s*pass', 'Exception silencieuse', 'high'),
        (r'except\s+Exception\s*:\s*pass', 'Exception générique silencieuse', 'high'),
        (r'# AI generated|# Generated by|# Auto-generated', 'Code AI non optimisé potentiel', 'info'),
    ]
    
    PERFORMANCE_PATTERNS = [
        (r'while\s+True\s*:', 'Boucle infinie potentielle', 'medium'),
        (r'for\s+\w+\s+in\s+\w+\.objects\.all\(\)', 'Query N+1 potentielle Django', 'high'),
        (r'\.objects\.get\s*\([^)]*\)\s*$.*for', 'N+1 query dans boucle', 'high'),
        (r'time\.sleep\s*\(\s*\d{2,}\s*\)', 'Sleep long bloquant', 'medium'),
        (r'\+\s*=\s*["\']', 'Concaténation string dans boucle', 'low'),
        (r'global\s+\w+', 'Variable globale utilisée', 'low'),
        (r'SELECT\s+\*\s+FROM', 'SELECT * non optimisé', 'low'),
    ]
    
    LANGUAGE_EXTENSIONS = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.ts': 'TypeScript',
        '.tsx': 'TypeScript/React',
        '.jsx': 'JavaScript/React',
        '.java': 'Java',
        '.go': 'Go',
        '.rb': 'Ruby',
        '.php': 'PHP',
        '.rs': 'Rust',
        '.cpp': 'C++',
        '.c': 'C',
        '.cs': 'C#',
        '.swift': 'Swift',
        '.kt': 'Kotlin',
        '.scala': 'Scala',
        '.vue': 'Vue.js',
        '.svelte': 'Svelte',
    }
    
    FRAMEWORK_INDICATORS = {
        'Django': ['django', 'from django', 'settings.py', 'urls.py', 'views.py', 'models.py'],
        'Flask': ['flask', 'from flask', 'Flask(__name__)', '@app.route'],
        'FastAPI': ['fastapi', 'from fastapi', 'FastAPI()'],
        'Express': ['express', 'require("express")', 'app.get(', 'app.post('],
        'React': ['react', 'from "react"', 'useState', 'useEffect', 'ReactDOM'],
        'Vue.js': ['vue', 'createApp', 'defineComponent', '.vue'],
        'Angular': ['@angular', 'NgModule', '@Component'],
        'Spring': ['springframework', '@SpringBootApplication', '@RestController'],
        'Rails': ['rails', 'ActiveRecord', 'ApplicationController'],
        'Laravel': ['laravel', 'Illuminate', 'artisan'],
        'Next.js': ['next', 'getServerSideProps', 'getStaticProps'],
        'NestJS': ['@nestjs', '@Module', '@Controller'],
    }
    
    SENSITIVE_FILES_GIT = [
        '.env', '.env.local', '.env.production', '.env.development',
        'config.json', 'secrets.json', 'credentials.json',
        '.htpasswd', '.htaccess',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        '*.pem', '*.key', '*.p12', '*.pfx',
        'wp-config.php', 'database.yml',
        '.npmrc', '.pypirc',
    ]
    
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
            'frameworks': set()
        }
    
    def analyze(self, repo_url, branch='main'):
        start_time = time.time()
        
        try:
            parsed = urlparse(repo_url)
            if parsed.netloc not in ['github.com', 'www.github.com']:
                return {
                    'error': True,
                    'message': 'Seuls les dépôts GitHub sont supportés'
                }
            
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) < 2:
                return {
                    'error': True,
                    'message': 'URL GitHub invalide. Format attendu: https://github.com/owner/repo'
                }
            
            owner = path_parts[0]
            repo_name = path_parts[1].replace('.git', '')
            
            self.temp_dir = tempfile.mkdtemp(prefix='github_analysis_')
            
            clone_result = self._clone_repository(repo_url, branch)
            if clone_result.get('error'):
                return clone_result
            
            commit_hash = self._get_commit_hash()
            
            self._analyze_all_files()
            
            self._analyze_git_history()
            
            self._analyze_dependencies()
            
            self._analyze_architecture()
            
            self._analyze_documentation()
            
            scores = self._calculate_scores()
            
            duration = time.time() - start_time
            
            return {
                'error': False,
                'repo_url': repo_url,
                'repo_name': repo_name,
                'repo_owner': owner,
                'branch': branch,
                'commit_hash': commit_hash,
                'overall_score': scores['overall'],
                'security_score': scores['security'],
                'risk_level': scores['risk_level'],
                'security_findings': self.findings['security'],
                'dependency_findings': self.findings['dependencies'],
                'architecture_findings': self.findings['architecture'],
                'performance_findings': self.findings['performance'],
                'git_hygiene_findings': self.findings['git_hygiene'],
                'documentation_findings': self.findings['documentation'],
                'toxic_ai_patterns': self.findings['toxic_ai'],
                'code_quality_findings': self.findings['code_quality'],
                'total_files_analyzed': self.stats['total_files'],
                'total_issues_found': sum(len(f) for f in self.findings.values()),
                'critical_issues': self._count_by_severity('critical'),
                'high_issues': self._count_by_severity('high'),
                'medium_issues': self._count_by_severity('medium'),
                'low_issues': self._count_by_severity('low'),
                'languages_detected': dict(self.stats['languages']),
                'frameworks_detected': list(self.stats['frameworks']),
                'analysis_duration': round(duration, 2),
                'analysis_summary': self._generate_summary(scores)
            }
            
        except Exception as e:
            return {
                'error': True,
                'message': f'Erreur lors de l\'analyse: {str(e)}'
            }
        finally:
            self._cleanup()
    
    def _clone_repository(self, repo_url, branch):
        try:
            api_url = repo_url.replace('github.com', 'api.github.com/repos').rstrip('/')
            if api_url.endswith('.git'):
                api_url = api_url[:-4]
            
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            try:
                response = requests.get(api_url, headers=headers, timeout=10)
                if response.status_code == 404:
                    return {'error': True, 'message': 'Dépôt non trouvé ou privé'}
                elif response.status_code != 200:
                    pass
            except:
                pass
            
            result = subprocess.run(
                ['git', 'clone', '--depth', '50', '--single-branch', '-b', branch, repo_url, self.temp_dir],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                if 'not found' in result.stderr.lower():
                    return {'error': True, 'message': f'Branche "{branch}" non trouvée. Essayez "main" ou "master".'}
                return {'error': True, 'message': f'Erreur de clonage: {result.stderr}'}
            
            return {'error': False}
            
        except subprocess.TimeoutExpired:
            return {'error': True, 'message': 'Timeout lors du clonage (dépôt trop volumineux)'}
        except Exception as e:
            return {'error': True, 'message': f'Erreur de clonage: {str(e)}'}
    
    def _get_commit_hash(self):
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            return result.stdout.strip()[:8]
        except:
            return 'unknown'
    
    def _analyze_all_files(self):
        excluded_dirs = {'.git', 'node_modules', '__pycache__', 'venv', 'env', 
                        '.venv', 'vendor', 'dist', 'build', '.next', 'coverage'}
        excluded_extensions = {'.min.js', '.min.css', '.map', '.lock', '.svg', 
                              '.png', '.jpg', '.gif', '.ico', '.woff', '.ttf'}
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            
            for filename in files:
                if any(filename.endswith(ext) for ext in excluded_extensions):
                    continue
                
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, self.temp_dir)
                
                _, ext = os.path.splitext(filename)
                if ext in self.LANGUAGE_EXTENSIONS:
                    self.stats['languages'][self.LANGUAGE_EXTENSIONS[ext]] += 1
                
                self.stats['total_files'] += 1
                
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        self.stats['total_lines'] += len(lines)
                        
                        self._detect_frameworks(content)
                        
                        self._scan_for_secrets(content, relative_path)
                        self._scan_sql_injection(content, relative_path)
                        self._scan_xss(content, relative_path)
                        self._scan_command_injection(content, relative_path)
                        self._scan_path_traversal(content, relative_path)
                        self._scan_insecure_deserialization(content, relative_path)
                        self._scan_insecure_config(content, relative_path)
                        
                        self._scan_toxic_ai_patterns(content, relative_path)
                        
                        self._scan_performance_issues(content, relative_path)
                        
                        self._analyze_code_quality(content, relative_path, ext)
                        
                except Exception as e:
                    continue
    
    def _detect_frameworks(self, content):
        for framework, indicators in self.FRAMEWORK_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in content.lower():
                    self.stats['frameworks'].add(framework)
                    break
    
    def _scan_for_secrets(self, content, filepath):
        for pattern, description, severity in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'secret_exposed',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': self._redact_secret(match.group(0)),
                    'remediation': 'Supprimez le secret du code et utilisez des variables d\'environnement'
                })
    
    def _scan_sql_injection(self, content, filepath):
        for pattern, description, severity in self.SQL_INJECTION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'sql_injection',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Utilisez des requêtes paramétrées ou un ORM'
                })
    
    def _scan_xss(self, content, filepath):
        for pattern, description, severity in self.XSS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'xss',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Échappez les données utilisateur avant l\'affichage'
                })
    
    def _scan_command_injection(self, content, filepath):
        for pattern, description, severity in self.COMMAND_INJECTION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'command_injection',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Évitez shell=True et validez toutes les entrées'
                })
    
    def _scan_path_traversal(self, content, filepath):
        for pattern, description, severity in self.PATH_TRAVERSAL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'path_traversal',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Validez et normalisez les chemins de fichiers'
                })
    
    def _scan_insecure_deserialization(self, content, filepath):
        for pattern, description, severity in self.INSECURE_DESERIALIZATION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'insecure_deserialization',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Utilisez des formats de sérialisation sécurisés (JSON) ou des loaders sécurisés'
                })
    
    def _scan_insecure_config(self, content, filepath):
        for pattern, description, severity in self.INSECURE_CONFIG_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'insecure_config',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Vérifiez et sécurisez la configuration pour la production'
                })
    
    def _scan_toxic_ai_patterns(self, content, filepath):
        for pattern, description, severity in self.TOXIC_AI_PATTERNS_REGEX:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['toxic_ai'].append({
                    'type': 'toxic_ai_pattern',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Révisez et complétez le code généré par l\'IA'
                })
        
        self._detect_duplicate_functions(content, filepath)
    
    def _detect_duplicate_functions(self, content, filepath):
        func_pattern = r'(def\s+\w+|function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\()'
        functions = re.findall(func_pattern, content)
        
        seen = {}
        for func in functions:
            func_name = re.search(r'\w+', func.split('(')[0].split()[-1])
            if func_name:
                name = func_name.group()
                if name in seen and name not in ['__init__', 'constructor', 'render']:
                    self.findings['toxic_ai'].append({
                        'type': 'duplicate_function',
                        'severity': 'medium',
                        'title': f'Fonction potentiellement dupliquée: {name}',
                        'file': filepath,
                        'line': 0,
                        'evidence': f'Fonction "{name}" définie plusieurs fois',
                        'remediation': 'Consolidez les fonctions dupliquées'
                    })
                seen[name] = True
    
    def _scan_performance_issues(self, content, filepath):
        for pattern, description, severity in self.PERFORMANCE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['performance'].append({
                    'type': 'performance_issue',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Optimisez ce pattern de code'
                })
    
    def _analyze_code_quality(self, content, filepath, ext):
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            if len(line) > 150:
                self.findings['code_quality'].append({
                    'type': 'long_line',
                    'severity': 'info',
                    'title': 'Ligne trop longue (>150 caractères)',
                    'file': filepath,
                    'line': i + 1,
                    'evidence': f'{len(line)} caractères',
                    'remediation': 'Divisez la ligne pour améliorer la lisibilité'
                })
        
        placeholders = [
            r'lorem\s+ipsum', r'placeholder', r'TODO:\s*replace',
            r'xxx', r'yyy', r'zzz', r'foo', r'bar', r'baz',
            r'test@test\.com', r'example@example\.com',
            r'password123', r'admin123', r'changeme'
        ]
        
        for pattern in placeholders:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['code_quality'].append({
                    'type': 'placeholder',
                    'severity': 'low',
                    'title': 'Placeholder détecté',
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0),
                    'remediation': 'Remplacez les placeholders par des valeurs réelles'
                })
    
    def _analyze_git_history(self):
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline', '-n', '50'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            commits = result.stdout.strip().split('\n') if result.stdout else []
            
            if len(commits) < 10:
                self.findings['git_hygiene'].append({
                    'type': 'sparse_history',
                    'severity': 'info',
                    'title': 'Historique Git limité',
                    'file': '.git',
                    'line': 0,
                    'evidence': f'{len(commits)} commits analysés',
                    'remediation': 'Maintenez un historique de commits régulier'
                })
            
            wip_commits = [c for c in commits if re.search(r'wip|work in progress|temp|test|fix|asdfg', c, re.I)]
            if len(wip_commits) > len(commits) * 0.3:
                self.findings['git_hygiene'].append({
                    'type': 'poor_commit_messages',
                    'severity': 'low',
                    'title': 'Messages de commit peu descriptifs',
                    'file': '.git',
                    'line': 0,
                    'evidence': f'{len(wip_commits)}/{len(commits)} commits WIP/temp',
                    'remediation': 'Utilisez des messages de commit conventionnels'
                })
            
            result = subprocess.run(
                ['git', 'log', '--all', '--diff-filter=A', '--name-only', '--pretty=format:'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            added_files = result.stdout.split('\n') if result.stdout else []
            
            for sensitive in self.SENSITIVE_FILES_GIT:
                for f in added_files:
                    if sensitive.startswith('*'):
                        if f.endswith(sensitive[1:]):
                            self.findings['git_hygiene'].append({
                                'type': 'sensitive_in_history',
                                'severity': 'high',
                                'title': f'Fichier sensible dans l\'historique: {f}',
                                'file': f,
                                'line': 0,
                                'evidence': 'Fichier sensible ajouté dans l\'historique Git',
                                'remediation': 'Utilisez git-filter-branch ou BFG pour nettoyer l\'historique'
                            })
                    elif sensitive in f:
                        self.findings['git_hygiene'].append({
                            'type': 'sensitive_in_history',
                            'severity': 'critical',
                            'title': f'Fichier sensible dans l\'historique: {f}',
                            'file': f,
                            'line': 0,
                            'evidence': 'Fichier sensible ajouté dans l\'historique Git',
                            'remediation': 'Utilisez git-filter-branch ou BFG pour nettoyer l\'historique'
                        })
            
        except Exception as e:
            pass
    
    def _analyze_dependencies(self):
        dep_files = {
            'requirements.txt': self._analyze_python_deps,
            'Pipfile': self._analyze_pipfile,
            'package.json': self._analyze_npm_deps,
            'Gemfile': self._analyze_ruby_deps,
            'go.mod': self._analyze_go_deps,
            'Cargo.toml': self._analyze_rust_deps,
            'pom.xml': self._analyze_maven_deps,
            'composer.json': self._analyze_php_deps,
        }
        
        for filename, analyzer in dep_files.items():
            filepath = os.path.join(self.temp_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        analyzer(content, filename)
                except:
                    pass
        
        lockfiles = ['package-lock.json', 'yarn.lock', 'Pipfile.lock', 'poetry.lock', 'Gemfile.lock']
        has_lockfile = any(os.path.exists(os.path.join(self.temp_dir, lf)) for lf in lockfiles)
        
        if not has_lockfile:
            main_deps = ['requirements.txt', 'package.json', 'Gemfile', 'Pipfile']
            if any(os.path.exists(os.path.join(self.temp_dir, d)) for d in main_deps):
                self.findings['dependencies'].append({
                    'type': 'no_lockfile',
                    'severity': 'medium',
                    'title': 'Fichier de verrouillage des dépendances manquant',
                    'file': '',
                    'line': 0,
                    'evidence': 'Pas de lockfile trouvé',
                    'remediation': 'Générez un fichier de verrouillage pour des builds reproductibles'
                })
    
    def _analyze_python_deps(self, content, filename):
        lines = content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '==' not in line and '>=' not in line and '<=' not in line:
                pkg = line.split('[')[0].split(';')[0].strip()
                if pkg:
                    self.findings['dependencies'].append({
                        'type': 'unpinned_dependency',
                        'severity': 'low',
                        'title': f'Dépendance non verrouillée: {pkg}',
                        'file': filename,
                        'line': 0,
                        'evidence': line,
                        'remediation': 'Épinglez la version pour des builds reproductibles'
                    })
    
    def _analyze_pipfile(self, content, filename):
        pass
    
    def _analyze_npm_deps(self, content, filename):
        try:
            data = json.loads(content)
            deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            
            for pkg, version in deps.items():
                if version.startswith('^') or version.startswith('~') or version == '*' or version == 'latest':
                    self.findings['dependencies'].append({
                        'type': 'loose_version',
                        'severity': 'low',
                        'title': f'Version flexible: {pkg}@{version}',
                        'file': filename,
                        'line': 0,
                        'evidence': f'{pkg}: {version}',
                        'remediation': 'Utilisez des versions exactes pour plus de stabilité'
                    })
        except:
            pass
    
    def _analyze_ruby_deps(self, content, filename):
        pass
    
    def _analyze_go_deps(self, content, filename):
        pass
    
    def _analyze_rust_deps(self, content, filename):
        pass
    
    def _analyze_maven_deps(self, content, filename):
        pass
    
    def _analyze_php_deps(self, content, filename):
        pass
    
    def _analyze_architecture(self):
        structure = defaultdict(list)
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv'}]
            
            relative_root = os.path.relpath(root, self.temp_dir)
            if relative_root == '.':
                relative_root = ''
            
            for f in files:
                if relative_root:
                    structure[relative_root].append(f)
                else:
                    structure['root'].append(f)
        
        root_code_files = [f for f in structure.get('root', []) 
                         if any(f.endswith(ext) for ext in self.LANGUAGE_EXTENSIONS.keys())]
        
        if len(root_code_files) > 10:
            self.findings['architecture'].append({
                'type': 'flat_structure',
                'severity': 'medium',
                'title': 'Structure de fichiers plate',
                'file': '/',
                'line': 0,
                'evidence': f'{len(root_code_files)} fichiers de code à la racine',
                'remediation': 'Organisez le code en modules/packages'
            })
        
        common_dirs = ['src', 'lib', 'app', 'tests', 'test', 'spec']
        has_structure = any(d in structure for d in common_dirs)
        
        if not has_structure and self.stats['total_files'] > 20:
            self.findings['architecture'].append({
                'type': 'no_standard_structure',
                'severity': 'low',
                'title': 'Structure de projet non standard',
                'file': '/',
                'line': 0,
                'evidence': 'Pas de dossier src/, lib/, app/ détecté',
                'remediation': 'Adoptez une structure de projet conventionnelle'
            })
        
        test_dirs = ['tests', 'test', 'spec', '__tests__']
        has_tests = any(d in structure for d in test_dirs)
        
        test_files = []
        for root, dirs, files in os.walk(self.temp_dir):
            for f in files:
                if 'test' in f.lower() or 'spec' in f.lower():
                    test_files.append(f)
        
        if not has_tests and not test_files:
            self.findings['architecture'].append({
                'type': 'no_tests',
                'severity': 'high',
                'title': 'Aucun test détecté',
                'file': '/',
                'line': 0,
                'evidence': 'Pas de dossier tests/ ni de fichiers *test*',
                'remediation': 'Ajoutez des tests unitaires et d\'intégration'
            })
    
    def _analyze_documentation(self):
        readme_path = None
        for name in ['README.md', 'README.rst', 'README.txt', 'README']:
            path = os.path.join(self.temp_dir, name)
            if os.path.exists(path):
                readme_path = path
                break
        
        if not readme_path:
            self.findings['documentation'].append({
                'type': 'no_readme',
                'severity': 'high',
                'title': 'README manquant',
                'file': '/',
                'line': 0,
                'evidence': 'Aucun fichier README trouvé',
                'remediation': 'Créez un README.md avec les instructions d\'installation et d\'utilisation'
            })
        else:
            with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                readme_content = f.read()
                
                readme_checks = [
                    ('installation', 'Section installation manquante'),
                    ('usage', 'Section usage/utilisation manquante'),
                    ('license', 'Information de licence manquante'),
                ]
                
                for keyword, message in readme_checks:
                    if keyword.lower() not in readme_content.lower():
                        self.findings['documentation'].append({
                            'type': 'incomplete_readme',
                            'severity': 'low',
                            'title': message,
                            'file': os.path.basename(readme_path),
                            'line': 0,
                            'evidence': f'Mot-clé "{keyword}" non trouvé',
                            'remediation': f'Ajoutez une section {keyword}'
                        })
                
                if len(readme_content) < 200:
                    self.findings['documentation'].append({
                        'type': 'short_readme',
                        'severity': 'medium',
                        'title': 'README trop court',
                        'file': os.path.basename(readme_path),
                        'line': 0,
                        'evidence': f'{len(readme_content)} caractères',
                        'remediation': 'Étoffez la documentation du projet'
                    })
        
        gitignore_path = os.path.join(self.temp_dir, '.gitignore')
        if not os.path.exists(gitignore_path):
            self.findings['documentation'].append({
                'type': 'no_gitignore',
                'severity': 'medium',
                'title': '.gitignore manquant',
                'file': '/',
                'line': 0,
                'evidence': 'Fichier .gitignore non trouvé',
                'remediation': 'Créez un .gitignore adapté à votre stack'
            })
    
    def _calculate_scores(self):
        def category_score(findings_list, max_penalty=100):
            if not findings_list:
                return 100
            
            total_penalty = 0
            for finding in findings_list:
                severity = finding.get('severity', 'info')
                total_penalty += self.SEVERITY_SCORES.get(severity, 0)
            
            normalized = min(total_penalty, max_penalty)
            return max(0, 100 - normalized)
        
        security_score = category_score(self.findings['security'], max_penalty=100)
        deps_score = category_score(self.findings['dependencies'], max_penalty=50)
        arch_score = category_score(self.findings['architecture'], max_penalty=50)
        perf_score = category_score(self.findings['performance'], max_penalty=50)
        git_score = category_score(self.findings['git_hygiene'], max_penalty=30)
        doc_score = category_score(self.findings['documentation'], max_penalty=30)
        toxic_score = category_score(self.findings['toxic_ai'], max_penalty=50)
        
        overall_score = (
            security_score * self.SECURITY_WEIGHT +
            deps_score * self.DEPENDENCIES_WEIGHT +
            arch_score * self.ARCHITECTURE_WEIGHT +
            toxic_score * self.TOXIC_AI_WEIGHT +
            perf_score * self.PERFORMANCE_WEIGHT +
            git_score * self.GIT_QUALITY_WEIGHT +
            doc_score * self.DOCUMENTATION_WEIGHT
        )
        
        if overall_score >= 85:
            risk_level = 'low'
        elif overall_score >= 70:
            risk_level = 'medium'
        elif overall_score >= 50:
            risk_level = 'high'
        else:
            risk_level = 'critical'
        
        return {
            'overall': round(overall_score, 1),
            'security': round(security_score, 1),
            'risk_level': risk_level
        }
    
    def _count_by_severity(self, severity):
        count = 0
        for category in self.findings.values():
            for finding in category:
                if finding.get('severity') == severity:
                    count += 1
        return count
    
    def _redact_secret(self, secret):
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    def _generate_summary(self, scores):
        summary_parts = []
        
        total_issues = sum(len(f) for f in self.findings.values())
        critical = self._count_by_severity('critical')
        high = self._count_by_severity('high')
        
        if scores['risk_level'] == 'critical':
            summary_parts.append(f"⚠️ RISQUE CRITIQUE: {total_issues} problèmes détectés dont {critical} critiques et {high} élevés.")
        elif scores['risk_level'] == 'high':
            summary_parts.append(f"⚠️ RISQUE ÉLEVÉ: {total_issues} problèmes détectés nécessitant une attention immédiate.")
        elif scores['risk_level'] == 'medium':
            summary_parts.append(f"⚡ RISQUE MODÉRÉ: {total_issues} problèmes détectés, des améliorations sont recommandées.")
        else:
            summary_parts.append(f"✅ RISQUE FAIBLE: Le code semble bien sécurisé avec {total_issues} points d'attention mineurs.")
        
        if self.findings['security']:
            summary_parts.append(f"🔒 Sécurité: {len(self.findings['security'])} vulnérabilités potentielles identifiées.")
        
        if self.stats['frameworks']:
            summary_parts.append(f"🛠️ Frameworks: {', '.join(self.stats['frameworks'])}")
        
        if self.stats['languages']:
            top_langs = sorted(self.stats['languages'].items(), key=lambda x: x[1], reverse=True)[:3]
            summary_parts.append(f"📝 Langages: {', '.join(l[0] for l in top_langs)}")
        
        return ' '.join(summary_parts)
    
    def _cleanup(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
