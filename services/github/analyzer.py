import os
import re
import json
import math
import shutil
import tempfile
import subprocess
import time
import hashlib
import base64
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict, Counter
from typing import Dict, List, Optional
import requests

from .patterns import (
    SECRET_PATTERNS,
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    INSECURE_DESERIALIZATION_PATTERNS,
    INSECURE_CONFIG_PATTERNS,
    SSRF_PATTERNS,
    CSRF_PATTERNS,
    AUTHENTICATION_PATTERNS,
    HARDCODED_VALUES_PATTERNS,
    TOXIC_AI_PATTERNS_REGEX,
    PERFORMANCE_PATTERNS,
    LANGUAGE_EXTENSIONS,
    FRAMEWORK_DETECTION,
    SENSITIVE_FILES_GIT,
    VULNERABLE_PACKAGES,
    SEVERITY_SCORES,
    SECURITY_WEIGHT,
    DEPENDENCIES_WEIGHT,
    ARCHITECTURE_WEIGHT,
    TOXIC_AI_WEIGHT,
    PERFORMANCE_WEIGHT,
    GIT_QUALITY_WEIGHT,
    DOCUMENTATION_WEIGHT,
)


class GitHubCodeAnalyzerService:
    
    SECURITY_WEIGHT = SECURITY_WEIGHT
    DEPENDENCIES_WEIGHT = DEPENDENCIES_WEIGHT
    ARCHITECTURE_WEIGHT = ARCHITECTURE_WEIGHT
    TOXIC_AI_WEIGHT = TOXIC_AI_WEIGHT
    PERFORMANCE_WEIGHT = PERFORMANCE_WEIGHT
    GIT_QUALITY_WEIGHT = GIT_QUALITY_WEIGHT
    DOCUMENTATION_WEIGHT = DOCUMENTATION_WEIGHT
    
    SEVERITY_SCORES = SEVERITY_SCORES
    
    SECRET_PATTERNS = SECRET_PATTERNS
    SQL_INJECTION_PATTERNS = SQL_INJECTION_PATTERNS
    XSS_PATTERNS = XSS_PATTERNS
    COMMAND_INJECTION_PATTERNS = COMMAND_INJECTION_PATTERNS
    PATH_TRAVERSAL_PATTERNS = PATH_TRAVERSAL_PATTERNS
    INSECURE_DESERIALIZATION_PATTERNS = INSECURE_DESERIALIZATION_PATTERNS
    INSECURE_CONFIG_PATTERNS = INSECURE_CONFIG_PATTERNS
    SSRF_PATTERNS = SSRF_PATTERNS
    CSRF_PATTERNS = CSRF_PATTERNS
    AUTHENTICATION_PATTERNS = AUTHENTICATION_PATTERNS
    HARDCODED_VALUES_PATTERNS = HARDCODED_VALUES_PATTERNS
    TOXIC_AI_PATTERNS_REGEX = TOXIC_AI_PATTERNS_REGEX
    PERFORMANCE_PATTERNS = PERFORMANCE_PATTERNS
    LANGUAGE_EXTENSIONS = LANGUAGE_EXTENSIONS
    FRAMEWORK_DETECTION = FRAMEWORK_DETECTION
    SENSITIVE_FILES_GIT = SENSITIVE_FILES_GIT
    VULNERABLE_PACKAGES = VULNERABLE_PACKAGES
    
    def __init__(self, github_token: Optional[str] = None, use_semgrep: bool = True):
        self.github_token = github_token
        self.use_semgrep = use_semgrep
        self.github_api_base = "https://api.github.com"
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
        self.file_hashes = {}
        self.owner = None
        self.repo_name = None
    
    def analyze(self, repo_url, branch='main', mode='full', github_token=None):
        """
        Analyse un dépôt GitHub avec différents modes.
        
        Args:
            repo_url: URL du dépôt GitHub
            branch: Branche à analyser (défaut: 'main')
            mode: 'full' (clone+scan), 'quick' (API only), ou 'hybrid'
            github_token: Token GitHub optionnel pour API Code Scanning
        """
        start_time = time.time()
        
        if github_token:
            self.github_token = github_token
        
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
            self.owner = owner
            self.repo_name = repo_name
            
            print(f"🔍 Analyse de {owner}/{repo_name} (branche: {branch}, mode: {mode})")
            
            # === PHASE 1: GitHub Code Scanning API (si token disponible) ===
            if self.github_token:
                print("  [1/6] Récupération des alertes GitHub Code Scanning...")
                github_alerts = self._fetch_github_code_scanning_alerts(owner, repo_name)
                if github_alerts:
                    print(f"    ✅ {len(github_alerts)} alertes GitHub trouvées")
                    self._integrate_github_alerts(github_alerts)
                else:
                    print("    ℹ️  Aucune alerte GitHub (Code Scanning non activé ou pas de token)")
            
            # === PHASE 2: Mode Quick (sans clonage) ===
            if mode == 'quick':
                print("  [Mode Quick] Scan rapide via API GitHub...")
                self._quick_scan_without_clone(owner, repo_name, branch)
                scores = self._calculate_scores()
                duration = time.time() - start_time
                return self._build_result(repo_url, repo_name, owner, branch, None, scores, duration, mode)
            
            # === PHASE 3: Clonage optimisé ===
            print("  [2/6] Clonage optimisé du dépôt...")
            self.temp_dir = tempfile.mkdtemp(prefix='github_analysis_')
            clone_result = self._clone_repository_optimized(repo_url, branch)
            if clone_result.get('error'):
                return clone_result
            
            commit_hash = self._get_commit_hash()
            print(f"    ✅ Dépôt cloné (commit: {commit_hash})")
            
            # === PHASE 4: Analyse Semgrep (AST) si disponible ===
            if self.use_semgrep and mode in ['full', 'hybrid']:
                print("  [3/6] Analyse Semgrep (AST-based)...")
                semgrep_results = self._run_semgrep_analysis(self.temp_dir)
                if semgrep_results:
                    print(f"    ✅ Semgrep: {len(semgrep_results)} vulnérabilités détectées")
                    self._integrate_semgrep_findings(semgrep_results)
                else:
                    print("    ℹ️  Semgrep: aucune vulnérabilité ou non disponible")
            
            # === PHASE 5: Scan traditionnel (regex) ===
            print("  [4/6] Scan patterns regex...")
            self._load_package_manifests()
            self._analyze_all_files()
            print(f"    ✅ {self.stats['total_files']} fichiers analysés")
            
            # === PHASE 6: Analyses complémentaires ===
            print("  [5/6] Analyses complémentaires...")
            self._analyze_git_history()
            self._analyze_dependencies()
            self._analyze_architecture()
            self._analyze_documentation()
            self._finalize_framework_detection()
            
            print("  [6/6] Calcul des scores...")
            scores = self._calculate_scores()
            duration = time.time() - start_time
            
            print(f"\n✨ Analyse terminée en {duration:.2f}s")
            print(f"   Score global: {scores['overall']:.1f}/100")
            print(f"   Niveau de risque: {scores['risk_level'].upper()}")
            
            return self._build_result(repo_url, repo_name, owner, branch, commit_hash, scores, duration, mode)
            
        except Exception as e:
            import traceback
            return {
                'error': True,
                'message': f'Erreur lors de l\'analyse: {str(e)}',
                'traceback': traceback.format_exc()
            }
        finally:
            self._cleanup()
    
    def _build_result(self, repo_url, repo_name, owner, branch, commit_hash, scores, duration, mode):
        """Construit le résultat de l'analyse."""
        return {
            'error': False,
            'repo_url': repo_url,
            'repo_name': repo_name,
            'repo_owner': owner,
            'branch': branch,
            'commit_hash': commit_hash or 'N/A (mode quick)',
            'analysis_mode': mode,
            'overall_score': scores['overall'],
            'security_score': scores['security'],
            'dependency_score': scores['dependencies'],
            'architecture_score': scores['architecture'],
            'performance_score': scores['performance'],
            'documentation_score': scores['documentation'],
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
            'total_lines_analyzed': self.stats['total_lines'],
            'total_issues_found': sum(len(f) for f in self.findings.values()),
            'critical_issues': self._count_by_severity('critical'),
            'high_issues': self._count_by_severity('high'),
            'medium_issues': self._count_by_severity('medium'),
            'low_issues': self._count_by_severity('low'),
            'languages_detected': dict(self.stats['languages']),
            'primary_language': self._get_primary_language(),
            'frameworks_detected': list(self.stats['detected_frameworks']),
            'framework_details': self._get_framework_details(),
            'analysis_duration': round(duration, 2),
            'analysis_summary': self._generate_summary(scores),
            'security_summary': self._generate_security_summary(),
            'recommendations': self._generate_recommendations()
        }
    
    # ============================================================
    # NOUVELLES METHODES - APIs EXTERNES ET OPTIMISATIONS
    # ============================================================
    
    def _fetch_github_code_scanning_alerts(self, owner: str, repo: str) -> List[Dict]:
        """
        Récupère les alertes via GitHub Code Scanning API (CodeQL).
        Référence: https://docs.github.com/en/rest/code-scanning
        """
        if not self.github_token:
            return []
        
        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        url = f"{self.github_api_base}/repos/{owner}/{repo}/code-scanning/alerts"
        params = {"state": "open", "per_page": 100}
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return []
            else:
                print(f"    ⚠️  GitHub Code Scanning API: {response.status_code}")
                return []
        except Exception as e:
            print(f"    ⚠️  Erreur GitHub API: {e}")
            return []
    
    def _integrate_github_alerts(self, alerts: List[Dict]):
        """Intègre les alertes GitHub CodeQL dans les findings."""
        severity_map = {
            "error": "critical",
            "warning": "high",
            "note": "medium",
            "none": "low"
        }
        
        for alert in alerts:
            rule = alert.get("rule", {})
            location = alert.get("most_recent_instance", {}).get("location", {})
            
            cwe_tags = rule.get("tags", [])
            cwe_str = ", ".join(cwe_tags) if isinstance(cwe_tags, list) else str(cwe_tags)
            
            finding = {
                "type": "github_code_scanning",
                "severity": severity_map.get(rule.get("security_severity_level", "none"), "medium"),
                "title": rule.get("description", "Vulnérabilité détectée par GitHub CodeQL"),
                "file": location.get("path", "unknown"),
                "line": location.get("start_line", 0),
                "evidence": alert.get("most_recent_instance", {}).get("message", {}).get("text", "")[:200],
                "category": "GitHub CodeQL",
                "cwe": cwe_str,
                "owasp": "Détecté par CodeQL",
                "remediation": rule.get("help_uri", "Voir la documentation GitHub"),
                "github_alert_url": alert.get("html_url", ""),
                "confidence": "HIGH"
            }
            
            self.findings["security"].append(finding)
    
    def _run_semgrep_analysis(self, repo_path: str) -> List[Dict]:
        """
        Exécute Semgrep pour une analyse AST précise.
        Semgrep est plus précis que regex car il comprend le contexte sémantique.
        """
        try:
            result = subprocess.run(
                ["which", "semgrep"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return []
            
            result = subprocess.run(
                [
                    "semgrep",
                    "scan",
                    "--config=auto",
                    "--json",
                    "--timeout=300",
                    "--max-memory=2000",
                    "--quiet",
                    repo_path
                ],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode in [0, 1]:
                try:
                    data = json.loads(result.stdout)
                    return data.get("results", [])
                except json.JSONDecodeError:
                    return []
            return []
                
        except subprocess.TimeoutExpired:
            print("    ⚠️  Semgrep timeout")
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            return []
    
    def _integrate_semgrep_findings(self, semgrep_results: List[Dict]):
        """Intègre les résultats Semgrep dans les findings."""
        severity_map = {
            "ERROR": "critical",
            "WARNING": "high",
            "INFO": "medium"
        }
        
        for result in semgrep_results:
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            
            cwe_data = metadata.get("cwe", [])
            cwe_str = ", ".join(cwe_data) if isinstance(cwe_data, list) else str(cwe_data)
            owasp_data = metadata.get("owasp", "")
            owasp_str = ", ".join(owasp_data) if isinstance(owasp_data, list) else str(owasp_data)
            
            finding = {
                "type": "semgrep_sast",
                "severity": severity_map.get(extra.get("severity", "INFO"), "medium"),
                "title": extra.get("message", "Vulnérabilité Semgrep"),
                "file": result.get("path", "unknown"),
                "line": result.get("start", {}).get("line", 0),
                "evidence": str(extra.get("lines", ""))[:200],
                "category": "Semgrep SAST (AST)",
                "cwe": cwe_str,
                "owasp": owasp_str,
                "remediation": metadata.get("fix", "Consultez la documentation Semgrep"),
                "confidence": metadata.get("confidence", "MEDIUM"),
                "rule_id": result.get("check_id", "")
            }
            
            self.findings["security"].append(finding)
    
    def _fetch_file_via_api(self, owner: str, repo: str, filepath: str, ref: str = "main") -> str:
        """
        Récupère le contenu d'un fichier via l'API GitHub (sans clonage).
        Utile pour le mode quick scan.
        """
        headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        
        url = f"{self.github_api_base}/repos/{owner}/{repo}/contents/{filepath}"
        params = {"ref": ref}
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                content_b64 = response.json().get("content", "")
                return base64.b64decode(content_b64).decode('utf-8')
            return ""
        except Exception:
            return ""
    
    def _quick_scan_without_clone(self, owner: str, repo: str, branch: str):
        """
        Scan rapide des fichiers critiques sans clonage complet.
        Idéal pour des pré-scans ou des démos.
        """
        critical_files = [
            ".env", ".env.local", ".env.production",
            "config.py", "settings.py", "config.js", "config.json",
            "package.json", "requirements.txt", ".gitignore",
            "docker-compose.yml", "Dockerfile",
            ".github/workflows/ci.yml", ".github/workflows/main.yml"
        ]
        
        scanned = 0
        for filename in critical_files:
            content = self._fetch_file_via_api(owner, repo, filename, branch)
            if content:
                scanned += 1
                self.stats['total_files'] += 1
                self.stats['total_lines'] += content.count('\n')
                
                self._scan_for_secrets(content, filename)
                self._scan_insecure_config(content, filename)
                
                if filename == 'package.json':
                    try:
                        self.stats['package_json'] = json.loads(content)
                        self._analyze_npm_deps(content, filename)
                    except:
                        pass
                elif filename == 'requirements.txt':
                    self.stats['requirements_txt'] = content
                    self._analyze_python_deps(content, filename)
        
        print(f"    ✅ {scanned} fichiers critiques analysés via API")
    
    def _clone_repository_optimized(self, repo_url, branch):
        """Clonage optimisé: shallow + filter pour rapidité."""
        if not self.temp_dir:
            return {'error': True, 'message': 'Répertoire temporaire non initialisé'}
        
        try:
            api_url = repo_url.replace('github.com', 'api.github.com/repos').rstrip('/')
            if api_url.endswith('.git'):
                api_url = api_url[:-4]
            
            headers = {'Accept': 'application/vnd.github.v3+json'}
            if self.github_token:
                headers['Authorization'] = f'Bearer {self.github_token}'
            
            try:
                response = requests.get(api_url, headers=headers, timeout=10)
                if response.status_code == 404:
                    return {'error': True, 'message': 'Dépôt non trouvé ou privé'}
            except:
                pass
            
            result = subprocess.run(
                [
                    'git', 'clone',
                    '--depth', '1',
                    '--single-branch',
                    '-b', branch,
                    '--filter=blob:none',
                    repo_url,
                    self.temp_dir
                ],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                if 'not found' in result.stderr.lower():
                    return {'error': True, 'message': f'Branche "{branch}" non trouvée. Essayez "main" ou "master".'}
                return {'error': True, 'message': f'Erreur de clonage: {result.stderr}'}
            
            subprocess.run(
                ['git', 'sparse-checkout', 'set', '--no-cone', '*', '!node_modules', '!vendor', '!.git'],
                cwd=self.temp_dir,
                capture_output=True,
                timeout=10
            )
            
            return {'error': False}
            
        except subprocess.TimeoutExpired:
            return {'error': True, 'message': 'Timeout (>60s), dépôt trop volumineux'}
        except Exception as e:
            return {'error': True, 'message': f'Erreur de clonage: {str(e)}'}
    
    def _calculate_entropy(self, text: str) -> float:
        """Calcule l'entropie de Shannon d'une chaîne pour détecter les faux positifs."""
        if len(text) < 8:
            return 0
        counter = Counter(text)
        length = len(text)
        return -sum((count/length) * math.log2(count/length) for count in counter.values())
    
    def _is_false_positive_advanced(self, match_text: str, filepath: str, line_content: str) -> bool:
        """Détection améliorée des faux positifs avec analyse d'entropie et contexte."""
        
        if any(marker in line_content.strip()[:10] for marker in ['#', '//', '/*', '*', '"""', "'''"]):
            return True
        
        test_indicators = ['test', 'spec', 'mock', 'fixture', 'example', 'sample', 'demo', 'readme', '__test__', '__tests__']
        if any(indicator in filepath.lower() for indicator in test_indicators):
            return True
        
        placeholders = [
            'your_', 'my_', 'example_', 'sample_', 'test_', 'fake_',
            'changeme', 'replace', 'insert', 'placeholder', 'xxx', 'yyy',
            '0000', 'aaaa', '1111', '1234', 'abcd', 'password', 'secret_here',
            'todo', 'fixme', 'hack', 'temp'
        ]
        if any(ph in match_text.lower() for ph in placeholders):
            return True
        
        env_patterns = [
            r'process\.env\.',
            r'os\.environ',
            r'getenv\s*\(',
            r'ENV\[',
            r'System\.getenv',
            r'\$\{.*\}',
            r'\{\{.*\}\}'
        ]
        for pattern in env_patterns:
            if re.search(pattern, line_content):
                return True
        
        entropy = self._calculate_entropy(match_text)
        if entropy < 2.5:
            return True
        
        return False
    
    def _clone_repository(self, repo_url, branch):
        """Méthode legacy - redirige vers la version optimisée."""
        return self._clone_repository_optimized(repo_url, branch)
    
    def _get_commit_hash(self):
        if not self.temp_dir:
            return 'unknown'
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
    
    def _load_package_manifests(self):
        if not self.temp_dir:
            return
        package_json_path = os.path.join(self.temp_dir, 'package.json')
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    self.stats['package_json'] = json.load(f)
            except:
                pass
        
        requirements_path = os.path.join(self.temp_dir, 'requirements.txt')
        if os.path.exists(requirements_path):
            try:
                with open(requirements_path, 'r', encoding='utf-8') as f:
                    self.stats['requirements_txt'] = f.read()
            except:
                pass
    
    def _analyze_all_files(self):
        if not self.temp_dir:
            return
        excluded_dirs = {'.git', 'node_modules', '__pycache__', 'venv', 'env', 
                        '.venv', 'vendor', 'dist', 'build', '.next', 'coverage',
                        '.cache', '.pytest_cache', '.mypy_cache', 'target',
                        'bower_components', '.nuxt', '.output', 'out'}
        excluded_extensions = {'.min.js', '.min.css', '.map', '.lock', '.svg', 
                              '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', 
                              '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4',
                              '.avi', '.mov', '.webm', '.pdf', '.zip', '.tar',
                              '.gz', '.rar', '.7z', '.exe', '.dll', '.so',
                              '.pyc', '.pyo', '.class', '.jar', '.war'}
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            
            for filename in files:
                if any(filename.endswith(ext) for ext in excluded_extensions):
                    continue
                
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, self.temp_dir)
                
                _, ext = os.path.splitext(filename)
                ext_lower = ext.lower()
                
                if ext_lower in self.LANGUAGE_EXTENSIONS:
                    self.stats['languages'][self.LANGUAGE_EXTENSIONS[ext_lower]] += 1
                
                self.stats['total_files'] += 1
                
                try:
                    file_size = os.path.getsize(filepath)
                    if file_size > 1024 * 1024:
                        continue
                    
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    self.stats['total_lines'] += content.count('\n')
                    
                    file_hash = hashlib.md5(content.encode()).hexdigest()
                    if file_hash in self.file_hashes:
                        self.findings['code_quality'].append({
                            'type': 'duplicate_file',
                            'severity': 'low',
                            'title': f'Fichier dupliqué: {relative_path}',
                            'file': relative_path,
                            'line': 0,
                            'evidence': f'Identique à {self.file_hashes[file_hash]}',
                            'remediation': 'Considérez factoriser le code dupliqué'
                        })
                    else:
                        self.file_hashes[file_hash] = relative_path
                    
                    self._scan_for_secrets(content, relative_path)
                    self._scan_sql_injection(content, relative_path)
                    self._scan_xss(content, relative_path)
                    self._scan_command_injection(content, relative_path)
                    self._scan_path_traversal(content, relative_path)
                    self._scan_insecure_deserialization(content, relative_path)
                    self._scan_insecure_config(content, relative_path)
                    self._scan_ssrf(content, relative_path)
                    self._scan_csrf(content, relative_path)
                    self._scan_authentication_issues(content, relative_path)
                    self._scan_hardcoded_values(content, relative_path)
                    self._scan_toxic_ai_patterns(content, relative_path)
                    self._scan_performance_issues(content, relative_path)
                    self._analyze_code_quality(content, relative_path, ext_lower)
                    self._detect_frameworks(content, relative_path, ext_lower)
                    
                except Exception as e:
                    continue
    
    def _detect_frameworks(self, content, filepath, ext):
        primary_lang = None
        for lang_ext, lang_name in self.LANGUAGE_EXTENSIONS.items():
            if ext == lang_ext:
                primary_lang = lang_name.split()[0]
                break
        
        if not primary_lang:
            return
        
        lang_frameworks = self.FRAMEWORK_DETECTION.get(primary_lang, {})
        
        if 'inherit' in lang_frameworks:
            parent_lang = lang_frameworks['inherit']
            lang_frameworks = self.FRAMEWORK_DETECTION.get(parent_lang, {})
        
        filename = os.path.basename(filepath)
        
        for framework_name, detection in lang_frameworks.items():
            if framework_name == 'inherit':
                continue
                
            score = 0
            evidence = []
            
            if filename in detection.get('files', []):
                score += 3
                evidence.append(f'Fichier caractéristique: {filename}')
            
            for config_file in detection.get('config_files', []):
                if config_file in filepath:
                    score += 4
                    evidence.append(f'Fichier de configuration: {config_file}')
            
            for pattern in detection.get('patterns', []):
                if re.search(pattern, content, re.IGNORECASE):
                    score += 2
                    evidence.append(f'Pattern détecté: {pattern[:30]}...')
                    if score >= 6:
                        break
            
            if self.stats.get('package_json'):
                pkg_deps = {
                    **self.stats['package_json'].get('dependencies', {}),
                    **self.stats['package_json'].get('devDependencies', {})
                }
                for dep in detection.get('package_deps', []):
                    if dep in pkg_deps:
                        score += 5
                        evidence.append(f'Dépendance package.json: {dep}')
            
            if self.stats.get('requirements_txt'):
                requirements_content = self.stats['requirements_txt'].lower()
                python_dep_map = {
                    'Django': ['django'],
                    'Flask': ['flask'],
                    'FastAPI': ['fastapi'],
                    'Pyramid': ['pyramid'],
                    'Tornado': ['tornado'],
                    'Celery': ['celery'],
                    'SQLAlchemy': ['sqlalchemy'],
                    'Pandas': ['pandas'],
                    'NumPy': ['numpy'],
                    'TensorFlow': ['tensorflow', 'tensorflow-gpu'],
                    'PyTorch': ['torch', 'pytorch'],
                    'Streamlit': ['streamlit'],
                }
                if framework_name in python_dep_map:
                    for dep in python_dep_map[framework_name]:
                        if dep in requirements_content:
                            score += 5
                            evidence.append(f'Dépendance requirements.txt: {dep}')
            
            if score > 0:
                self.stats['frameworks'][framework_name]['score'] += score
                self.stats['frameworks'][framework_name]['evidence'].extend(evidence)
    
    def _finalize_framework_detection(self):
        for framework, data in self.stats['frameworks'].items():
            has_manifest_evidence = any(
                'package.json' in e or 'requirements.txt' in e or 'Pipfile' in e or 
                'composer.json' in e or 'Gemfile' in e or 'pom.xml' in e or
                'Cargo.toml' in e or 'go.mod' in e
                for e in data.get('evidence', [])
            )
            
            if has_manifest_evidence and data['score'] >= 5:
                self.stats['detected_frameworks'].add(framework)
            elif data['score'] >= 8:
                self.stats['detected_frameworks'].add(framework)
    
    def _get_framework_details(self):
        details = {}
        for framework in self.stats['detected_frameworks']:
            data = self.stats['frameworks'].get(framework, {})
            details[framework] = {
                'confidence_score': min(data.get('score', 0), 10),
                'evidence': list(set(data.get('evidence', [])))[:5]
            }
        return details
    
    def _get_primary_language(self):
        if not self.stats['languages']:
            return 'Unknown'
        return max(self.stats['languages'].items(), key=lambda x: x[1])[0]
    
    def _scan_for_secrets(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                
                if self._is_false_positive_secret(match.group(0), filepath, line_content):
                    continue
                if self._is_comment_line(line_content):
                    continue
                    
                self.findings['security'].append({
                    'type': 'secret_exposed',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': self._redact_secret(match.group(0)),
                    'category': 'Secrets & Credentials',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'remediation': 'Supprimez le secret du code et utilisez des variables d\'environnement ou un gestionnaire de secrets'
                })
    
    def _is_comment_line(self, line):
        stripped = line.strip()
        if not stripped:
            return False
        
        if stripped.startswith('#') and not stripped.startswith('#!') and not stripped.startswith('#include') and not stripped.startswith('#define'):
            return True
        if stripped.startswith('//'):
            return True
        if stripped.startswith('/*') or stripped.startswith('*/'):
            return True
        if stripped.startswith('* ') and not any(c.isalnum() for c in stripped[2:5] if stripped[2:5]):
            return True
        if stripped.startswith('--') and not stripped.startswith('---'):
            return True
        if stripped.startswith('"""') or stripped.startswith("'''"):
            return True
        if stripped.startswith('<!--'):
            return True
        
        return False
    
    def _is_false_positive_secret(self, match, filepath, line_content=""):
        """Détection améliorée des faux positifs avec entropie."""
        false_positive_patterns = [
            r'example', r'placeholder', r'your[_-]?api[_-]?key', r'xxx+',
            r'test[_-]?key', r'fake[_-]?key', r'dummy', r'sample',
            r'<your', r'\[your', r'\{your', r'INSERT_', r'REPLACE_',
            r'process\.env', r'os\.environ', r'getenv', r'env\[',
            r'config\[', r'settings\.', r'\.get\s*\(', r'environ\.get',
            r'secret_key_here', r'your_secret', r'change_me', r'changeme',
            r'todo', r'fixme', r'0{8,}', r'1{8,}', r'a{8,}', r'x{8,}',
            r'demo', r'default', r'template', r'skeleton', r'scaffold',
            r'\.env\.example', r'\.env\.sample', r'\.env\.template',
            r'config\.example', r'config\.sample', r'config\.template',
            r'api_key_example', r'example_api_key', r'my_api_key',
            r'secret_here', r'add_your', r'enter_your', r'put_your',
            r'abc123', r'12345', r'password123', r'testpass',
            r'\$\{', r'\{\{', r'%\w+%'
        ]
        match_lower = match.lower()
        for fp in false_positive_patterns:
            if re.search(fp, match_lower):
                return True
        
        false_positive_files = [
            'test', 'spec', 'mock', 'fixture', 'example', 'sample', 'doc',
            'readme', 'changelog', 'contributing', 'license', 'template',
            'demo', 'tutorial', 'guide', 'getting-started', 'quickstart',
            '.example', '.sample', '.template', '.dist', '.default',
            '__test__', '__tests__', '__mocks__'
        ]
        if any(x in filepath.lower() for x in false_positive_files):
            return True
        
        if len(match) < 10 or all(c == match[0] for c in match if c.isalnum()):
            return True
        
        entropy = self._calculate_entropy(match)
        if entropy < 2.5:
            return True
        
        if line_content:
            env_patterns = [r'process\.env', r'os\.environ', r'getenv', r'\$\{', r'\{\{']
            for pattern in env_patterns:
                if re.search(pattern, line_content):
                    return True
        
        return False
    
    def _scan_sql_injection(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.SQL_INJECTION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'sql_injection',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Injection',
                    'owasp': 'A03:2021 - Injection',
                    'remediation': 'Utilisez des requêtes paramétrées ou un ORM avec des paramètres typés'
                })
    
    def _scan_xss(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.XSS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'xss',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Cross-Site Scripting',
                    'owasp': 'A03:2021 - Injection',
                    'remediation': 'Échappez toujours les données utilisateur avant l\'affichage HTML'
                })
    
    def _scan_command_injection(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.COMMAND_INJECTION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'command_injection',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Command Injection',
                    'owasp': 'A03:2021 - Injection',
                    'remediation': 'Évitez shell=True et utilisez des listes de commandes avec validation stricte des entrées'
                })
    
    def _scan_path_traversal(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.PATH_TRAVERSAL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'path_traversal',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Path Traversal',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'remediation': 'Validez et normalisez les chemins de fichiers, utilisez une whitelist de répertoires autorisés'
                })
    
    def _scan_insecure_deserialization(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.INSECURE_DESERIALIZATION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'insecure_deserialization',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Insecure Deserialization',
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'remediation': 'Utilisez des formats de sérialisation sécurisés (JSON) ou des loaders sécurisés (SafeLoader pour YAML)'
                })
    
    def _scan_insecure_config(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.INSECURE_CONFIG_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'insecure_config',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Security Misconfiguration',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'remediation': 'Vérifiez et sécurisez la configuration pour la production'
                })
    
    def _scan_ssrf(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.SSRF_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'ssrf',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Server-Side Request Forgery',
                    'owasp': 'A10:2021 - Server-Side Request Forgery',
                    'remediation': 'Validez et sanitisez les URLs, utilisez une whitelist de domaines autorisés'
                })
    
    def _scan_csrf(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.CSRF_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'csrf',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Cross-Site Request Forgery',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'remediation': 'Implémentez une protection CSRF avec des tokens'
                })
    
    def _scan_authentication_issues(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.AUTHENTICATION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'authentication_issue',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Authentication Failures',
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'remediation': 'Utilisez des fonctions de hachage sécurisées (bcrypt, Argon2) et des comparaisons à temps constant'
                })
    
    def _scan_hardcoded_values(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.HARDCODED_VALUES_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if self._is_false_positive_secret(match.group(0), filepath):
                    continue
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['security'].append({
                    'type': 'hardcoded_value',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Hardcoded Values',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'remediation': 'Utilisez des variables d\'environnement ou des fichiers de configuration externes'
                })
    
    def _scan_toxic_ai_patterns(self, content, filepath):
        lines = content.split('\n')
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
        self._detect_inconsistent_logic(content, filepath)
    
    def _detect_duplicate_functions(self, content, filepath):
        func_pattern = r'(def\s+(\w+)|function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\(|(\w+)\s*:\s*(?:async\s*)?function)'
        matches = list(re.finditer(func_pattern, content))
        
        seen = defaultdict(list)
        for match in matches:
            groups = match.groups()
            name = next((g for g in groups[1:] if g), None)
            if name and name not in ['__init__', 'constructor', 'render', 'get', 'set', 'delete', 'update', 'create']:
                line_num = content[:match.start()].count('\n') + 1
                seen[name].append(line_num)
        
        for name, lines in seen.items():
            if len(lines) > 1:
                self.findings['toxic_ai'].append({
                    'type': 'duplicate_function',
                    'severity': 'medium',
                    'title': f'Fonction potentiellement dupliquée: {name}',
                    'file': filepath,
                    'line': lines[0],
                    'evidence': f'Fonction "{name}" définie aux lignes {", ".join(map(str, lines))}',
                    'remediation': 'Consolidez les fonctions dupliquées en une seule implémentation'
                })
    
    def _detect_inconsistent_logic(self, content, filepath):
        patterns = [
            (r'if\s+\w+\s*==\s*None.*if\s+\w+\s*is\s+None', 'Comparaison None incohérente (== vs is)', 'low'),
            (r'return\s+True.*return\s+False.*return\s+True', 'Logique de retour potentiellement incohérente', 'low'),
            (r'except\s*:\s*\n\s*raise', 'Catch-and-rethrow inutile', 'low'),
        ]
        
        for pattern, description, severity in patterns:
            if re.search(pattern, content, re.DOTALL | re.IGNORECASE):
                self.findings['toxic_ai'].append({
                    'type': 'inconsistent_logic',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': 0,
                    'evidence': 'Pattern de logique incohérente détecté',
                    'remediation': 'Revoyez la logique pour plus de cohérence'
                })
    
    def _scan_performance_issues(self, content, filepath):
        lines = content.split('\n')
        for pattern, description, severity in self.PERFORMANCE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                if 0 < line_num <= len(lines) and self._is_comment_line(lines[line_num - 1]):
                    continue
                self.findings['performance'].append({
                    'type': 'performance_issue',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Optimisez ce pattern de code pour de meilleures performances'
                })
    
    def _analyze_code_quality(self, content, filepath, ext):
        lines = content.split('\n')
        
        long_lines = sum(1 for line in lines if len(line) > 120)
        if long_lines > 5:
            self.findings['code_quality'].append({
                'type': 'long_lines',
                'severity': 'info',
                'title': f'{long_lines} lignes dépassent 120 caractères',
                'file': filepath,
                'line': 0,
                'evidence': f'{long_lines} lignes trop longues',
                'remediation': 'Divisez les lignes longues pour améliorer la lisibilité'
            })
        
        if len(lines) > 500:
            self.findings['code_quality'].append({
                'type': 'large_file',
                'severity': 'low',
                'title': f'Fichier volumineux ({len(lines)} lignes)',
                'file': filepath,
                'line': 0,
                'evidence': f'{len(lines)} lignes de code',
                'remediation': 'Envisagez de diviser ce fichier en modules plus petits'
            })
        
        placeholders = [
            (r'lorem\s+ipsum', 'Texte Lorem Ipsum'),
            (r'placeholder', 'Placeholder'),
            (r'TODO:\s*replace', 'TODO: replace'),
            (r'test@test\.com', 'Email de test'),
            (r'example@example\.com', 'Email example'),
            (r'["\']password123["\']', 'Mot de passe trivial'),
            (r'["\']admin123["\']', 'Mot de passe admin trivial'),
            (r'["\']changeme["\']', 'Valeur à changer'),
            (r'["\']your[_-]?api[_-]?key["\']', 'Placeholder API key'),
        ]
        
        for pattern, desc in placeholders:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                line_num = content[:matches[0].start()].count('\n') + 1
                self.findings['code_quality'].append({
                    'type': 'placeholder',
                    'severity': 'low',
                    'title': f'{desc} détecté',
                    'file': filepath,
                    'line': line_num,
                    'evidence': matches[0].group(0),
                    'remediation': 'Remplacez les placeholders par des valeurs réelles ou des variables d\'environnement'
                })
    
    def _analyze_git_history(self):
        if not self.temp_dir:
            return
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline', '-n', '100'],
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
                    'remediation': 'Maintenez un historique de commits régulier et descriptif'
                })
            
            poor_messages = [c for c in commits if re.search(
                r'^[a-f0-9]+\s+(wip|work in progress|temp|test|fix|update|changes|stuff|asdf|qwer|commit|\.+)$', 
                c, re.I
            )]
            if len(poor_messages) > len(commits) * 0.25:
                self.findings['git_hygiene'].append({
                    'type': 'poor_commit_messages',
                    'severity': 'low',
                    'title': 'Messages de commit peu descriptifs',
                    'file': '.git',
                    'line': 0,
                    'evidence': f'{len(poor_messages)}/{len(commits)} commits avec messages vagues',
                    'remediation': 'Utilisez des messages de commit conventionnels (feat:, fix:, docs:, etc.)'
                })
            
            result = subprocess.run(
                ['git', 'log', '--all', '--diff-filter=A', '--name-only', '--pretty=format:'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            added_files = [f for f in result.stdout.split('\n') if f.strip()] if result.stdout else []
            
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
                                'evidence': 'Ce type de fichier ne devrait jamais être commité',
                                'remediation': 'Utilisez git-filter-branch ou BFG Repo-Cleaner pour nettoyer l\'historique, puis changez les credentials exposés'
                            })
                    elif sensitive in f:
                        severity = 'critical' if any(x in f for x in ['.env', 'credential', 'secret', 'key']) else 'high'
                        self.findings['git_hygiene'].append({
                            'type': 'sensitive_in_history',
                            'severity': severity,
                            'title': f'Fichier sensible dans l\'historique: {f}',
                            'file': f,
                            'line': 0,
                            'evidence': 'Fichier potentiellement sensible ajouté dans l\'historique Git',
                            'remediation': 'Utilisez git-filter-branch ou BFG Repo-Cleaner pour nettoyer l\'historique, puis changez tous les secrets exposés'
                        })
            
            result = subprocess.run(
                ['git', 'branch', '-a'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            branches = [b.strip() for b in result.stdout.split('\n') if b.strip()] if result.stdout else []
            stale_branches = [b for b in branches if any(x in b.lower() for x in ['temp', 'old', 'backup', 'test', 'wip'])]
            if len(stale_branches) > 3:
                self.findings['git_hygiene'].append({
                    'type': 'stale_branches',
                    'severity': 'info',
                    'title': f'{len(stale_branches)} branches potentiellement obsolètes',
                    'file': '.git',
                    'line': 0,
                    'evidence': ', '.join(stale_branches[:5]),
                    'remediation': 'Nettoyez les branches obsolètes pour garder le dépôt propre'
                })
            
        except Exception as e:
            pass
    
    def _analyze_dependencies(self):
        if not self.temp_dir:
            return
        dep_files = {
            'requirements.txt': self._analyze_python_deps,
            'Pipfile': self._analyze_pipfile,
            'pyproject.toml': self._analyze_pyproject,
            'package.json': self._analyze_npm_deps,
            'Gemfile': self._analyze_ruby_deps,
            'go.mod': self._analyze_go_deps,
            'Cargo.toml': self._analyze_rust_deps,
            'pom.xml': self._analyze_maven_deps,
            'composer.json': self._analyze_php_deps,
        }
        
        found_dep_files = []
        for filename, analyzer in dep_files.items():
            filepath = os.path.join(self.temp_dir, filename)
            if os.path.exists(filepath):
                found_dep_files.append(filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        analyzer(content, filename)
                except:
                    pass
        
        lockfiles = {
            'package.json': ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
            'requirements.txt': ['requirements.lock', 'Pipfile.lock', 'poetry.lock'],
            'Gemfile': ['Gemfile.lock'],
            'go.mod': ['go.sum'],
            'Cargo.toml': ['Cargo.lock'],
            'composer.json': ['composer.lock'],
        }
        
        for main_file, locks in lockfiles.items():
            if os.path.exists(os.path.join(self.temp_dir, main_file)):
                has_lock = any(os.path.exists(os.path.join(self.temp_dir, lf)) for lf in locks)
                if not has_lock:
                    self.findings['dependencies'].append({
                        'type': 'no_lockfile',
                        'severity': 'medium',
                        'title': f'Fichier de verrouillage manquant pour {main_file}',
                        'file': main_file,
                        'line': 0,
                        'evidence': f'Lockfiles attendus: {", ".join(locks)}',
                        'remediation': 'Générez un fichier de verrouillage pour des builds reproductibles et sécurisés'
                    })
    
    def _analyze_python_deps(self, content, filename):
        lines = content.strip().split('\n')
        deps = {}
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)(?:\[.*\])?(?:([=<>!~]+)(.+))?', line)
            if match:
                pkg_name = match.group(1).lower()
                version_op = match.group(2)
                version = match.group(3)
                
                if not version_op:
                    self.findings['dependencies'].append({
                        'type': 'unpinned_dependency',
                        'severity': 'low',
                        'title': f'Dépendance non verrouillée: {pkg_name}',
                        'file': filename,
                        'line': 0,
                        'evidence': line,
                        'remediation': 'Épinglez la version exacte pour des builds reproductibles'
                    })
                
                if pkg_name in self.VULNERABLE_PACKAGES.get('python', {}):
                    vuln_info = self.VULNERABLE_PACKAGES['python'][pkg_name]
                    self.findings['dependencies'].append({
                        'type': 'vulnerable_dependency',
                        'severity': vuln_info['severity'],
                        'title': f'Dépendance potentiellement vulnérable: {pkg_name}',
                        'file': filename,
                        'line': 0,
                        'evidence': f'{pkg_name} - {vuln_info["cve"]}',
                        'cve': vuln_info['cve'],
                        'remediation': f'Mettez à jour {pkg_name} vers une version non vulnérable'
                    })
    
    def _analyze_pipfile(self, content, filename):
        pass
    
    def _analyze_pyproject(self, content, filename):
        pass
    
    def _analyze_npm_deps(self, content, filename):
        try:
            data = json.loads(content)
            all_deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            
            for pkg, version in all_deps.items():
                if version in ['*', 'latest']:
                    self.findings['dependencies'].append({
                        'type': 'dangerous_version',
                        'severity': 'high',
                        'title': f'Version dangereuse: {pkg}@{version}',
                        'file': filename,
                        'line': 0,
                        'evidence': f'{pkg}: {version}',
                        'remediation': 'N\'utilisez jamais * ou latest en production'
                    })
                elif version.startswith('^') or version.startswith('~'):
                    pass
                
                pkg_lower = pkg.lower()
                if pkg_lower in self.VULNERABLE_PACKAGES.get('npm', {}):
                    vuln_info = self.VULNERABLE_PACKAGES['npm'][pkg_lower]
                    self.findings['dependencies'].append({
                        'type': 'vulnerable_dependency',
                        'severity': vuln_info['severity'],
                        'title': f'Dépendance potentiellement vulnérable: {pkg}',
                        'file': filename,
                        'line': 0,
                        'evidence': f'{pkg}@{version} - {vuln_info["cve"]}',
                        'cve': vuln_info['cve'],
                        'remediation': f'Mettez à jour {pkg} vers une version non vulnérable'
                    })
            
            if 'engines' not in data:
                self.findings['dependencies'].append({
                    'type': 'missing_engines',
                    'severity': 'low',
                    'title': 'Version Node.js non spécifiée',
                    'file': filename,
                    'line': 0,
                    'evidence': 'Champ "engines" manquant',
                    'remediation': 'Spécifiez la version Node.js requise dans le champ "engines"'
                })
                
        except json.JSONDecodeError:
            self.findings['dependencies'].append({
                'type': 'invalid_package_json',
                'severity': 'high',
                'title': 'package.json invalide',
                'file': filename,
                'line': 0,
                'evidence': 'Erreur de parsing JSON',
                'remediation': 'Corrigez la syntaxe du fichier package.json'
            })
    
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
        if not self.temp_dir:
            return
        structure = defaultdict(list)
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv'}]
            
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
        
        if len(root_code_files) > 15:
            self.findings['architecture'].append({
                'type': 'flat_structure',
                'severity': 'medium',
                'title': 'Structure de fichiers trop plate',
                'file': '/',
                'line': 0,
                'evidence': f'{len(root_code_files)} fichiers de code à la racine',
                'remediation': 'Organisez le code en modules/packages avec une structure claire (src/, lib/, etc.)'
            })
        
        common_dirs = ['src', 'lib', 'app', 'pkg', 'internal', 'cmd']
        has_source_structure = any(d in structure for d in common_dirs)
        
        test_dirs = ['tests', 'test', 'spec', '__tests__', 'test_*']
        has_tests = any(d in structure or any(d.startswith('test') for d in structure) for d in test_dirs)
        
        test_files = []
        for root, dirs, files in os.walk(self.temp_dir):
            for f in files:
                if re.search(r'(test_|_test|\.test\.|\.spec\.)', f, re.I):
                    test_files.append(f)
        
        if not has_tests and not test_files and self.stats['total_files'] > 10:
            self.findings['architecture'].append({
                'type': 'no_tests',
                'severity': 'high',
                'title': 'Aucun test détecté',
                'file': '/',
                'line': 0,
                'evidence': 'Pas de dossier tests/ ni de fichiers *test*',
                'remediation': 'Ajoutez des tests unitaires et d\'intégration pour assurer la qualité du code'
            })
        elif test_files and len(test_files) < self.stats['total_files'] * 0.1:
            self.findings['architecture'].append({
                'type': 'insufficient_tests',
                'severity': 'medium',
                'title': 'Couverture de tests potentiellement insuffisante',
                'file': '/',
                'line': 0,
                'evidence': f'{len(test_files)} fichiers de test pour {self.stats["total_files"]} fichiers',
                'remediation': 'Augmentez la couverture de tests (objectif: >80%)'
            })
        
        ci_files = ['.github/workflows', '.gitlab-ci.yml', '.travis.yml', 'Jenkinsfile', '.circleci', 'azure-pipelines.yml']
        has_ci = any(
            os.path.exists(os.path.join(self.temp_dir, cf)) or 
            any(cf in s for s in structure.keys())
            for cf in ci_files
        )
        
        if not has_ci and self.stats['total_files'] > 20:
            self.findings['architecture'].append({
                'type': 'no_ci',
                'severity': 'low',
                'title': 'Aucune configuration CI/CD détectée',
                'file': '/',
                'line': 0,
                'evidence': 'Pas de fichier de configuration CI trouvé',
                'remediation': 'Ajoutez une pipeline CI/CD (GitHub Actions, GitLab CI, etc.)'
            })
        
        config_dirs = ['config', 'configs', 'settings']
        env_example = ['.env.example', '.env.sample', 'env.example']
        has_env_example = any(os.path.exists(os.path.join(self.temp_dir, ef)) for ef in env_example)
        
        if os.path.exists(os.path.join(self.temp_dir, '.env')) and not has_env_example:
            self.findings['architecture'].append({
                'type': 'missing_env_example',
                'severity': 'low',
                'title': '.env.example manquant',
                'file': '/',
                'line': 0,
                'evidence': '.env existe mais pas de template .env.example',
                'remediation': 'Créez un fichier .env.example avec les variables requises (sans valeurs sensibles)'
            })
    
    def _analyze_documentation(self):
        if not self.temp_dir:
            return
        readme_path = None
        for name in ['README.md', 'README.rst', 'README.txt', 'README', 'readme.md']:
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
                'remediation': 'Créez un README.md avec description, installation, utilisation et contribution'
            })
        else:
            with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                readme_content = f.read()
                readme_lower = readme_content.lower()
                
                required_sections = [
                    ('installation', 'Section Installation manquante'),
                    ('usage', 'Section Usage/Utilisation manquante'),
                ]
                
                recommended_sections = [
                    ('license', 'Information de licence manquante'),
                    ('contributing', 'Guide de contribution manquant'),
                    ('api', 'Documentation API manquante'),
                ]
                
                for keyword, message in required_sections:
                    if keyword not in readme_lower:
                        self.findings['documentation'].append({
                            'type': 'incomplete_readme',
                            'severity': 'medium',
                            'title': message,
                            'file': os.path.basename(readme_path),
                            'line': 0,
                            'evidence': f'Section "{keyword}" non trouvée',
                            'remediation': f'Ajoutez une section {keyword.title()} détaillée'
                        })
                
                for keyword, message in recommended_sections:
                    if keyword not in readme_lower:
                        self.findings['documentation'].append({
                            'type': 'missing_section',
                            'severity': 'low',
                            'title': message,
                            'file': os.path.basename(readme_path),
                            'line': 0,
                            'evidence': f'Section "{keyword}" recommandée mais non trouvée',
                            'remediation': f'Envisagez d\'ajouter une section {keyword.title()}'
                        })
                
                if len(readme_content) < 300:
                    self.findings['documentation'].append({
                        'type': 'short_readme',
                        'severity': 'medium',
                        'title': 'README trop court',
                        'file': os.path.basename(readme_path),
                        'line': 0,
                        'evidence': f'{len(readme_content)} caractères seulement',
                        'remediation': 'Étoffez la documentation avec plus de détails sur le projet'
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
                'remediation': 'Créez un .gitignore adapté à votre stack (utilisez gitignore.io)'
            })
        else:
            with open(gitignore_path, 'r', encoding='utf-8', errors='ignore') as f:
                gitignore_content = f.read().lower()
                
                critical_ignores = [
                    ('.env', 'Fichiers .env non ignorés'),
                    ('node_modules', 'node_modules non ignoré'),
                    ('__pycache__', '__pycache__ non ignoré'),
                    ('.pyc', 'Fichiers .pyc non ignorés'),
                ]
                
                for pattern, message in critical_ignores:
                    if pattern not in gitignore_content:
                        if (pattern == 'node_modules' and 'JavaScript' in self.stats['languages']) or \
                           (pattern in ['.pyc', '__pycache__'] and 'Python' in self.stats['languages']) or \
                           pattern == '.env':
                            self.findings['documentation'].append({
                                'type': 'incomplete_gitignore',
                                'severity': 'medium' if pattern == '.env' else 'low',
                                'title': message,
                                'file': '.gitignore',
                                'line': 0,
                                'evidence': f'Pattern "{pattern}" non trouvé',
                                'remediation': f'Ajoutez {pattern} au .gitignore'
                            })
    
    def _calculate_scores(self):
        def category_score(findings_list, expected_max_issues=10):
            if not findings_list:
                return 100
            
            severity_weights = {
                'critical': 15,
                'high': 10,
                'medium': 5,
                'low': 2,
                'info': 1
            }
            
            total_penalty = 0
            for finding in findings_list:
                severity = finding.get('severity', 'info')
                total_penalty += severity_weights.get(severity, 1)
            
            max_expected_penalty = expected_max_issues * severity_weights['high']
            normalized_penalty = min(total_penalty / max_expected_penalty, 1.0) * 100
            
            return max(0, round(100 - normalized_penalty, 1))
        
        security_score = category_score(self.findings['security'], expected_max_issues=8)
        deps_score = category_score(self.findings['dependencies'], expected_max_issues=5)
        arch_score = category_score(self.findings['architecture'], expected_max_issues=5)
        perf_score = category_score(self.findings['performance'], expected_max_issues=5)
        git_score = category_score(self.findings['git_hygiene'], expected_max_issues=4)
        doc_score = category_score(self.findings['documentation'], expected_max_issues=4)
        toxic_score = category_score(self.findings['toxic_ai'], expected_max_issues=5)
        
        overall_score = (
            security_score * self.SECURITY_WEIGHT +
            deps_score * self.DEPENDENCIES_WEIGHT +
            arch_score * self.ARCHITECTURE_WEIGHT +
            toxic_score * self.TOXIC_AI_WEIGHT +
            perf_score * self.PERFORMANCE_WEIGHT +
            git_score * self.GIT_QUALITY_WEIGHT +
            doc_score * self.DOCUMENTATION_WEIGHT
        )
        
        if overall_score >= 80:
            risk_level = 'low'
        elif overall_score >= 60:
            risk_level = 'medium'
        elif overall_score >= 40:
            risk_level = 'high'
        else:
            risk_level = 'critical'
        
        return {
            'overall': round(overall_score, 1),
            'security': round(security_score, 1),
            'dependencies': round(deps_score, 1),
            'architecture': round(arch_score, 1),
            'performance': round(perf_score, 1),
            'documentation': round(doc_score, 1),
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
            summary_parts.append(f"⚠️ RISQUE CRITIQUE: {total_issues} problèmes détectés dont {critical} critiques et {high} élevés nécessitant une action immédiate.")
        elif scores['risk_level'] == 'high':
            summary_parts.append(f"⚠️ RISQUE ÉLEVÉ: {total_issues} problèmes détectés nécessitant une attention prioritaire.")
        elif scores['risk_level'] == 'medium':
            summary_parts.append(f"⚡ RISQUE MODÉRÉ: {total_issues} problèmes détectés, des améliorations sont recommandées.")
        else:
            summary_parts.append(f"✅ RISQUE FAIBLE: Le code semble bien sécurisé avec {total_issues} points d'attention mineurs.")
        
        if self.findings['security']:
            sec_critical = sum(1 for f in self.findings['security'] if f.get('severity') == 'critical')
            sec_high = sum(1 for f in self.findings['security'] if f.get('severity') == 'high')
            summary_parts.append(f"🔒 Sécurité: {len(self.findings['security'])} vulnérabilités ({sec_critical} critiques, {sec_high} élevées).")
        
        if self.stats['detected_frameworks']:
            summary_parts.append(f"🛠️ Frameworks: {', '.join(sorted(self.stats['detected_frameworks']))}")
        
        primary_lang = self._get_primary_language()
        if primary_lang != 'Unknown':
            other_langs = [l for l in self.stats['languages'].keys() if l != primary_lang][:2]
            lang_str = primary_lang
            if other_langs:
                lang_str += f" (+ {', '.join(other_langs)})"
            summary_parts.append(f"📝 Langage principal: {lang_str}")
        
        return ' '.join(summary_parts)
    
    def _generate_security_summary(self):
        if not self.findings['security']:
            return {'status': 'clean', 'message': 'Aucune vulnérabilité de sécurité détectée'}
        
        categories = defaultdict(list)
        for finding in self.findings['security']:
            cat = finding.get('category', 'Autre')
            categories[cat].append(finding)
        
        summary = {
            'status': 'issues_found',
            'total_vulnerabilities': len(self.findings['security']),
            'critical_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'critical'),
            'high_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'high'),
            'medium_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'medium'),
            'low_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'low'),
            'categories': {cat: len(findings) for cat, findings in categories.items()},
            'owasp_coverage': list(set(f.get('owasp', '') for f in self.findings['security'] if f.get('owasp')))
        }
        
        return summary
    
    def _generate_recommendations(self):
        recommendations = []
        
        critical_findings = [f for f in self.findings['security'] if f.get('severity') == 'critical']
        if critical_findings:
            recommendations.append({
                'priority': 'URGENT',
                'title': 'Corriger les vulnérabilités critiques',
                'description': f'{len(critical_findings)} vulnérabilités critiques nécessitent une correction immédiate',
                'items': [f['title'] for f in critical_findings[:5]]
            })
        
        secret_findings = [f for f in self.findings['security'] if f.get('type') == 'secret_exposed']
        if secret_findings:
            recommendations.append({
                'priority': 'URGENT',
                'title': 'Supprimer les secrets exposés',
                'description': 'Supprimez tous les secrets du code et utilisez des variables d\'environnement',
                'items': [f['title'] for f in secret_findings[:3]]
            })
        
        if not any('tests' in str(f) for f in self.findings['architecture']):
            pass
        
        no_tests = [f for f in self.findings['architecture'] if 'test' in f.get('type', '').lower()]
        if no_tests:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Ajouter des tests',
                'description': 'La couverture de tests est insuffisante',
                'items': ['Ajoutez des tests unitaires', 'Ajoutez des tests d\'intégration', 'Configurez une pipeline CI']
            })
        
        if self.findings['dependencies']:
            vuln_deps = [f for f in self.findings['dependencies'] if f.get('type') == 'vulnerable_dependency']
            if vuln_deps:
                recommendations.append({
                    'priority': 'HIGH',
                    'title': 'Mettre à jour les dépendances vulnérables',
                    'description': f'{len(vuln_deps)} dépendances avec des vulnérabilités connues',
                    'items': [f['title'] for f in vuln_deps[:5]]
                })
        
        return recommendations
    
    def _cleanup(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
