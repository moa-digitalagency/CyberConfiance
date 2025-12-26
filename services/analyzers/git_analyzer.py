"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Analyseur d'hygiene Git.
"""

import subprocess
import re
from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class GitAnalyzer(BaseAnalyzer):
    
    SENSITIVE_FILE_PATTERNS = [
        r'\.env$',
        r'\.env\.local$',
        r'\.env\.production$',
        r'\.pem$',
        r'\.key$',
        r'\.p12$',
        r'\.pfx$',
        r'id_rsa',
        r'id_dsa',
        r'id_ecdsa',
        r'id_ed25519',
        r'\.htpasswd$',
        r'credentials\.json$',
        r'secrets\.json$',
        r'\.npmrc$',
        r'\.pypirc$',
        r'\.netrc$',
        r'\.dockercfg$',
        r'config\.json$',
        r'firebase.*\.json$',
        r'service.*account.*\.json$',
    ]
    
    def __init__(self):
        super().__init__()
        self.commit_count = 0
        self.authors = set()
        self.sensitive_files_in_history = []
    
    def analyze_git_history(self, repo_path: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline', '-100'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                commits = result.stdout.strip().split('\n')
                self.commit_count = len(commits)
                
                short_commits = []
                for commit in commits[:50]:
                    if len(commit) > 10:
                        msg = commit[8:].strip()
                        if len(msg) < 10:
                            short_commits.append(commit)
                
                if len(short_commits) > 5:
                    findings.append({
                        'type': 'git_hygiene',
                        'severity': 'low',
                        'title': f'{len(short_commits)} commits avec messages trop courts',
                        'file': 'git history',
                        'line': 0,
                        'evidence': 'Messages de commit de moins de 10 caractères',
                        'context': '\n'.join(short_commits[:5]),
                        'matched_text': 'short commit messages',
                        'remediation': 'Écrire des messages de commit descriptifs expliquant le changement'
                    })
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        try:
            result = subprocess.run(
                ['git', 'ls-files'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                files = result.stdout.strip().split('\n')
                for filepath in files:
                    for pattern in self.SENSITIVE_FILE_PATTERNS:
                        if re.search(pattern, filepath, re.IGNORECASE):
                            findings.append({
                                'type': 'git_hygiene',
                                'severity': 'critical',
                                'title': f'Fichier sensible commité: {filepath}',
                                'file': filepath,
                                'line': 0,
                                'evidence': f'Fichier sensible détecté: {filepath}',
                                'context': f'Pattern: {pattern}',
                                'matched_text': filepath,
                                'remediation': f'Supprimer {filepath} de l\'historique git avec git filter-branch ou BFG'
                            })
                            self.sensitive_files_in_history.append(filepath)
                            break
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        try:
            result = subprocess.run(
                ['git', 'log', '--all', '--diff-filter=D', '--name-only', '--pretty=format:', '-50'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                deleted_files = [f for f in result.stdout.strip().split('\n') if f]
                for filepath in deleted_files:
                    for pattern in self.SENSITIVE_FILE_PATTERNS:
                        if re.search(pattern, filepath, re.IGNORECASE):
                            findings.append({
                                'type': 'git_hygiene',
                                'severity': 'high',
                                'title': f'Fichier sensible dans l\'historique: {filepath}',
                                'file': filepath,
                                'line': 0,
                                'evidence': f'Fichier sensible supprimé mais reste dans l\'historique',
                                'context': 'Historique Git',
                                'matched_text': filepath,
                                'remediation': 'Utiliser git filter-branch ou BFG Repo-Cleaner pour nettoyer l\'historique'
                            })
                            break
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        return findings
    
    def analyze(self, content: str, filepath: str, lines: List[str] = None) -> List[Dict[str, Any]]:
        return []
