"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier dependency_analyzer.py du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

"""

"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Analyseur de dependances vulnerables.
"""

import re
import json
from typing import List, Dict, Any, Optional
from .base_analyzer import BaseAnalyzer


class DependencyAnalyzer(BaseAnalyzer):
    
    KNOWN_VULNERABLE_PACKAGES = {
        'python': {
            'django': {'vulnerable_versions': ['<2.2.28', '<3.2.13', '<4.0.4'], 'reason': 'Failles de sécurité connues'},
            'flask': {'vulnerable_versions': ['<2.0.0'], 'reason': 'Améliorations de sécurité dans v2'},
            'requests': {'vulnerable_versions': ['<2.20.0'], 'reason': 'CVE-2018-18074'},
            'urllib3': {'vulnerable_versions': ['<1.26.5'], 'reason': 'Multiples CVE'},
            'pyyaml': {'vulnerable_versions': ['<5.4'], 'reason': 'Désérialisation non sécurisée'},
            'pillow': {'vulnerable_versions': ['<9.0.0'], 'reason': 'Multiples CVE buffer overflow'},
            'cryptography': {'vulnerable_versions': ['<3.4.6'], 'reason': 'Failles cryptographiques'},
            'jinja2': {'vulnerable_versions': ['<2.11.3'], 'reason': 'XSS potentiel'},
            'werkzeug': {'vulnerable_versions': ['<2.0.0'], 'reason': 'Cookie parsing vulnerability'},
            'sqlalchemy': {'vulnerable_versions': ['<1.3.0'], 'reason': 'SQL injection dans certains cas'},
        },
        'javascript': {
            'lodash': {'vulnerable_versions': ['<4.17.21'], 'reason': 'Prototype pollution'},
            'axios': {'vulnerable_versions': ['<0.21.1'], 'reason': 'SSRF vulnerability'},
            'express': {'vulnerable_versions': ['<4.17.3'], 'reason': 'Open redirect'},
            'node-fetch': {'vulnerable_versions': ['<2.6.7'], 'reason': 'SSRF vulnerability'},
            'minimist': {'vulnerable_versions': ['<1.2.6'], 'reason': 'Prototype pollution'},
            'glob-parent': {'vulnerable_versions': ['<5.1.2'], 'reason': 'ReDoS'},
            'path-parse': {'vulnerable_versions': ['<1.0.7'], 'reason': 'ReDoS'},
            'moment': {'vulnerable_versions': ['*'], 'reason': 'Projet déprécié, utiliser date-fns ou dayjs'},
            'request': {'vulnerable_versions': ['*'], 'reason': 'Projet déprécié, utiliser axios ou node-fetch'},
        }
    }
    
    def __init__(self):
        super().__init__()
        self.dependencies = {}
    
    def analyze_requirements(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([<>=!~]+)?(.+)?$', line)
            if match:
                package = match.group(1).lower()
                version_spec = match.group(2) or ''
                version = match.group(3) or ''
                
                if package in self.KNOWN_VULNERABLE_PACKAGES.get('python', {}):
                    vuln_info = self.KNOWN_VULNERABLE_PACKAGES['python'][package]
                    findings.append({
                        'type': 'dependency',
                        'severity': 'high',
                        'title': f"Dépendance potentiellement vulnérable: {package}",
                        'file': filepath,
                        'line': line_num,
                        'evidence': line,
                        'context': f"Ligne {line_num}: {line}",
                        'matched_text': line,
                        'remediation': f"Mettre à jour {package}. {vuln_info['reason']}"
                    })
                
                if not version_spec or version_spec in ['>=', '~=', '']:
                    findings.append({
                        'type': 'dependency',
                        'severity': 'low',
                        'title': f"Version non épinglée: {package}",
                        'file': filepath,
                        'line': line_num,
                        'evidence': line,
                        'context': f"Ligne {line_num}: {line}",
                        'matched_text': line,
                        'remediation': f"Épingler la version avec == pour la reproductibilité"
                    })
        
        return findings
    
    def analyze_package_json(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            pkg_data = json.loads(content)
        except json.JSONDecodeError:
            return [{
                'type': 'dependency',
                'severity': 'medium',
                'title': 'package.json invalide',
                'file': filepath,
                'line': 1,
                'evidence': 'Format JSON invalide',
                'context': content[:200],
                'matched_text': 'JSON parse error',
                'remediation': 'Corriger le format JSON du package.json'
            }]
        
        for dep_type in ['dependencies', 'devDependencies']:
            deps = pkg_data.get(dep_type, {})
            for package, version in deps.items():
                package_lower = package.lower()
                
                if package_lower in self.KNOWN_VULNERABLE_PACKAGES.get('javascript', {}):
                    vuln_info = self.KNOWN_VULNERABLE_PACKAGES['javascript'][package_lower]
                    findings.append({
                        'type': 'dependency',
                        'severity': 'high',
                        'title': f"Dépendance potentiellement vulnérable: {package}",
                        'file': filepath,
                        'line': 1,
                        'evidence': f'"{package}": "{version}"',
                        'context': f'{dep_type}: {package}@{version}',
                        'matched_text': f'{package}@{version}',
                        'remediation': f"Mettre à jour {package}. {vuln_info['reason']}"
                    })
                
                if version.startswith('^') or version.startswith('~') or version == '*' or version == 'latest':
                    findings.append({
                        'type': 'dependency',
                        'severity': 'low',
                        'title': f"Version non épinglée: {package}",
                        'file': filepath,
                        'line': 1,
                        'evidence': f'"{package}": "{version}"',
                        'context': f'{dep_type}: {package}@{version}',
                        'matched_text': f'{package}@{version}',
                        'remediation': f"Épingler la version exacte pour la reproductibilité (npm shrinkwrap ou package-lock.json)"
                    })
        
        return findings
    
    def analyze(self, content: str, filepath: str, lines: List[str] = None) -> List[Dict[str, Any]]:
        self.findings = []
        
        if filepath.endswith('requirements.txt') or filepath.endswith('requirements-dev.txt'):
            self.findings = self.analyze_requirements(content, filepath)
        elif filepath.endswith('package.json'):
            self.findings = self.analyze_package_json(content, filepath)
        
        return self.findings
