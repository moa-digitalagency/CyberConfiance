"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Classe de base pour les analyseurs de code.
"""

import re
from typing import List, Dict, Any, Tuple


class BaseAnalyzer:
    
    SEVERITY_SCORES = {
        'info': 0,
        'low': 1,
        'medium': 3,
        'high': 6,
        'critical': 10
    }
    
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
    
    def analyze(self, content: str, filepath: str, lines: List[str] = None) -> List[Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement analyze()")
    
    def clear(self):
        self.findings = []
    
    def get_findings(self) -> List[Dict[str, Any]]:
        return self.findings
    
    def _is_comment_line(self, line: str) -> bool:
        """Check if a line is a comment (should be excluded from analysis)"""
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
    
    def _scan_patterns(self, content: str, filepath: str, patterns: List[Tuple], finding_type: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.split('\n')
        
        for pattern_tuple in patterns:
            if len(pattern_tuple) == 3:
                pattern, description, severity = pattern_tuple
                remediation = self._get_default_remediation(finding_type, description)
            else:
                pattern, description, severity, remediation = pattern_tuple
            
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in regex.finditer(content):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    if 0 < line_num <= len(lines):
                        full_line = lines[line_num - 1].strip()
                        if self._is_comment_line(lines[line_num - 1]):
                            continue
                    else:
                        full_line = match.group(0)
                    
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 2)
                    context_lines = []
                    for i in range(context_start, context_end):
                        prefix = ">>> " if i == line_num - 1 else "    "
                        context_lines.append(f"{i + 1}: {prefix}{lines[i]}")
                    context = '\n'.join(context_lines)
                    
                    findings.append({
                        'type': finding_type,
                        'severity': severity,
                        'title': description,
                        'file': filepath,
                        'line': line_num,
                        'evidence': full_line,
                        'context': context,
                        'matched_text': match.group(0),
                        'remediation': remediation
                    })
            except re.error:
                continue
        
        return findings
    
    def _get_default_remediation(self, finding_type: str, description: str) -> str:
        remediations = {
            'secret': "Utiliser des variables d'environnement ou un gestionnaire de secrets",
            'sql_injection': "Utiliser des requêtes paramétrées ou un ORM",
            'xss': "Échapper les entrées utilisateur et utiliser des templates sécurisés",
            'command_injection': "Éviter shell=True et valider les entrées",
            'path_traversal': "Valider et nettoyer les chemins de fichiers",
            'deserialization': "Utiliser des formats de sérialisation sûrs (JSON)",
            'config': "Désactiver le mode debug en production",
            'ssrf': "Valider et filtrer les URLs",
            'csrf': "Activer la protection CSRF",
            'auth': "Utiliser bcrypt ou argon2 pour le hachage",
            'hardcoded': "Utiliser des variables d'environnement",
            'toxic_ai': "Compléter l'implémentation et supprimer le code temporaire",
            'performance': "Optimiser la requête ou utiliser la pagination"
        }
        return remediations.get(finding_type, "Corriger selon les bonnes pratiques de sécurité")
