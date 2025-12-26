"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Analyseur d'architecture de projet.
"""

import os
from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class ArchitectureAnalyzer(BaseAnalyzer):
    
    def __init__(self):
        super().__init__()
        self.file_structure = {}
        self.has_tests = False
        self.has_config = False
        self.has_env_example = False
        self.has_gitignore = False
        self.has_dockerfile = False
        self.has_ci = False
        self.large_files = []
        self.deep_nesting = []
    
    def analyze_structure(self, base_path: str, files: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        for filepath in files:
            rel_path = filepath.lower()
            
            if 'test' in rel_path or 'spec' in rel_path:
                self.has_tests = True
            if rel_path.endswith('.env.example') or rel_path.endswith('.env.template'):
                self.has_env_example = True
            if rel_path.endswith('.gitignore'):
                self.has_gitignore = True
            if 'dockerfile' in rel_path:
                self.has_dockerfile = True
            if '.github/workflows' in rel_path or '.gitlab-ci' in rel_path or 'jenkinsfile' in rel_path.lower():
                self.has_ci = True
            if rel_path.endswith(('config.py', 'config.js', 'config.ts', 'settings.py')):
                self.has_config = True
            
            depth = filepath.count(os.sep)
            if depth > 8:
                self.deep_nesting.append(filepath)
        
        if not self.has_tests:
            findings.append({
                'type': 'architecture',
                'severity': 'medium',
                'title': 'Aucun fichier de test détecté',
                'file': base_path,
                'line': 0,
                'evidence': 'Pas de dossier test/, tests/, spec/ ou fichiers *_test.*',
                'context': 'Structure du projet',
                'matched_text': 'missing tests',
                'remediation': 'Ajouter des tests unitaires et d\'intégration pour garantir la qualité du code'
            })
        
        if not self.has_env_example:
            findings.append({
                'type': 'architecture',
                'severity': 'low',
                'title': 'Pas de fichier .env.example',
                'file': base_path,
                'line': 0,
                'evidence': 'Fichier .env.example manquant',
                'context': 'Configuration',
                'matched_text': 'missing .env.example',
                'remediation': 'Créer un fichier .env.example documentant les variables d\'environnement nécessaires'
            })
        
        if not self.has_gitignore:
            findings.append({
                'type': 'architecture',
                'severity': 'high',
                'title': 'Pas de fichier .gitignore',
                'file': base_path,
                'line': 0,
                'evidence': 'Fichier .gitignore manquant',
                'context': 'Configuration Git',
                'matched_text': 'missing .gitignore',
                'remediation': 'Ajouter un .gitignore pour exclure node_modules, __pycache__, .env, etc.'
            })
        
        if self.deep_nesting:
            findings.append({
                'type': 'architecture',
                'severity': 'low',
                'title': f'Structure de dossiers trop profonde ({len(self.deep_nesting)} fichiers)',
                'file': base_path,
                'line': 0,
                'evidence': f'Fichiers avec plus de 8 niveaux: {", ".join(self.deep_nesting[:3])}...',
                'context': 'Structure du projet',
                'matched_text': 'deep nesting',
                'remediation': 'Simplifier la structure des dossiers pour améliorer la maintenabilité'
            })
        
        return findings
    
    def analyze_file_size(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.split('\n')
        line_count = len(lines)
        
        if line_count > 500:
            severity = 'high' if line_count > 1000 else 'medium'
            findings.append({
                'type': 'architecture',
                'severity': severity,
                'title': f'Fichier trop volumineux ({line_count} lignes)',
                'file': filepath,
                'line': 1,
                'evidence': f'{line_count} lignes de code',
                'context': f'Fichier: {filepath}',
                'matched_text': f'{line_count} lines',
                'remediation': 'Diviser le fichier en modules plus petits et cohérents'
            })
        
        return findings
    
    def analyze(self, content: str, filepath: str, lines: List[str] = None) -> List[Dict[str, Any]]:
        return self.analyze_file_size(content, filepath)
