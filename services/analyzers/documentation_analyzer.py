"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier documentation_analyzer.py du projet CyberConfiance
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

Analyseur de documentation de projet.
"""

import os
from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class DocumentationAnalyzer(BaseAnalyzer):
    
    def __init__(self):
        super().__init__()
        self.has_readme = False
        self.has_license = False
        self.has_contributing = False
        self.has_changelog = False
        self.has_api_docs = False
    
    def analyze_documentation_files(self, files: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        for filepath in files:
            filename = os.path.basename(filepath).lower()
            
            if filename.startswith('readme'):
                self.has_readme = True
            if filename in ['license', 'license.txt', 'license.md', 'licence']:
                self.has_license = True
            if filename.startswith('contributing'):
                self.has_contributing = True
            if filename.startswith('changelog') or filename == 'history.md':
                self.has_changelog = True
            if 'docs' in filepath.lower() or 'documentation' in filepath.lower():
                self.has_api_docs = True
        
        if not self.has_readme:
            findings.append({
                'type': 'documentation',
                'severity': 'high',
                'title': 'README manquant',
                'file': 'projet',
                'line': 0,
                'evidence': 'Aucun fichier README trouvé',
                'context': 'Documentation du projet',
                'matched_text': 'missing README',
                'remediation': 'Créer un README.md avec description, installation, et utilisation'
            })
        
        if not self.has_license:
            findings.append({
                'type': 'documentation',
                'severity': 'medium',
                'title': 'Fichier LICENSE manquant',
                'file': 'projet',
                'line': 0,
                'evidence': 'Aucun fichier LICENSE trouvé',
                'context': 'Licence du projet',
                'matched_text': 'missing LICENSE',
                'remediation': 'Ajouter un fichier LICENSE (MIT, Apache 2.0, GPL, etc.)'
            })
        
        return findings
    
    def analyze_readme_content(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        
        required_sections = [
            ('installation', 'Section Installation', "Ajouter les instructions d'installation"),
            ('usage', 'Section Usage/Utilisation', "Documenter comment utiliser le projet"),
        ]
        
        content_lower = content.lower()
        
        for keyword, section_name, remediation in required_sections:
            if keyword not in content_lower:
                findings.append({
                    'type': 'documentation',
                    'severity': 'low',
                    'title': f'{section_name} manquante dans le README',
                    'file': filepath,
                    'line': 0,
                    'evidence': f'Mot-clé "{keyword}" non trouvé',
                    'context': 'Contenu du README',
                    'matched_text': f'missing {keyword}',
                    'remediation': remediation
                })
        
        if len(content) < 200:
            findings.append({
                'type': 'documentation',
                'severity': 'medium',
                'title': 'README trop court',
                'file': filepath,
                'line': 0,
                'evidence': f'Seulement {len(content)} caractères',
                'context': 'Contenu du README',
                'matched_text': 'short README',
                'remediation': 'Enrichir le README avec plus de détails sur le projet'
            })
        
        return findings
    
    def analyze(self, content: str, filepath: str, lines: List[str] = None) -> List[Dict[str, Any]]:
        if 'readme' in filepath.lower():
            return self.analyze_readme_content(content, filepath)
        return []
