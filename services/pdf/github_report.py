"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier github_report.py du projet CyberConfiance
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

Mixin pour la generation de rapports PDF d'audit GitHub.
"""

import fitz
from utils.document_code_generator import generate_qr_code


class GitHubReportMixin:
    """Mixin for GitHub code analysis PDF report generation"""
    
    def generate_github_analysis_report(self, analysis, ip_address):
        """
        Génère un rapport PDF pour l'analyse de code GitHub
        
        Args:
            analysis: GitHubCodeAnalysis model instance
            ip_address: IP address of user generating report
            
        Returns:
            bytes: PDF content
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        page.insert_text((30, y_pos), "RAPPORT D'ANALYSE DE CODE GITHUB", 
                        fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        page.insert_text((30, y_pos), "Type de rapport: Analyse de securite et qualite du code", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        page.insert_text((30, y_pos), f"ID du rapport: #{analysis.id}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 40
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 120), color=None, fill=(0.95, 0.95, 0.95))
        y_pos += 15
        
        page.insert_text((40, y_pos), "INFORMATIONS DU DEPOT", 
                        fontsize=12, fontname="helv")
        y_pos += 20
        
        page.insert_text((40, y_pos), f"Depot: {analysis.repo_owner}/{analysis.repo_name}", fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), f"Branche: {analysis.branch}", fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), f"Commit: {analysis.commit_hash or 'N/A'}", fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), 
                        f"Date de l'analyse: {analysis.created_at.strftime('%d/%m/%Y a %H:%M:%S')}", 
                        fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), f"Fichiers analyses: {analysis.total_files_analyzed}", fontsize=10)
        y_pos += 15
        
        total_lines = getattr(analysis, 'total_lines_analyzed', 0) or 0
        total_dirs = getattr(analysis, 'total_directories', 0) or 0
        page.insert_text((40, y_pos), f"Lignes de code: {total_lines:,}  |  Dossiers scannes: {total_dirs}", fontsize=10)
        y_pos += 15
        
        file_types = getattr(analysis, 'file_types_distribution', None) or {}
        if file_types and isinstance(file_types, dict):
            types_str = ", ".join([f"{ext}: {count}" for ext, count in list(file_types.items())[:5]])
            if types_str:
                page.insert_text((40, y_pos), f"Types de fichiers: {types_str}", fontsize=9, color=(0.3, 0.3, 0.3))
                y_pos += 15
        
        y_pos += 15
        
        risk_color = self._get_risk_color(analysis.risk_level or 'safe')
        page.draw_rect(fitz.Rect(30, y_pos, 290, y_pos + 80), color=risk_color, fill=risk_color, fill_opacity=0.1)
        page.draw_rect(fitz.Rect(305, y_pos, 565, y_pos + 80), color=self.base_color, fill=self.base_color, fill_opacity=0.1)
        
        y_score = y_pos + 15
        page.insert_text((40, y_score), "NIVEAU DE RISQUE", fontsize=10, fontname="helv")
        y_score += 18
        risk_text = (analysis.risk_level or 'Faible').upper()
        page.insert_text((40, y_score), risk_text, fontsize=16, fontname="helv", color=risk_color)
        y_score += 20
        page.insert_text((40, y_score), f"Score securite: {analysis.security_score}/100", fontsize=9, color=(0.3, 0.3, 0.3))
        
        y_overall = y_pos + 15
        page.insert_text((315, y_overall), "SCORE GLOBAL", fontsize=10, fontname="helv")
        y_overall += 18
        page.insert_text((315, y_overall), f"{analysis.overall_score}/100", fontsize=16, fontname="helv", color=self.base_color)
        y_overall += 20
        page.insert_text((315, y_overall), f"Issues: {analysis.total_issues_found}", fontsize=9, color=(0.3, 0.3, 0.3))
        
        y_pos += 95
        
        page.insert_text((30, y_pos), "RESUME DES PROBLEMES", 
                        fontsize=14, fontname="helv")
        y_pos += 25
        
        issue_stats = [
            ("Critiques", analysis.critical_issues or 0, self.danger_color),
            ("Eleves", analysis.high_issues or 0, self.warning_color),
            ("Moyens", analysis.medium_issues or 0, (251/255, 191/255, 36/255)),
            ("Faibles", analysis.low_issues or 0, self.success_color)
        ]
        
        x_offset = 40
        for label, count, color in issue_stats:
            page.draw_rect(fitz.Rect(x_offset, y_pos, x_offset + 120, y_pos + 35), 
                          color=color, fill=color, fill_opacity=0.1)
            page.insert_text((x_offset + 10, y_pos + 15), label, fontsize=9, color=color)
            page.insert_text((x_offset + 10, y_pos + 28), str(count), fontsize=12, fontname="helv", color=color)
            x_offset += 130
        
        y_pos += 50
        
        findings_sections = [
            ("PROBLEMES DE SECURITE", analysis.security_findings or [], self.danger_color),
            ("PATTERNS IA TOXIQUES (VIBECODING)", analysis.toxic_ai_patterns or [], self.warning_color),
            ("PROBLEMES DE PERFORMANCE", analysis.performance_findings or [], (251/255, 191/255, 36/255)),
            ("PROBLEMES DE DEPENDANCES", analysis.dependency_findings or [], self.base_color),
            ("ARCHITECTURE", analysis.architecture_findings or [], self.base_color),
            ("HYGIENE GIT", analysis.git_hygiene_findings or [], self.base_color),
            ("DOCUMENTATION", analysis.documentation_findings or [], self.base_color),
            ("QUALITE DU CODE", analysis.code_quality_findings or [], self.warning_color),
        ]
        
        for section_title, findings, section_color in findings_sections:
            if not findings:
                continue
            
            findings_to_display = findings[:15]
            
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_line((30, y_pos), (565, y_pos), color=section_color, width=1)
            y_pos += 15
            
            page.insert_text((30, y_pos), section_title, fontsize=12, fontname="helv", color=section_color)
            y_pos += 20
            
            for idx, finding in enumerate(findings_to_display, 1):
                if y_pos > self.max_y - 60:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                severity = finding.get('severity', 'info')
                sev_color = self._get_risk_color(severity)
                
                page.draw_rect(fitz.Rect(40, y_pos - 3, 75, y_pos + 10), 
                              color=sev_color, fill=sev_color, fill_opacity=0.2)
                page.insert_text((42, y_pos + 6), severity.upper()[:4], fontsize=7, color=sev_color)
                
                title = finding.get('title', 'Issue')
                if len(title) > 80:
                    title = title[:77] + "..."
                page.insert_text((80, y_pos + 6), f"{idx}. {title}", fontsize=9, fontname="helv")
                y_pos += 16
                
                file_info = finding.get('file', '')
                line_info = finding.get('line', '')
                if file_info:
                    if file_info.startswith('/tmp/github_analysis_'):
                        parts = file_info.split('/')
                        if len(parts) > 3:
                            file_info = '/'.join(parts[3:])
                    
                    if len(file_info) > 60:
                        file_info = "..." + file_info[-57:]
                    
                    location = f"Fichier: {file_info}"
                    if line_info:
                        location += f" (ligne {line_info})"
                    page.insert_text((80, y_pos), location, fontsize=8, color=(0.5, 0.5, 0.5))
                    y_pos += 12
                
                remediation = finding.get('remediation', '')
                if remediation:
                    if len(remediation) > 90:
                        remediation = remediation[:87] + "..."
                    rem_text = f"Remediation: {remediation}"
                    page.insert_text((80, y_pos), rem_text, fontsize=8, color=(0.3, 0.3, 0.3))
                    y_pos += 12
                
                y_pos += 8
            
            if len(findings) > 15:
                remaining = len(findings) - 15
                page.insert_text((40, y_pos), f"... et {remaining} autre{'s' if remaining > 1 else ''} probleme{'s' if remaining > 1 else ''}", 
                                fontsize=8, color=(0.5, 0.5, 0.5))
                y_pos += 15
            
            y_pos += 10
        
        if y_pos > self.max_y - 150:
            page = doc.new_page(width=595, height=842)
            y_pos = 90
        
        page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
        y_pos += 20
        
        page.insert_text((30, y_pos), "TECHNOLOGIES DETECTEES", 
                        fontsize=12, fontname="helv", color=self.base_color)
        y_pos += 20
        
        languages = analysis.languages_detected or {}
        if languages:
            lang_text = ", ".join([f"{lang}: {count}" for lang, count in list(languages.items())[:6]])
            page.insert_text((40, y_pos), f"Langages: {lang_text}", fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 15
        
        frameworks = analysis.frameworks_detected or []
        if frameworks:
            fw_text = ", ".join(frameworks[:6])
            page.insert_text((40, y_pos), f"Frameworks: {fw_text}", fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 25
        
        if y_pos > self.max_y - 120:
            page = doc.new_page(width=595, height=842)
            y_pos = 90
        
        page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
        y_pos += 20
        
        page.insert_text((30, y_pos), "RECOMMANDATIONS", 
                        fontsize=12, fontname="helv", color=self.base_color)
        y_pos += 20
        
        if (analysis.critical_issues or 0) > 0 or (analysis.high_issues or 0) > 0:
            recommendations = [
                "Corrigez immediatement les problemes de securite critiques",
                "Supprimez tous les secrets exposes du code source",
                "Utilisez des variables d'environnement pour les configurations sensibles",
                "Implementez des requetes parametrees pour eviter les injections SQL",
                "Revoyez le code genere par l'IA avant de le deployer",
                "Mettez en place une revue de code systematique"
            ]
        else:
            recommendations = [
                "Continuez a maintenir de bonnes pratiques de securite",
                "Mettez a jour regulierement vos dependances",
                "Implementez des tests de securite automatises",
                "Documentez votre code et architecture"
            ]
        
        for rec in recommendations[:6]:
            if y_pos > self.max_y - 20:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            page.insert_text((40, y_pos), f"- {rec}", fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 16
        
        qr_url = "https://cyberconfiance.com/outils/analyseur-github"
        try:
            qr_bytes = generate_qr_code(qr_url, box_size=3, border=1)
        except Exception:
            qr_bytes = None

        total_pages = len(doc)
        for page_num, p in enumerate(doc, 1):
            self._add_header_footer(p, page_num, total_pages, ip_address, 
                                   document_code=analysis.document_code,
                                   qr_url=qr_url,
                                   qr_bytes=qr_bytes)
        
        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
