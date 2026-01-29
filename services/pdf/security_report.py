"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier security_report.py du projet CyberConfiance
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

Mixin pour la generation de rapports PDF d'analyse de securite.
"""

import fitz
from utils.document_code_generator import generate_qr_code


class SecurityReportMixin:
    """Mixin for security analysis and prompt analysis PDF report generation"""
    
    def generate_security_analysis_report(self, security_analysis, breach_analysis, ip_address):
        """
        Génère un rapport PDF pour l'analyse de sécurité (URL/domaine/IP/fichier)
        
        Args:
            security_analysis: SecurityAnalysis model instance
            breach_analysis: BreachAnalysis model instance (optional)
            ip_address: IP address of user generating report
            
        Returns:
            bytes: PDF content
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        page.insert_text((30, y_pos), "RAPPORT D'ANALYSE DE SÉCURITÉ", 
                        fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        page.insert_text((30, y_pos), "Type de rapport: Analyse de réputation et de sécurité", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        page.insert_text((30, y_pos), f"ID du rapport: #{security_analysis.id}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 40
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 100), color=None, fill=(0.95, 0.95, 0.95))
        y_pos += 15
        
        page.insert_text((40, y_pos), "INFORMATIONS DE L'ANALYSE", 
                        fontsize=12, fontname="helv")
        y_pos += 20
        
        input_type_labels = {
            'url': 'URL',
            'domain': 'Domaine',
            'ip': 'Adresse IP',
            'hash': 'Hash de fichier',
            'file': 'Fichier'
        }
        page.insert_text((40, y_pos), 
                        f"Type d'analyse: {input_type_labels.get(security_analysis.input_type, security_analysis.input_type)}", 
                        fontsize=10)
        y_pos += 15
        
        input_display = security_analysis.input_value[:80] + ('...' if len(security_analysis.input_value) > 80 else '')
        page.insert_text((40, y_pos), f"Élément analysé: {input_display}", fontsize=10)
        y_pos += 15
        
        page.insert_text((40, y_pos), 
                        f"Date de l'analyse: {security_analysis.created_at.strftime('%d/%m/%Y à %H:%M:%S')}", 
                        fontsize=10)
        y_pos += 15
        
        page.insert_text((40, y_pos), 
                        f"Résultats: {security_analysis.malicious_count}/{security_analysis.total_engines} moteurs ont détecté une menace", 
                        fontsize=10, 
                        color=self.danger_color if security_analysis.threat_detected else self.success_color)
        y_pos += 30
        
        threat_color = self._get_risk_color(security_analysis.threat_level or 'safe')
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), color=threat_color, fill=threat_color, fill_opacity=0.1)
        y_pos += 15
        page.insert_text((40, y_pos), "NIVEAU DE MENACE", fontsize=12, fontname="helv")
        y_pos += 20
        threat_text = (security_analysis.threat_level or 'Sûr').upper()
        page.insert_text((40, y_pos), threat_text, fontsize=14, fontname="helv", color=threat_color)
        y_pos += 40
        
        page.insert_text((30, y_pos), "RÉSULTATS DÉTAILLÉS", 
                        fontsize=14, fontname="helv")
        y_pos += 25
        
        results = security_analysis.analysis_results or {}
        
        if results.get('found') == False:
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 80), 
                          color=self.success_color, fill=self.success_color, fill_opacity=0.1)
            y_pos += 20
            page.insert_text((40, y_pos), "✓ Élément non répertorié", 
                            fontsize=12, fontname="helv", color=self.success_color)
            y_pos += 20
            message = results.get('message', 'Aucune menace connue détectée dans notre base de données.')
            page.insert_text((40, y_pos), message, fontsize=10)
            y_pos += 18
            page.insert_text((40, y_pos), 
                            "Cet élément n'est pas connu dans notre base de données de menaces,", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 14
            page.insert_text((40, y_pos), 
                            "ce qui est généralement un bon signe.", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 30
        elif security_analysis.threat_detected:
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 100), 
                          color=self.danger_color, fill=self.danger_color, fill_opacity=0.1)
            y_pos += 20
            page.insert_text((40, y_pos), "⚠ Menace Détectée", 
                            fontsize=12, fontname="helv", color=self.danger_color)
            y_pos += 20
            page.insert_text((40, y_pos), 
                            "Cet élément a été signalé comme potentiellement dangereux par plusieurs sources.", 
                            fontsize=10, color=self.danger_color)
            y_pos += 20
            page.insert_text((40, y_pos), "• Ne téléchargez pas ou n'exécutez pas ce fichier", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 14
            page.insert_text((40, y_pos), "• Ne visitez pas ce site ou cette URL", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 14
            page.insert_text((40, y_pos), "• Vérifiez avec votre équipe de sécurité IT", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 30
        else:
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 60), 
                          color=self.success_color, fill=self.success_color, fill_opacity=0.1)
            y_pos += 20
            page.insert_text((40, y_pos), "✓ Aucune Menace Majeure Détectée", 
                            fontsize=12, fontname="helv", color=self.success_color)
            y_pos += 20
            page.insert_text((40, y_pos), 
                            "Cet élément semble sûr selon les analyses de sécurité disponibles.", 
                            fontsize=10)
            y_pos += 30
        
        if results.get('found', True) and not results.get('error', False) and 'total' in results:
            stats = [
                ("Malveillant", results.get('malicious', 0), self.danger_color),
                ("Suspect", results.get('suspicious', 0), self.warning_color),
                ("Sûr", results.get('clean', 0), self.success_color),
                ("Total des moteurs", results.get('total', 0), self.base_color)
            ]
            
            for label, value, color in stats:
                if y_pos > self.max_y - 50:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 30), color=color, fill=color, fill_opacity=0.05)
                page.insert_text((40, y_pos + 15), f"{label}: {value}", fontsize=10, fontname="helv")
                y_pos += 35
        
        source_results = results.get('source_results', {})
        if source_results:
            if y_pos > self.max_y - 150:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
            y_pos += 20
            
            page.insert_text((30, y_pos), "RÉSULTATS PAR SOURCE DE SÉCURITÉ", 
                            fontsize=14, fontname="helv", color=self.base_color)
            y_pos += 25
            
            vt_result = source_results.get('virustotal', {})
            if vt_result:
                if y_pos > self.max_y - 80:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                vt_color = self.danger_color if vt_result.get('malicious', 0) > 0 else self.success_color
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 70), color=vt_color, fill=vt_color, fill_opacity=0.05)
                y_pos += 15
                page.insert_text((40, y_pos), "VirusTotal", fontsize=12, fontname="helv", color=vt_color)
                y_pos += 18
                if vt_result.get('error'):
                    page.insert_text((50, y_pos), f"Erreur: {vt_result.get('error')}", fontsize=9, color=(0.5, 0.5, 0.5))
                else:
                    page.insert_text((50, y_pos), f"Malveillant: {vt_result.get('malicious', 0)} | Suspect: {vt_result.get('suspicious', 0)} | Sûr: {vt_result.get('clean', 0)}", fontsize=9)
                    y_pos += 14
                    page.insert_text((50, y_pos), f"Total des moteurs: {vt_result.get('total', 0)}", fontsize=9, color=(0.5, 0.5, 0.5))
                y_pos += 25
            
            gsb_result = source_results.get('google_safe_browsing', {})
            if gsb_result:
                if y_pos > self.max_y - 70:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                gsb_safe = gsb_result.get('safe', True)
                gsb_color = self.success_color if gsb_safe else self.danger_color
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), color=gsb_color, fill=gsb_color, fill_opacity=0.05)
                y_pos += 15
                page.insert_text((40, y_pos), "Google Safe Browsing", fontsize=12, fontname="helv", color=gsb_color)
                y_pos += 18
                if gsb_result.get('error'):
                    page.insert_text((50, y_pos), f"Erreur: {gsb_result.get('error')}", fontsize=9, color=(0.5, 0.5, 0.5))
                else:
                    status_text = "Sûr - Aucune menace détectée" if gsb_safe else "Menace détectée"
                    page.insert_text((50, y_pos), status_text, fontsize=9, color=gsb_color)
                    if not gsb_safe and gsb_result.get('threats'):
                        y_pos += 14
                        threats_str = ', '.join(gsb_result.get('threats', []))[:80]
                        page.insert_text((50, y_pos), f"Types: {threats_str}", fontsize=9, color=(0.5, 0.5, 0.5))
                y_pos += 25
            
            urlhaus_result = source_results.get('urlhaus', {})
            if urlhaus_result:
                if y_pos > self.max_y - 70:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                urlhaus_safe = not urlhaus_result.get('found', False)
                urlhaus_color = self.success_color if urlhaus_safe else self.danger_color
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), color=urlhaus_color, fill=urlhaus_color, fill_opacity=0.05)
                y_pos += 15
                page.insert_text((40, y_pos), "URLhaus (abuse.ch)", fontsize=12, fontname="helv", color=urlhaus_color)
                y_pos += 18
                if urlhaus_result.get('error'):
                    page.insert_text((50, y_pos), f"Erreur: {urlhaus_result.get('error')}", fontsize=9, color=(0.5, 0.5, 0.5))
                else:
                    status_text = "Sûr - Non répertorié" if urlhaus_safe else "URL malveillante détectée"
                    page.insert_text((50, y_pos), status_text, fontsize=9, color=urlhaus_color)
                    if not urlhaus_safe and urlhaus_result.get('threat_type'):
                        y_pos += 14
                        page.insert_text((50, y_pos), f"Type: {urlhaus_result.get('threat_type')}", fontsize=9, color=(0.5, 0.5, 0.5))
                y_pos += 25
        
        url_shortener = results.get('url_shortener', {})
        if url_shortener.get('detected'):
            if y_pos > self.max_y - 150:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_line((30, y_pos), (565, y_pos), color=self.warning_color, width=1)
            y_pos += 20
            
            page.insert_text((30, y_pos), "CHAINE DE REDIRECTION (URL RACCOURCIE)", 
                            fontsize=14, fontname="helv", color=self.warning_color)
            y_pos += 25
            
            service = url_shortener.get('service', 'Inconnu')
            page.insert_text((40, y_pos), f"Service detecte: {service}", fontsize=10, fontname="helv", color=self.warning_color)
            y_pos += 18
            
            original_url = url_shortener.get('original_url', '')
            if original_url:
                page.insert_text((40, y_pos), "URL originale:", fontsize=9, fontname="helv")
                y_pos += 12
                page, y_pos = self._insert_wrapped_url(page, doc, original_url, 50, y_pos, fontsize=8)
                y_pos += 8
            
            final_url = url_shortener.get('final_url', '')
            if final_url and final_url != original_url:
                if y_pos > self.max_y - 40:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                page.insert_text((40, y_pos), "URL finale:", fontsize=9, fontname="helv", color=self.success_color)
                y_pos += 12
                page, y_pos = self._insert_wrapped_url(page, doc, final_url, 50, y_pos, fontsize=8, color=self.success_color)
                y_pos += 8
            
            redirect_count = url_shortener.get('redirect_count', 0)
            page.insert_text((40, y_pos), f"Nombre de redirections: {redirect_count}", fontsize=9)
            y_pos += 20
            
            redirect_chain = url_shortener.get('redirect_chain', [])
            if redirect_chain:
                page.insert_text((40, y_pos), "Chaine de redirection complete:", fontsize=10, fontname="helv")
                y_pos += 18
                
                for idx, redirect in enumerate(redirect_chain, 1):
                    if y_pos > self.max_y - 60:
                        page = doc.new_page(width=595, height=842)
                        y_pos = 90
                    
                    status_code = redirect.get('status_code', '')
                    redirect_type = redirect.get('redirect_type', '')
                    is_shortener = redirect.get('is_shortener', False)
                    
                    step_color = self.warning_color if is_shortener else self.base_color
                    page.draw_rect(fitz.Rect(40, y_pos, 565, y_pos + 4), color=step_color, fill=step_color)
                    y_pos += 12
                    
                    step_info = f"Etape {idx}"
                    if status_code:
                        step_info += f" | HTTP {status_code}"
                    if redirect_type:
                        step_info += f" | {redirect_type}"
                    if is_shortener:
                        step_info += " | [Raccourcisseur]"
                    
                    page.insert_text((50, y_pos), step_info, fontsize=8, fontname="helv", color=step_color)
                    y_pos += 12
                    
                    url = redirect.get('url', '')
                    page, y_pos = self._insert_wrapped_url(page, doc, url, 50, y_pos, fontsize=7)
                    y_pos += 6
            
            if url_shortener.get('multiple_shorteners'):
                y_pos += 5
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 30), 
                              color=self.danger_color, fill=self.danger_color, fill_opacity=0.1)
                y_pos += 12
                page.insert_text((40, y_pos), "ATTENTION: Plusieurs raccourcisseurs detectes dans la chaine", 
                                fontsize=9, fontname="helv", color=self.danger_color)
                y_pos += 25
            
            if url_shortener.get('expansion_error'):
                page.insert_text((40, y_pos), f"Erreur: {url_shortener.get('expansion_error')}", 
                                fontsize=8, color=self.danger_color)
                y_pos += 14
            
            y_pos += 10
        
        if breach_analysis:
            if y_pos > self.max_y - 120:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
            y_pos += 20
            
            page.insert_text((30, y_pos), "ANALYSE DE FUITE D'EMAIL", 
                            fontsize=14, fontname="helv", color=self.danger_color)
            y_pos += 25
            
            page.insert_text((40, y_pos), f"Email: {breach_analysis.email}", fontsize=10)
            y_pos += 15
            page.insert_text((40, y_pos), f"Fuites détectées: {breach_analysis.breach_count}", 
                            fontsize=10, 
                            color=self.danger_color if breach_analysis.breach_count > 0 else self.success_color)
            y_pos += 15
            risk_text = (breach_analysis.risk_level or 'Sûr').capitalize()
            page.insert_text((40, y_pos), f"Niveau de risque: {risk_text}", 
                            fontsize=10, color=self._get_risk_color(breach_analysis.risk_level or 'safe'))
            y_pos += 25
            
            if breach_analysis.breaches_data:
                breach_data = breach_analysis.breaches_data
                if breach_data.get('breaches'):
                    if y_pos > self.max_y - 50:
                        page = doc.new_page(width=595, height=842)
                        y_pos = 90
                    page.insert_text((40, y_pos), "Fuites identifiées:", fontsize=10, fontname="helv")
                    y_pos += 18
                    for breach in breach_data['breaches'][:5]:
                        if y_pos > self.max_y - 30:
                            page = doc.new_page(width=595, height=842)
                            y_pos = 90
                        breach_name = breach.get('Name', 'Inconnu')
                        breach_date = breach.get('BreachDate', '')
                        page.insert_text((50, y_pos), f"• {breach_name} ({breach_date})", fontsize=9)
                        y_pos += 14
        
        qr_url = "https://cyberconfiance.com/outils/analyseur-securite"
        try:
            qr_bytes = generate_qr_code(qr_url, box_size=3, border=1)
        except Exception:
            qr_bytes = None

        total_pages = len(doc)
        for page_num, page in enumerate(doc, 1):
            self._add_header_footer(page, page_num, total_pages, ip_address, 
                                  document_code=security_analysis.document_code,
                                  qr_url=qr_url,
                                  qr_bytes=qr_bytes)
        
        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
    
    def generate_prompt_analysis_report(self, analysis, ip_address):
        """
        Genere un rapport PDF pour l'analyse d'injection de prompt IA
        Format identique aux rapports breach et security
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        page.insert_text((30, y_pos), "RAPPORT D'ANALYSE D'INJECTION DE PROMPT", 
                        fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        page.insert_text((30, y_pos), "Type de rapport: Detection d'injection IA et code malveillant", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        page.insert_text((30, y_pos), f"ID du rapport: #{analysis.id}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 40
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 70), color=None, fill=(0.95, 0.95, 0.95))
        y_pos += 15
        
        page.insert_text((40, y_pos), "INFORMATIONS DE L'ANALYSE", 
                        fontsize=12, fontname="helv")
        y_pos += 20
        
        page.insert_text((40, y_pos), f"Longueur du prompt: {analysis.prompt_length or 0} caracteres", fontsize=10)
        y_pos += 15
        
        detected_issues = analysis.detected_issues or []
        page.insert_text((40, y_pos), f"Nombre de problemes detectes: {len(detected_issues)}", 
                        fontsize=10, color=self.danger_color if len(detected_issues) > 0 else self.success_color)
        y_pos += 30
        
        threat_level = analysis.threat_level or 'safe'
        threat_color = self._get_risk_color(threat_level)
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), color=threat_color, fill=threat_color, fill_opacity=0.1)
        y_pos += 15
        page.insert_text((40, y_pos), "NIVEAU DE MENACE", fontsize=12, fontname="helv")
        y_pos += 20
        threat_text = threat_level.upper()
        page.insert_text((40, y_pos), threat_text, fontsize=14, fontname="helv", color=threat_color)
        y_pos += 40
        
        page.insert_text((30, y_pos), "STATUT DES DETECTIONS", 
                        fontsize=14, fontname="helv", color=self.base_color)
        y_pos += 25
        
        detections = [
            ("Injection de prompt", analysis.injection_detected, self.danger_color),
            ("Code malveillant", analysis.code_detected, self.warning_color),
            ("Obfuscation", analysis.obfuscation_detected, self.warning_color)
        ]
        
        for label, detected, color in detections:
            status = "DETECTE" if detected else "Non detecte"
            status_color = color if detected else self.success_color
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 25), color=status_color, fill=status_color, fill_opacity=0.05)
            page.insert_text((40, y_pos + 15), f"{label}: {status}", fontsize=10, fontname="helv", color=status_color)
            y_pos += 30
        
        y_pos += 10
        
        if detected_issues:
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.insert_text((30, y_pos), "PROBLEMES DETECTES", 
                            fontsize=14, fontname="helv", color=self.danger_color)
            y_pos += 25
            
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_issues = sorted(detected_issues, key=lambda x: severity_order.get(x.get('severity', 'low'), 4))
            
            for idx, issue in enumerate(sorted_issues[:15], 1):
                if y_pos > self.max_y - 60:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                severity = issue.get('severity', 'low')
                severity_color = self._get_risk_color(severity)
                
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 5), color=severity_color, fill=severity_color)
                y_pos += 18
                
                page.insert_text((40, y_pos), f"{idx}. [{severity.upper()}] {issue.get('message', '')[:65]}", 
                                fontsize=10, fontname="helv")
                y_pos += 16
                
                if issue.get('category'):
                    page.insert_text((50, y_pos), f"Categorie: {issue.get('category')}", 
                                    fontsize=8, color=(0.5, 0.5, 0.5))
                    y_pos += 14
                
                y_pos += 6
        else:
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 60), 
                          color=self.success_color, fill=self.success_color, fill_opacity=0.1)
            y_pos += 25
            page.insert_text((40, y_pos), "Aucune injection detectee", 
                            fontsize=12, fontname="helv", color=self.success_color)
            y_pos += 20
            page.insert_text((40, y_pos), 
                            "Ce prompt ne contient pas de tentatives d'injection connues.", 
                            fontsize=10)
            y_pos += 35
        
        if y_pos > self.max_y - 180:
            page = doc.new_page(width=595, height=842)
            y_pos = 90
        
        page.insert_text((30, y_pos), "EXTRAIT DU PROMPT ANALYSE", 
                        fontsize=14, fontname="helv", color=self.base_color)
        y_pos += 25
        
        prompt_preview = (analysis.prompt_text or '')[:400]
        prompt_lines = self._wrap_text(prompt_preview, 85)
        
        box_height = min(len(prompt_lines[:8]) * 14 + 20, 140)
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + box_height), 
                      color=(0.9, 0.9, 0.9), fill=(0.95, 0.95, 0.95))
        y_pos += 10
        
        for line in prompt_lines[:8]:
            page.insert_text((40, y_pos + 5), line, fontsize=8, color=(0.3, 0.3, 0.3))
            y_pos += 14
        
        if len(prompt_lines) > 8:
            page.insert_text((40, y_pos + 5), "...[texte tronque]", fontsize=8, color=(0.5, 0.5, 0.5))
            y_pos += 14
        
        y_pos += 30
        
        if y_pos > self.max_y - 120:
            page = doc.new_page(width=595, height=842)
            y_pos = 90
        
        page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
        y_pos += 20
        
        page.insert_text((30, y_pos), "RECOMMANDATIONS DE SECURITE", 
                        fontsize=14, fontname="helv", color=self.base_color)
        y_pos += 25
        
        if analysis.threat_detected:
            recommendations = [
                "N'utilisez pas ce prompt tel quel dans un systeme IA",
                "Verifiez et nettoyez le contenu avant toute utilisation",
                "Implementez des filtres de securite sur vos systemes IA",
                "Surveillez les logs pour detecter les patterns d'attaque",
                "Formez vos equipes aux risques d'injection de prompt"
            ]
        else:
            recommendations = [
                "Ce prompt ne contient pas de menaces evidentes",
                "Restez vigilant face aux nouveaux patterns d'injection",
                "Mettez en place une validation des entrees utilisateur",
                "Maintenez vos systemes de detection a jour"
            ]
        
        for rec in recommendations:
            page.insert_text((40, y_pos), f"- {rec}", fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 16
        
        qr_url = "https://cyberconfiance.com/outils/analyseur-prompt"
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
