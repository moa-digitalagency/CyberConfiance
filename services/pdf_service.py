import fitz
import io
import os
import re
from datetime import datetime
from PIL import Image
from utils.document_code_generator import generate_qr_code


class PDFReportService:
    """Service pour générer des rapports PDF forensiques professionnels"""
    
    def __init__(self):
        self.logo_path = 'static/img/logo_dark.png'
        self.base_color = (59/255, 130/255, 246/255)
        self.primary_color = (59/255, 130/255, 246/255)
        self.danger_color = (239/255, 68/255, 68/255)
        self.warning_color = (217/255, 119/255, 6/255)
        self.success_color = (16/255, 185/255, 129/255)
        self.text_color = (0.3, 0.3, 0.3)
        self.footer_height = 60
        self.max_y = 780
    
    def _add_cover_page(self, page, title, subtitle):
        """Ajoute une page de couverture au rapport"""
        width, height = page.rect.width, page.rect.height
        
        page.draw_rect(fitz.Rect(0, 0, width, height), color=None, fill=(0.05, 0.05, 0.1))
        
        page.draw_rect(fitz.Rect(0, height/2 - 100, width, height/2 + 100), 
                      color=None, fill=self.primary_color, fill_opacity=0.1)
        
        if os.path.exists(self.logo_path):
            try:
                logo_rect = fitz.Rect(width/2 - 100, 120, width/2 + 100, 200)
                page.insert_image(logo_rect, filename=self.logo_path)
            except:
                pass
        
        title_width = fitz.get_text_length(title, fontsize=28, fontname="helv")
        page.insert_text(((width - title_width) / 2, height/2 - 20), title, 
                        fontsize=28, fontname="helv", color=(1, 1, 1))
        
        subtitle_width = fitz.get_text_length(subtitle, fontsize=14, fontname="helv")
        page.insert_text(((width - subtitle_width) / 2, height/2 + 20), subtitle, 
                        fontsize=14, fontname="helv", color=(0.7, 0.7, 0.7))
        
        timestamp = datetime.now().strftime("%d/%m/%Y")
        ts_width = fitz.get_text_length(f"Genere le {timestamp}", fontsize=10, fontname="helv")
        page.insert_text(((width - ts_width) / 2, height - 80), f"Genere le {timestamp}", 
                        fontsize=10, fontname="helv", color=(0.5, 0.5, 0.5))
        
        page.insert_text((30, height - 40), "cyberconfiance.com", 
                        fontsize=10, fontname="helv", color=self.primary_color)
        
    def _add_header_footer(self, page, page_num, total_pages, ip_address, site_url="https://cyberconfiance.com", document_code=None, qr_url=None):
        """Ajoute en-tête et pied de page à une page"""
        width, height = page.rect.width, page.rect.height
        
        if os.path.exists(self.logo_path):
            try:
                logo_rect = fitz.Rect(30, 20, 180, 60)
                page.insert_image(logo_rect, filename=self.logo_path)
            except:
                pass
        
        if qr_url:
            try:
                qr_bytes = generate_qr_code(qr_url, box_size=3, border=1)
                qr_img = Image.open(io.BytesIO(qr_bytes))
                
                qr_size = 50
                qr_x = width - 30 - qr_size
                qr_y = 15
                qr_rect = fitz.Rect(qr_x, qr_y, qr_x + qr_size, qr_y + qr_size)
                
                page.insert_image(qr_rect, stream=qr_bytes)
            except Exception as e:
                pass
        
        page.draw_line((30, 70), (width - 30, 70), color=self.base_color, width=2)
        
        footer_y = height - 35
        page.draw_line((30, footer_y - 10), (width - 30, footer_y - 10), color=self.base_color, width=1)
        
        timestamp = datetime.now().strftime("%d/%m/%Y à %H:%M")
        if document_code:
            footer_text = f"Cyberconfiance.com | Code: {document_code} | Rapport généré le {timestamp} par {ip_address} | Page {page_num}/{total_pages}"
        else:
            footer_text = f"Cyberconfiance.com | Rapport généré le {timestamp} par {ip_address} | Page {page_num}/{total_pages}"
        page.insert_text((30, footer_y + 5), footer_text, fontsize=8, color=(0.5, 0.5, 0.5))
        
    def _get_risk_color(self, risk_level):
        """Retourne la couleur selon le niveau de risque"""
        risk_colors = {
            'critique': self.danger_color,
            'danger': self.danger_color,
            'élevé': self.warning_color,
            'warning': self.warning_color,
            'moyen': self.warning_color,
            'modéré': (251/255, 191/255, 36/255),
            'faible': self.success_color,
            'safe': self.success_color,
            'sûr': self.success_color
        }
        return risk_colors.get(risk_level.lower(), self.base_color)
        
    def generate_breach_report(self, breach_analysis, breach_result, ip_address):
        """
        Génère un rapport PDF pour l'analyse de fuite de données
        
        Args:
            breach_analysis: BreachAnalysis model instance
            breach_result: Dict with breach data from HIBP API
            ip_address: IP address of user generating report
            
        Returns:
            bytes: PDF content
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        page.insert_text((30, y_pos), "RAPPORT D'ANALYSE DE FUITE DE DONNEES", 
                        fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        page.insert_text((30, y_pos), "Type de rapport: Analyse de securite des fuites de donnees", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        page.insert_text((30, y_pos), f"ID du rapport: #{breach_analysis.id}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 40
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 80), color=None, fill=(0.95, 0.95, 0.95))
        y_pos += 15
        
        page.insert_text((40, y_pos), "INFORMATIONS DE L'ANALYSE", 
                        fontsize=12, fontname="helv")
        y_pos += 20
        
        page.insert_text((40, y_pos), f"Email analysé: {breach_analysis.email}", fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), 
                        f"Date de l'analyse: {breach_analysis.created_at.strftime('%d/%m/%Y à %H:%M:%S')}", 
                        fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), f"Nombre de fuites détectées: {breach_analysis.breach_count}", 
                        fontsize=10, color=self.danger_color if breach_analysis.breach_count > 0 else self.success_color)
        y_pos += 30
        
        risk_color = self._get_risk_color(breach_analysis.risk_level or 'safe')
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), color=risk_color, fill=risk_color, fill_opacity=0.1)
        y_pos += 15
        page.insert_text((40, y_pos), "NIVEAU DE RISQUE", fontsize=12, fontname="helv")
        y_pos += 20
        risk_text = (breach_analysis.risk_level or 'Sur').upper()
        page.insert_text((40, y_pos), risk_text, fontsize=14, fontname="helv", color=risk_color)
        y_pos += 40
        
        if breach_result.get('breaches'):
            page.insert_text((30, y_pos), "DETAILS DES FUITES DETECTEES", 
                            fontsize=14, fontname="helv", color=self.danger_color)
            y_pos += 25
            
            for idx, breach in enumerate(breach_result['breaches'][:15], 1):
                if y_pos > self.max_y:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                page.draw_rect(fitz.Rect(41, y_pos, 565, y_pos + 5), color=self.danger_color, fill=self.danger_color)
                y_pos += 18
                
                page.insert_text((54, y_pos), f"{idx}. {breach.get('Name', 'Inconnu')}", 
                                fontsize=11, fontname="helv")
                y_pos += 18
                
                if breach.get('BreachDate'):
                    page.insert_text((54, y_pos), f"Date de la fuite: {breach.get('BreachDate')}", 
                                    fontsize=9, color=(0.3, 0.3, 0.3))
                    y_pos += 14
                
                if breach.get('PwnCount'):
                    page.insert_text((54, y_pos), 
                                    f"Comptes affectés: {breach.get('PwnCount'):,} utilisateurs", 
                                    fontsize=9, color=(0.3, 0.3, 0.3))
                    y_pos += 14
                
                if breach.get('DataClasses'):
                    data_classes = ', '.join(breach.get('DataClasses', [])[:8])
                    page.insert_text((54, y_pos), f"Données compromises: {data_classes}", 
                                    fontsize=9, color=self.danger_color)
                    y_pos += 16
                
                y_pos += 8
        else:
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 60), 
                          color=self.success_color, fill=self.success_color, fill_opacity=0.1)
            y_pos += 25
            page.insert_text((40, y_pos), "✓ Aucune fuite détectée", 
                            fontsize=12, fontname="helv", color=self.success_color)
            y_pos += 20
            page.insert_text((40, y_pos), 
                            "Votre adresse email n'apparaît dans aucune base de données de fuites connues.", 
                            fontsize=10)
        
        total_pages = len(doc)
        for page_num, page in enumerate(doc, 1):
            self._add_header_footer(page, page_num, total_pages, ip_address, 
                                  document_code=breach_analysis.document_code,
                                  qr_url="https://cyberconfiance.com/")
        
        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
        
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
        
        if breach_analysis:
            if y_pos > self.max_y:
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
                    page.insert_text((40, y_pos), "Fuites identifiées:", fontsize=10, fontname="helv")
                    y_pos += 18
                    for breach in breach_data['breaches'][:5]:
                        breach_name = breach.get('Name', 'Inconnu')
                        breach_date = breach.get('BreachDate', '')
                        page.insert_text((50, y_pos), f"• {breach_name} ({breach_date})", fontsize=9)
                        y_pos += 14
        
        total_pages = len(doc)
        for page_num, page in enumerate(doc, 1):
            self._add_header_footer(page, page_num, total_pages, ip_address, 
                                  document_code=security_analysis.document_code,
                                  qr_url="https://cyberconfiance.com/outils/analyseur-securite")
        
        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
        
    def generate_quiz_report(self, quiz_result, recommendations, ip_address):
        """
        Genere un rapport PDF pour les resultats du quiz
        
        Args:
            quiz_result: QuizResult model instance
            recommendations: Dict with priority_rules, weak_areas, suggested_tools
            ip_address: IP address of user generating report
            
        Returns:
            bytes: PDF content
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        page.insert_text((30, y_pos), "RAPPORT DE RESULTATS QUIZ CYBERSECURITE", 
                        fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        page.insert_text((30, y_pos), "Evaluation de votre niveau de cybersecurite", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        page.insert_text((30, y_pos), f"ID du rapport: #{quiz_result.id}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 40
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 80), color=None, fill=(0.95, 0.95, 0.95))
        y_pos += 15
        
        page.insert_text((40, y_pos), "INFORMATIONS DU QUIZ", 
                        fontsize=12, fontname="hebo")
        y_pos += 20
        
        page.insert_text((40, y_pos), f"Email: {quiz_result.email}", fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), 
                        f"Date: {quiz_result.created_at.strftime('%d/%m/%Y a %H:%M:%S')}", 
                        fontsize=10)
        y_pos += 15
        page.insert_text((40, y_pos), f"Score global: {quiz_result.overall_score}%", 
                        fontsize=10, color=self.success_color if quiz_result.overall_score >= 70 else self.warning_color)
        y_pos += 35
        
        page.insert_text((30, y_pos), "SCORES PAR CATEGORIE", 
                        fontsize=14, fontname="hebo", color=self.base_color)
        y_pos += 30
        
        categories = quiz_result.category_scores
        if 'percentages' in categories:
            for cat, score in categories['percentages'].items():
                cat_name = cat.capitalize()
                page.insert_text((40, y_pos), f"{cat_name}: {score}%", fontsize=10)
                page.draw_rect(fitz.Rect(240, y_pos - 10, 240 + (score * 3), y_pos + 2), 
                              color=self.base_color, fill=self.base_color, fill_opacity=0.3)
                y_pos += 22
        
        y_pos += 25
        
        if recommendations and recommendations.get('priority_rules'):
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.insert_text((30, y_pos), "REGLES D'OR RECOMMANDEES", 
                            fontsize=14, fontname="hebo", color=self.base_color)
            y_pos += 30
            
            for rule in recommendations['priority_rules'][:3]:
                if y_pos > self.max_y - 60:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                page.draw_rect(fitz.Rect(63, y_pos, 565, y_pos + 5), color=self.base_color, fill=self.base_color)
                y_pos += 18
                
                page.insert_text((63, y_pos), f"Regle {rule.order}: {self._strip_html(rule.title)}", 
                                fontsize=11, fontname="hebo")
                y_pos += 20
                
                desc = self._strip_html(rule.description)[:150] + ('...' if len(rule.description) > 150 else '')
                desc_lines = self._wrap_text(desc, 75)
                for line in desc_lines[:3]:
                    page.insert_text((63, y_pos), line, fontsize=9, color=(0.3, 0.3, 0.3))
                    y_pos += 13
                
                y_pos += 15
        
        if recommendations and recommendations.get('weak_areas'):
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.insert_text((30, y_pos), "POINTS D'ATTENTION", 
                            fontsize=14, fontname="hebo", color=self.base_color)
            y_pos += 30
            
            for area in recommendations['weak_areas'][:5]:
                if y_pos > self.max_y - 50:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                question = self._strip_html(area['question'])[:80]
                page.insert_text((80, y_pos), f"• {question}", fontsize=9, fontname="hebo", color=self.warning_color)
                y_pos += 16
                
                desc = self._strip_html(area['description'])[:100]
                desc_lines = self._wrap_text(desc, 65)
                for line in desc_lines[:2]:
                    page.insert_text((80, y_pos), line, fontsize=8, color=(0.4, 0.4, 0.4))
                    y_pos += 12
                
                y_pos += 10
        
        if quiz_result.hibp_summary:
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            y_pos += 5
            breach_count = quiz_result.hibp_summary.get('breach_count', 0)
            breach_color = self.danger_color if breach_count > 0 else self.success_color
            
            page.insert_text((30, y_pos), "ANALYSE DES FUITES DE DONNEES", 
                            fontsize=14, fontname="hebo", color=self.base_color)
            y_pos += 30
            
            page.insert_text((53, y_pos), f"Email: {quiz_result.email}", fontsize=10)
            y_pos += 16
            page.insert_text((53, y_pos), f"Fuites detectees: {breach_count}", 
                            fontsize=11, fontname="hebo", color=breach_color)
            y_pos += 25
            
            if breach_count > 0 and quiz_result.hibp_summary.get('breaches'):
                breaches = quiz_result.hibp_summary['breaches'][:10]
                for idx, breach in enumerate(breaches, 1):
                    if y_pos > self.max_y - 80:
                        page = doc.new_page(width=595, height=842)
                        y_pos = 90
                    
                    page.draw_rect(fitz.Rect(53, y_pos, 565, y_pos + 3), color=self.danger_color, fill=self.danger_color)
                    y_pos += 15
                    
                    page.insert_text((53, y_pos), f"{idx}. {breach.get('name', 'Inconnu')}", 
                                    fontsize=10, fontname="hebo", color=self.danger_color)
                    y_pos += 18
                    
                    if breach.get('date'):
                        page.insert_text((67, y_pos), f"Date: {breach.get('date')}", fontsize=9, color=(0.3, 0.3, 0.3))
                        y_pos += 14
                    
                    if breach.get('pwn_count'):
                        page.insert_text((67, y_pos), f"Comptes affectes: {breach.get('pwn_count'):,}", 
                                        fontsize=9, color=(0.3, 0.3, 0.3))
                        y_pos += 14
                    
                    if breach.get('data_classes'):
                        data_classes = ', '.join(breach.get('data_classes', [])[:8])
                        page.insert_text((67, y_pos), f"Donnees: {data_classes}", 
                                        fontsize=8, color=self.danger_color)
                        y_pos += 14
                    
                    y_pos += 12
        
        total_pages = len(doc)
        for page_num, page in enumerate(doc, 1):
            self._add_header_footer(page, page_num, total_pages, ip_address, 
                                  document_code=quiz_result.document_code,
                                  qr_url="https://cyberconfiance.com/quiz")
        
        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
    
    def _strip_html(self, text):
        """Supprime les balises HTML du texte"""
        if not text:
            return ""
        clean = re.sub(r'<[^>]+>', '', text)
        clean = re.sub(r'&quot;', '"', clean)
        clean = re.sub(r'&amp;', '&', clean)
        clean = re.sub(r'&lt;', '<', clean)
        clean = re.sub(r'&gt;', '>', clean)
        clean = re.sub(r'&nbsp;', ' ', clean)
        return clean.strip()
    
    def _wrap_text(self, text, width):
        """Divise le texte en lignes de largeur maximale"""
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            word_length = len(word) + 1
            if current_length + word_length <= width:
                current_line.append(word)
                current_length += word_length
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = word_length
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
    def generate_qrcode_analysis_report(self, analysis, ip_address):
        """
        Genere un rapport PDF pour l'analyse de QR code (Anti-Quishing)
        Format identique aux rapports breach et security
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        page.insert_text((30, y_pos), "RAPPORT D'ANALYSE QR CODE (ANTI-QUISHING)", 
                        fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        page.insert_text((30, y_pos), "Type de rapport: Analyse de securite des QR codes", 
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
        
        page.insert_text((40, y_pos), f"Nombre de redirections detectees: {analysis.redirect_count or 0}", 
                        fontsize=10, color=self.warning_color if (analysis.redirect_count or 0) > 0 else self.success_color)
        y_pos += 15
        
        js_status = "Oui" if analysis.js_redirects_detected else "Non"
        js_color = self.warning_color if analysis.js_redirects_detected else self.success_color
        page.insert_text((40, y_pos), f"Redirections JavaScript: {js_status}", fontsize=10, color=js_color)
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
        
        page.insert_text((30, y_pos), "URL EXTRAITE DU QR CODE", 
                        fontsize=14, fontname="helv", color=self.base_color)
        y_pos += 25
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 40), color=None, fill=(0.95, 0.95, 0.95))
        y_pos += 15
        url = analysis.extracted_url or 'Aucune URL extraite'
        url_display = url[:90] + ('...' if len(url) > 90 else '')
        page.insert_text((40, y_pos), url_display, fontsize=9, color=(0.2, 0.2, 0.2))
        y_pos += 40
        
        if analysis.final_url and analysis.final_url != analysis.extracted_url:
            page.insert_text((30, y_pos), "URL FINALE (APRES REDIRECTIONS)", 
                            fontsize=14, fontname="helv", color=self.warning_color)
            y_pos += 25
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 40), color=self.warning_color, fill=self.warning_color, fill_opacity=0.1)
            y_pos += 15
            final_display = analysis.final_url[:90] + ('...' if len(analysis.final_url) > 90 else '')
            page.insert_text((40, y_pos), final_display, fontsize=9, color=(0.2, 0.2, 0.2))
            y_pos += 40
        
        threat_details = analysis.threat_details or []
        if threat_details:
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.insert_text((30, y_pos), "PROBLEMES DE SECURITE DETECTES", 
                            fontsize=14, fontname="helv", color=self.danger_color)
            y_pos += 25
            
            for idx, issue in enumerate(threat_details[:15], 1):
                if y_pos > self.max_y - 60:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                severity = issue.get('severity', 'low')
                severity_color = self._get_risk_color(severity)
                
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 5), color=severity_color, fill=severity_color)
                y_pos += 18
                
                page.insert_text((40, y_pos), f"{idx}. [{severity.upper()}] {issue.get('message', '')[:70]}", 
                                fontsize=10, fontname="helv")
                y_pos += 20
        else:
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 60), 
                          color=self.success_color, fill=self.success_color, fill_opacity=0.1)
            y_pos += 25
            page.insert_text((40, y_pos), "Aucun probleme de securite majeur detecte", 
                            fontsize=12, fontname="helv", color=self.success_color)
            y_pos += 20
            page.insert_text((40, y_pos), 
                            "Ce QR code semble sur selon notre analyse.", 
                            fontsize=10)
            y_pos += 35
        
        if analysis.blacklist_matches:
            if y_pos > self.max_y - 80:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.insert_text((30, y_pos), "VERIFICATION LISTE NOIRE", 
                            fontsize=14, fontname="helv", color=self.base_color)
            y_pos += 25
            
            bl = analysis.blacklist_matches
            if bl.get('is_blacklisted'):
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), 
                              color=self.danger_color, fill=self.danger_color, fill_opacity=0.1)
                y_pos += 20
                page.insert_text((40, y_pos), f"URL MALVEILLANTE - Detectee par {bl.get('malicious', 0)} source(s)", 
                               fontsize=11, fontname="helv", color=self.danger_color)
                y_pos += 50
            else:
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), 
                              color=self.success_color, fill=self.success_color, fill_opacity=0.1)
                y_pos += 20
                page.insert_text((40, y_pos), "URL non repertoriee dans les listes noires connues", 
                               fontsize=11, fontname="helv", color=self.success_color)
                y_pos += 50
        
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
                "Ne scannez pas ce QR code avec votre telephone personnel",
                "N'ouvrez pas cette URL directement dans votre navigateur",
                "Ne saisissez aucune information personnelle ou bancaire",
                "Signalez ce QR code aux autorites si trouve dans un lieu public",
                "Verifiez l'authenticite du QR code aupres de l'emetteur officiel"
            ]
        else:
            recommendations = [
                "Ce QR code semble sur, mais restez toujours vigilant",
                "Verifiez toujours l'URL avant de saisir des donnees sensibles",
                "Ne partagez pas d'informations personnelles sur des sites inconnus",
                "En cas de doute, contactez directement l'organisme concerne"
            ]
        
        for rec in recommendations:
            page.insert_text((40, y_pos), f"- {rec}", fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 16
        
        total_pages = len(doc)
        for page_num, p in enumerate(doc, 1):
            self._add_header_footer(p, page_num, total_pages, ip_address, 
                                   document_code=analysis.document_code,
                                   qr_url="https://cyberconfiance.com/outils/analyseur-qrcode")
        
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
        
        total_pages = len(doc)
        for page_num, p in enumerate(doc, 1):
            self._add_header_footer(p, page_num, total_pages, ip_address, 
                                   document_code=analysis.document_code,
                                   qr_url="https://cyberconfiance.com/outils/analyseur-prompt")
        
        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
