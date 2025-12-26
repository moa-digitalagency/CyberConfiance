"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Mixin pour la generation de rapports PDF de fuite de donnees.
"""

import fitz


class BreachReportMixin:
    """Mixin for breach analysis PDF report generation"""
    
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
