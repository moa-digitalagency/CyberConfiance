"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Mixin pour la generation de rapports PDF de resultats quiz.
"""

import fitz


class QuizReportMixin:
    """Mixin for quiz results PDF report generation"""
    
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
