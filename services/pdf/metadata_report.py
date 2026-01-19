"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Mixin pour la generation de rapports PDF d'analyse de metadonnees.
"""

import fitz


class MetadataReportMixin:
    """Mixin for metadata analysis PDF report generation"""
    
    def generate_metadata_analysis_report(self, analysis, ip_address):
        """
        Genere un rapport PDF pour l'analyse de metadonnees
        Format identique aux autres rapports forensiques
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        page.insert_text((30, y_pos), "RAPPORT D'ANALYSE DE METADONNEES", 
                        fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        page.insert_text((30, y_pos), "Type de rapport: Analyse forensique des metadonnees", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        page.insert_text((30, y_pos), f"ID du rapport: #{analysis.id}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 40
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 90), color=None, fill=(0.95, 0.95, 0.95))
        y_pos += 15
        
        page.insert_text((40, y_pos), "INFORMATIONS DU FICHIER", 
                        fontsize=12, fontname="helv")
        y_pos += 20
        
        page.insert_text((40, y_pos), f"Nom du fichier: {analysis.filename}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        
        file_type_labels = {'image': 'Image', 'video': 'Video', 'audio': 'Audio'}
        file_type_display = file_type_labels.get(analysis.file_type, analysis.file_type)
        page.insert_text((40, y_pos), f"Type de fichier: {file_type_display}", 
                        fontsize=10, color=(0.3, 0.3, 0.3))
        y_pos += 15
        
        if analysis.file_size:
            size_mb = analysis.file_size / (1024 * 1024)
            if size_mb >= 1:
                size_display = f"{size_mb:.2f} Mo"
            else:
                size_kb = analysis.file_size / 1024
                size_display = f"{size_kb:.2f} Ko"
            page.insert_text((40, y_pos), f"Taille du fichier: {size_display}", 
                            fontsize=10, color=(0.3, 0.3, 0.3))
            y_pos += 15
        
        page.insert_text((40, y_pos), f"Nombre de metadonnees detectees: {analysis.metadata_count or 0}", 
                        fontsize=10, color=self.base_color)
        y_pos += 35
        
        privacy_risk = analysis.privacy_risk or 'low'
        risk_color = self._get_risk_color(privacy_risk)
        
        page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), color=risk_color, fill=risk_color, fill_opacity=0.1)
        y_pos += 15
        page.insert_text((40, y_pos), "NIVEAU DE RISQUE VIE PRIVEE", fontsize=12, fontname="helv")
        y_pos += 20
        
        risk_labels = {
            'low': 'FAIBLE',
            'medium': 'MODERE',
            'high': 'ELEVE',
            'critical': 'CRITIQUE'
        }
        risk_text = risk_labels.get(privacy_risk, privacy_risk.upper())
        page.insert_text((40, y_pos), risk_text, fontsize=14, fontname="helv", color=risk_color)
        y_pos += 40
        
        if analysis.has_gps_data:
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 60), color=self.danger_color, fill=self.danger_color, fill_opacity=0.1)
            y_pos += 15
            page.insert_text((40, y_pos), "DONNEES GPS DETECTEES", fontsize=12, fontname="helv", color=self.danger_color)
            y_pos += 20
            page.insert_text((40, y_pos), "Ce fichier contient des coordonnees GPS qui peuvent reveler votre localisation exacte.", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 15
            page.insert_text((40, y_pos), "Recommendation: Utilisez la version nettoyee avant de partager ce fichier.", 
                            fontsize=9, color=self.warning_color)
            y_pos += 35
        
        if analysis.has_camera_info:
            if y_pos > self.max_y - 80:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 45), color=self.warning_color, fill=self.warning_color, fill_opacity=0.1)
            y_pos += 15
            page.insert_text((40, y_pos), "INFORMATIONS APPAREIL DETECTEES", fontsize=12, fontname="helv", color=self.warning_color)
            y_pos += 20
            page.insert_text((40, y_pos), "Ce fichier contient des informations sur l'appareil utilise (marque, modele, numero de serie).", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 35
        
        if analysis.has_author_info:
            if y_pos > self.max_y - 80:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 45), color=self.warning_color, fill=self.warning_color, fill_opacity=0.1)
            y_pos += 15
            page.insert_text((40, y_pos), "INFORMATIONS AUTEUR/COPYRIGHT DETECTEES", fontsize=12, fontname="helv", color=self.warning_color)
            y_pos += 20
            page.insert_text((40, y_pos), "Ce fichier contient des informations sur l'auteur ou les droits d'auteur.", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 35
        
        if analysis.has_datetime_info:
            if y_pos > self.max_y - 80:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 45), color=self.base_color, fill=self.base_color, fill_opacity=0.1)
            y_pos += 15
            page.insert_text((40, y_pos), "INFORMATIONS DATE/HEURE DETECTEES", fontsize=12, fontname="helv", color=self.base_color)
            y_pos += 20
            page.insert_text((40, y_pos), "Ce fichier contient des dates et heures de creation ou modification.", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 35
        
        if analysis.has_software_info:
            if y_pos > self.max_y - 80:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 45), color=self.base_color, fill=self.base_color, fill_opacity=0.1)
            y_pos += 15
            page.insert_text((40, y_pos), "INFORMATIONS LOGICIEL DETECTEES", fontsize=12, fontname="helv", color=self.base_color)
            y_pos += 20
            page.insert_text((40, y_pos), "Ce fichier contient des informations sur les logiciels utilises pour le creer ou le modifier.", 
                            fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 35
        
        analysis_results = analysis.analysis_results or {}
        metadata = analysis_results.get('metadata', {})
        categories = analysis_results.get('categories', {})
        
        if categories:
            for category_name, category_data in categories.items():
                if not category_data:
                    continue
                
                needed_height = 60 + (len(category_data) * 18)
                if y_pos > self.max_y - min(needed_height, 200):
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
                y_pos += 20
                
                page.insert_text((30, y_pos), category_name.upper(), 
                                fontsize=12, fontname="helv", color=self.base_color)
                y_pos += 20
                
                items_on_page = 0
                for key, value in category_data.items():
                    if y_pos > self.max_y - 30:
                        page = doc.new_page(width=595, height=842)
                        y_pos = 90
                        items_on_page = 0
                    
                    display_key = key.replace('ExifTool_', '').replace('PIL_', '').replace('FFprobe_', '').replace('Audio_', '').replace('Mutagen_', '')
                    
                    str_value = str(value)
                    if len(str_value) > 80:
                        str_value = str_value[:77] + "..."
                    
                    page.insert_text((40, y_pos), f"{display_key}:", fontsize=9, fontname="helv", color=(0.3, 0.3, 0.3))
                    page.insert_text((200, y_pos), str_value, fontsize=9, color=(0.2, 0.2, 0.2))
                    y_pos += 15
                    items_on_page += 1
                    
                    if items_on_page >= 30:
                        break
                
                y_pos += 10
        
        if y_pos > self.max_y - 120:
            page = doc.new_page(width=595, height=842)
            y_pos = 90
        
        page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
        y_pos += 20
        
        page.insert_text((30, y_pos), "RECOMMANDATIONS", 
                        fontsize=12, fontname="helv", color=self.base_color)
        y_pos += 25
        
        recommendations = []
        if analysis.has_gps_data:
            recommendations.append("Supprimez les donnees GPS avant de partager des photos en ligne")
        if analysis.has_camera_info:
            recommendations.append("Les informations d'appareil peuvent servir a vous identifier")
        if analysis.has_author_info:
            recommendations.append("Verifiez que les informations d'auteur sont appropriees avant partage")
        if analysis.has_datetime_info:
            recommendations.append("Les dates peuvent reveler vos habitudes et routines")
        
        if not recommendations:
            recommendations.append("Aucune metadonnee sensible majeure detectee")
            recommendations.append("Restez vigilant lors du partage de fichiers multimedia")
        
        for rec in recommendations:
            if y_pos > self.max_y - 20:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            page.insert_text((40, y_pos), f"• {rec}", fontsize=9, color=(0.3, 0.3, 0.3))
            y_pos += 15
        
        total_pages = len(doc)
        document_code = analysis.document_code if analysis.document_code else f"META-{analysis.id}"
        qr_url = "https://cyberconfiance.com/outils/analyseur-metadonnee"
        
        for page_num, p in enumerate(doc, 1):
            self._add_header_footer(p, page_num, total_pages, ip_address, 
                                   document_code=document_code,
                                   qr_url=qr_url)
        
        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
