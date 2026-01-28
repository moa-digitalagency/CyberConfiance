"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier metadata_report.py du projet CyberConfiance
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

Mixin pour la generation de rapports PDF d'analyse de metadonnees.
"""

import fitz


class MetadataReportMixin:
    """Mixin for metadata analysis PDF report generation"""
    
    def generate_metadata_analysis_report(self, analysis, ip_address, report_type='complete'):
        """
        Genere un rapport PDF pour l'analyse de metadonnees
        Format identique aux autres rapports forensiques
        
        Args:
            analysis: MetadataAnalysis object
            ip_address: IP address of the requester
            report_type: 'summary' pour rapport resume, 'complete' pour rapport complet
        """
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        
        y_pos = 90
        
        if report_type == 'summary':
            page.insert_text((30, y_pos), "RAPPORT RESUME - ANALYSE DE METADONNEES", 
                            fontsize=18, fontname="helv", color=self.base_color)
        else:
            page.insert_text((30, y_pos), "RAPPORT COMPLET - ANALYSE DE METADONNEES", 
                            fontsize=18, fontname="helv", color=self.base_color)
        y_pos += 30
        
        report_type_label = "Rapport resume" if report_type == 'summary' else "Rapport complet forensique"
        page.insert_text((30, y_pos), f"Type de rapport: {report_type_label}", 
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
        
        if analysis.has_gps_data and analysis.gps_data:
            gps_lines = []
            for key, value in analysis.gps_data.items():
                key_lower = key.lower()
                if 'latitude' in key_lower and 'ref' not in key_lower:
                    gps_lines.append(f"Latitude: {value}")
                elif 'longitude' in key_lower and 'ref' not in key_lower:
                    gps_lines.append(f"Longitude: {value}")
                elif 'altitude' in key_lower:
                    gps_lines.append(f"Altitude: {value}")
            
            box_height = 50 + (len(gps_lines) * 15)
            if y_pos > self.max_y - box_height - 20:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + box_height), color=self.danger_color, fill=self.danger_color, fill_opacity=0.1)
            y_pos += 15
            page.insert_text((40, y_pos), "LOCALISATION GPS", fontsize=12, fontname="helv", color=self.danger_color)
            y_pos += 20
            for line in gps_lines:
                page.insert_text((50, y_pos), line, fontsize=10, color=(0.3, 0.3, 0.3))
                y_pos += 15
            y_pos += 15
        
        if analysis.has_camera_info and analysis.camera_info:
            camera_lines = []
            for key, value in analysis.camera_info.items():
                key_lower = key.lower()
                if key == 'Marque' or key == 'Make' or 'marque' in key_lower:
                    camera_lines.append(f"Marque: {value}")
                elif key == 'Modele' or key == 'Model' or 'modele' in key_lower or 'model' in key_lower:
                    camera_lines.append(f"Modele: {value}")
                elif 'serie' in key_lower or 'serial' in key_lower:
                    camera_lines.append(f"N Serie: {value}")
                elif 'objectif' in key_lower or 'lens' in key_lower:
                    camera_lines.append(f"Objectif: {value}")
            
            box_height = 50 + (len(camera_lines) * 15)
            if y_pos > self.max_y - box_height - 20:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + box_height), color=self.warning_color, fill=self.warning_color, fill_opacity=0.1)
            y_pos += 15
            page.insert_text((40, y_pos), "APPAREIL", fontsize=12, fontname="helv", color=self.warning_color)
            y_pos += 20
            for line in camera_lines:
                page.insert_text((50, y_pos), line, fontsize=10, color=(0.3, 0.3, 0.3))
                y_pos += 15
            y_pos += 15
        
        if analysis.has_datetime_info and analysis.datetime_info:
            date_lines = []
            creation_found = False
            modif_found = False
            for key, value in analysis.datetime_info.items():
                key_lower = key.lower()
                if not creation_found and ('original' in key_lower or 'prise' in key_lower or 'create' in key_lower):
                    date_lines.append(f"Creation: {value}")
                    creation_found = True
                elif not modif_found and ('modif' in key_lower or 'modify' in key_lower):
                    date_lines.append(f"Modification: {value}")
                    modif_found = True
            
            if date_lines:
                box_height = 50 + (len(date_lines) * 15)
                if y_pos > self.max_y - box_height - 20:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + box_height), color=self.base_color, fill=self.base_color, fill_opacity=0.1)
                y_pos += 15
                page.insert_text((40, y_pos), "DATES", fontsize=12, fontname="helv", color=self.base_color)
                y_pos += 20
                for line in date_lines:
                    page.insert_text((50, y_pos), line, fontsize=10, color=(0.3, 0.3, 0.3))
                    y_pos += 15
                y_pos += 15
        
        if analysis.has_author_info and analysis.author_info:
            author_lines = []
            for key, value in analysis.author_info.items():
                key_lower = key.lower()
                if 'artiste' in key_lower or 'artist' in key_lower:
                    author_lines.append(f"Artiste: {value}")
                elif 'auteur' in key_lower or 'author' in key_lower:
                    author_lines.append(f"Auteur: {value}")
                elif 'createur' in key_lower or 'creator' in key_lower:
                    author_lines.append(f"Createur: {value}")
                elif 'copyright' in key_lower or 'droits' in key_lower:
                    author_lines.append(f"Copyright: {value}")
            
            if author_lines:
                box_height = 50 + (len(author_lines) * 15)
                if y_pos > self.max_y - box_height - 20:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + box_height), color=self.warning_color, fill=self.warning_color, fill_opacity=0.1)
                y_pos += 15
                page.insert_text((40, y_pos), "AUTEUR", fontsize=12, fontname="helv", color=self.warning_color)
                y_pos += 20
                for line in author_lines:
                    page.insert_text((50, y_pos), line, fontsize=10, color=(0.3, 0.3, 0.3))
                    y_pos += 15
                y_pos += 15
        
        if analysis.has_software_info and analysis.software_info:
            software_lines = []
            for key, value in analysis.software_info.items():
                key_lower = key.lower()
                if 'logiciel' in key_lower or 'software' in key_lower:
                    software_lines.append(f"Logiciel: {value}")
                elif 'outil' in key_lower or 'tool' in key_lower:
                    software_lines.append(f"Outil: {value}")
                elif 'program' in key_lower or 'application' in key_lower:
                    software_lines.append(f"Application: {value}")
            
            if software_lines:
                box_height = 50 + (len(software_lines) * 15)
                if y_pos > self.max_y - box_height - 20:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + box_height), color=self.base_color, fill=self.base_color, fill_opacity=0.1)
                y_pos += 15
                page.insert_text((40, y_pos), "LOGICIELS", fontsize=12, fontname="helv", color=self.base_color)
                y_pos += 20
                for line in software_lines:
                    page.insert_text((50, y_pos), line, fontsize=10, color=(0.3, 0.3, 0.3))
                    y_pos += 15
                y_pos += 15
        
        if report_type == 'complete':
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
