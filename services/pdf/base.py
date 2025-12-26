"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Classe de base pour la generation de rapports PDF.
"""

import fitz
import io
import os
import re
from datetime import datetime
from PIL import Image
from utils.document_code_generator import generate_qr_code


class PDFReportBase:
    """Base class for PDF report generation with common utilities and constants"""
    
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
            'critical': self.danger_color,
            'critique': self.danger_color,
            'danger': self.danger_color,
            'high': (251/255, 146/255, 60/255),
            'élevé': (251/255, 146/255, 60/255),
            'warning': (251/255, 146/255, 60/255),
            'medium': (234/255, 179/255, 8/255),
            'moyen': (234/255, 179/255, 8/255),
            'modéré': (234/255, 179/255, 8/255),
            'low': self.success_color,
            'faible': self.success_color,
            'safe': self.success_color,
            'sûr': self.success_color
        }
        return risk_colors.get(risk_level.lower(), self.base_color)
    
    def _insert_wrapped_url(self, page, doc, url, x_pos, y_pos, fontsize=8, color=None, max_width=500):
        """Insert a URL with automatic line wrapping to display complete URLs without truncation.
        
        Returns:
            tuple: (page, y_pos) - returns possibly new page object and updated y position
        """
        if color is None:
            color = (0.3, 0.3, 0.3)
        
        chars_per_line = int(max_width / (fontsize * 0.5))
        
        if len(url) <= chars_per_line:
            page.insert_text((x_pos, y_pos), url, fontsize=fontsize, color=color)
            return page, y_pos + fontsize + 4
        
        lines = []
        for i in range(0, len(url), chars_per_line):
            lines.append(url[i:i + chars_per_line])
        
        for line in lines:
            if y_pos > self.max_y - 20:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            page.insert_text((x_pos, y_pos), line, fontsize=fontsize, color=color)
            y_pos += fontsize + 3
        
        return page, y_pos
    
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
