"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier qrcode_report.py du projet CyberConfiance
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

Mixin pour la generation de rapports PDF d'analyse QR code.
"""

import fitz


class QRCodeReportMixin:
    """Mixin for QR code analysis PDF report generation"""
    
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
        
        redirect_chain = analysis.redirect_chain or []
        if redirect_chain and len(redirect_chain) > 0:
            if y_pos > self.max_y - 150:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_line((30, y_pos), (565, y_pos), color=self.warning_color, width=1)
            y_pos += 20
            
            redirect_count = analysis.redirect_count or len(redirect_chain)
            page.insert_text((30, y_pos), f"CHAINE DE REDIRECTION COMPLETE ({redirect_count} redirection{'s' if redirect_count > 1 else ''})", 
                            fontsize=14, fontname="helv", color=self.warning_color)
            y_pos += 25
            
            for idx, redirect in enumerate(redirect_chain, 1):
                if y_pos > self.max_y - 60:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                status_code = redirect.get('status_code', '')
                redirect_type = redirect.get('redirect_type', '')
                is_shortener = redirect.get('is_shortener', False)
                js_redirect = redirect.get('js_redirect_detected', False)
                
                if js_redirect:
                    step_color = self.danger_color
                elif is_shortener:
                    step_color = self.warning_color
                else:
                    step_color = self.base_color
                
                step_info = f"Etape {idx}"
                if status_code:
                    step_info += f" | HTTP {status_code}"
                if redirect_type:
                    step_info += f" | {redirect_type}"
                if is_shortener:
                    step_info += " | [Raccourcisseur]"
                if js_redirect:
                    step_info += " | [JavaScript]"
                
                page.insert_text((50, y_pos), step_info, fontsize=8, fontname="helv", color=step_color)
                y_pos += 12
                
                url = redirect.get('url', '')
                page, y_pos = self._insert_wrapped_url(page, doc, url, 50, y_pos, fontsize=7)
                
                if redirect.get('error'):
                    page.insert_text((50, y_pos), f"Erreur: {redirect.get('error')}", fontsize=7, color=self.danger_color)
                    y_pos += 10
                
                y_pos += 6
            
            y_pos += 10
        
        analysis_results = analysis.analysis_results or {}
        multi_api_analysis = analysis_results.get('multi_api_analysis', {})
        
        source_results = multi_api_analysis.get('source_results', {})
        if source_results and not multi_api_analysis.get('error'):
            if y_pos > self.max_y - 150:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
            y_pos += 20
            
            page.insert_text((30, y_pos), "RESULTATS PAR SOURCE DE SECURITE", 
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
                    page.insert_text((50, y_pos), f"Malveillant: {vt_result.get('malicious', 0)} | Suspect: {vt_result.get('suspicious', 0)} | Sur: {vt_result.get('clean', 0)}", fontsize=9)
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
                    status_text = "Sur - Aucune menace detectee" if gsb_safe else "Menace detectee"
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
                    status_text = "Sur - Non repertorie" if urlhaus_safe else "URL malveillante detectee"
                    page.insert_text((50, y_pos), status_text, fontsize=9, color=urlhaus_color)
                    if not urlhaus_safe and urlhaus_result.get('threat_type'):
                        y_pos += 14
                        page.insert_text((50, y_pos), f"Type: {urlhaus_result.get('threat_type')}", fontsize=9, color=(0.5, 0.5, 0.5))
                y_pos += 25
            
            urlscan_result = source_results.get('urlscan', {})
            if urlscan_result:
                if y_pos > self.max_y - 70:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                urlscan_safe = not urlscan_result.get('malicious', False)
                urlscan_color = self.success_color if urlscan_safe else self.danger_color
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 50), color=urlscan_color, fill=urlscan_color, fill_opacity=0.05)
                y_pos += 15
                page.insert_text((40, y_pos), "URLScan.io", fontsize=12, fontname="helv", color=urlscan_color)
                y_pos += 18
                if urlscan_result.get('error'):
                    page.insert_text((50, y_pos), f"Erreur: {urlscan_result.get('error')}", fontsize=9, color=(0.5, 0.5, 0.5))
                else:
                    status_text = "Sur - Aucune menace detectee" if urlscan_safe else "Menace potentielle detectee"
                    page.insert_text((50, y_pos), status_text, fontsize=9, color=urlscan_color)
                    if urlscan_result.get('score'):
                        y_pos += 14
                        page.insert_text((50, y_pos), f"Score de risque: {urlscan_result.get('score')}/100", fontsize=9, color=(0.5, 0.5, 0.5))
                y_pos += 25
            
            y_pos += 10
        
        consolidated_summary = analysis_results.get('consolidated_summary', {})
        key_findings = consolidated_summary.get('key_findings', [])
        
        if key_findings:
            if y_pos > self.max_y - 100:
                page = doc.new_page(width=595, height=842)
                y_pos = 90
            
            page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
            y_pos += 20
            
            page.insert_text((30, y_pos), f"RESULTATS DE L'ANALYSE ({len(key_findings)} element{'s' if len(key_findings) > 1 else ''})", 
                            fontsize=14, fontname="helv", color=self.base_color)
            y_pos += 25
            
            for finding in key_findings:
                if y_pos > self.max_y - 60:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                
                severity = finding.get('severity', 'low')
                severity_color = self._get_risk_color(severity)
                title = finding.get('title', '')
                description = finding.get('description', '')
                
                page.draw_rect(fitz.Rect(30, y_pos, 565, y_pos + 35), 
                              color=severity_color, fill=severity_color, fill_opacity=0.08)
                page.draw_rect(fitz.Rect(30, y_pos, 34, y_pos + 35), 
                              color=severity_color, fill=severity_color)
                
                y_pos += 12
                page.insert_text((40, y_pos), f"[{severity.upper()}] {title}", 
                                fontsize=10, fontname="helv", color=severity_color)
                y_pos += 14
                if description:
                    desc_lines = self._wrap_text(description, 85)
                    for line in desc_lines[:2]:
                        page.insert_text((40, y_pos), line, fontsize=8, color=(0.4, 0.4, 0.4))
                        y_pos += 10
                y_pos += 12
        else:
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
                    
                    page.insert_text((40, y_pos), f"{idx}. [{severity.upper()}] {issue.get('message', '')[:70]}", 
                                    fontsize=10, fontname="helv", color=severity_color)
                    y_pos += 18
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
        
        if y_pos > self.max_y - 120:
            page = doc.new_page(width=595, height=842)
            y_pos = 90
        
        page.draw_line((30, y_pos), (565, y_pos), color=self.base_color, width=1)
        y_pos += 20
        
        summary_recommendations = consolidated_summary.get('recommendations', [])
        overall_verdict = consolidated_summary.get('overall_verdict', 'safe')
        
        if overall_verdict in ['critical', 'high']:
            rec_color = self.danger_color
            rec_title = "AVERTISSEMENT DE SECURITE"
        elif overall_verdict == 'medium':
            rec_color = self.warning_color
            rec_title = "POINTS D'ATTENTION"
        else:
            rec_color = self.success_color
            rec_title = "RECOMMANDATIONS"
        
        page.insert_text((30, y_pos), rec_title, 
                        fontsize=14, fontname="helv", color=rec_color)
        y_pos += 25
        
        if summary_recommendations:
            for rec in summary_recommendations:
                if y_pos > self.max_y - 30:
                    page = doc.new_page(width=595, height=842)
                    y_pos = 90
                page.insert_text((40, y_pos), f"- {rec}", fontsize=9, color=(0.3, 0.3, 0.3))
                y_pos += 16
        else:
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
