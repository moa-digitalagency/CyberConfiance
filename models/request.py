"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier request.py du projet CyberConfiance
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

Modele RequestSubmission pour les demandes de service utilisateur.
"""

from datetime import datetime
from models.base import db


class RequestSubmission(db.Model):
    __tablename__ = 'request_submissions'
    
    id = db.Column(db.Integer, primary_key=True)
    request_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    urls = db.Column(db.Text)
    crime_type = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    platform_identifier = db.Column(db.String(500))
    file_name = db.Column(db.String(500))
    file_path = db.Column(db.String(1000))
    file_size = db.Column(db.Integer)
    file_hash = db.Column(db.String(100))
    vt_file_results = db.Column(db.JSON)
    vt_url_results = db.Column(db.JSON)
    vt_text_results = db.Column(db.JSON)
    is_anonymous = db.Column(db.Boolean, default=False)
    contact_name = db.Column(db.String(200))
    contact_email = db.Column(db.String(200))
    contact_phone = db.Column(db.String(50))
    threat_detected = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')
    admin_notes = db.Column(db.Text)
    document_code = db.Column(db.String(20), unique=True, index=True)
    pdf_report = db.Column(db.LargeBinary)
    pdf_generated_at = db.Column(db.DateTime)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    consultation_type = db.Column(db.String(100))
    organization_size = db.Column(db.String(50))
    business_sector = db.Column(db.String(100))
    priority = db.Column(db.String(50))
    investigation_type = db.Column(db.String(100))
    context = db.Column(db.String(100))
    target_identifier = db.Column(db.String(500))
    timeline = db.Column(db.String(50))
    known_information = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<RequestSubmission {self.request_type} - {self.id}>'
