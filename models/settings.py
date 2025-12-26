"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Modeles de configuration: SiteSettings et SEOMetadata.
"""

from datetime import datetime
from models.base import db


class SiteSettings(db.Model):
    __tablename__ = 'site_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
    is_public = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    updater = db.relationship('User', backref='settings_updates')
    
    def __repr__(self):
        return f'<SiteSettings {self.key}>'


class SEOMetadata(db.Model):
    __tablename__ = 'seo_metadata'
    
    id = db.Column(db.Integer, primary_key=True)
    page_path = db.Column(db.String(200), unique=True, nullable=False)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    keywords = db.Column(db.Text)
    og_title = db.Column(db.String(200))
    og_description = db.Column(db.Text)
    og_image = db.Column(db.String(500))
    canonical_url = db.Column(db.String(500))
    robots = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    updater = db.relationship('User', backref='seo_updates')
    
    def __repr__(self):
        return f'<SEOMetadata {self.page_path}>'
