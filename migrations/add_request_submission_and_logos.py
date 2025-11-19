#!/usr/bin/env python3
"""
Migration: Add RequestSubmission table and logo settings
"""

from __init__ import create_app, db
from models import SiteSettings, RequestSubmission

def run_migration():
    """Add new table and settings"""
    app = create_app()
    
    with app.app_context():
        db.create_all()
        print("[OK] RequestSubmission table created")
        
        logo_light = SiteSettings.query.filter_by(key='logo_light').first()
        if not logo_light:
            logo_light = SiteSettings(
                key='logo_light',
                value='/static/img/logo.png',
                value_type='string',
                description='Logo for light theme',
                category='branding',
                is_public=True
            )
            db.session.add(logo_light)
        
        logo_dark = SiteSettings.query.filter_by(key='logo_dark').first()
        if not logo_dark:
            logo_dark = SiteSettings(
                key='logo_dark',
                value='/static/img/logo.png',
                value_type='string',
                description='Logo for dark theme',
                category='branding',
                is_public=True
            )
            db.session.add(logo_dark)
        
        db.session.commit()
        print("[OK] Logo settings added")
        print("[OK] Migration completed successfully")

if __name__ == '__main__':
    run_migration()
