#!/usr/bin/env python3
"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Migration: Ajout colonnes document_code, pdf_report, pdf_generated_at a RequestSubmission.
"""

import sys
sys.path.insert(0, '/home/runner/workspace')

from __init__ import create_app, db

def run_migration():
    """Add document_code and PDF columns to request_submissions table"""
    app = create_app()
    
    with app.app_context():
        try:
            db.session.execute(db.text(
                "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS document_code VARCHAR(20) UNIQUE"
            ))
            db.session.execute(db.text(
                "CREATE INDEX IF NOT EXISTS ix_request_submissions_document_code ON request_submissions (document_code)"
            ))
            print("[OK] Added document_code to request_submissions")
        except Exception as e:
            print(f"[INFO] document_code column may already exist: {e}")
        
        try:
            db.session.execute(db.text(
                "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS pdf_report BYTEA"
            ))
            print("[OK] Added pdf_report to request_submissions")
        except Exception as e:
            print(f"[INFO] pdf_report column may already exist: {e}")
        
        try:
            db.session.execute(db.text(
                "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"
            ))
            print("[OK] Added pdf_generated_at to request_submissions")
        except Exception as e:
            print(f"[INFO] pdf_generated_at column may already exist: {e}")
        
        db.session.commit()
        print("[OK] Migration completed successfully")

if __name__ == '__main__':
    run_migration()
