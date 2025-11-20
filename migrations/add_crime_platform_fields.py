#!/usr/bin/env python3
"""
Migration: Add crime_type, platform, and platform_identifier columns to request_submissions table
"""
import sys
sys.path.insert(0, '/home/runner/workspace')

from __init__ import create_app, db

def run_migration():
    """Add crime_type, platform, and platform_identifier columns to request_submissions table"""
    app = create_app()
    
    with app.app_context():
        try:
            db.session.execute(db.text(
                "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS crime_type VARCHAR(100)"
            ))
            print("[OK] Added crime_type to request_submissions")
        except Exception as e:
            print(f"[INFO] crime_type column may already exist: {e}")
        
        try:
            db.session.execute(db.text(
                "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS platform VARCHAR(100)"
            ))
            print("[OK] Added platform to request_submissions")
        except Exception as e:
            print(f"[INFO] platform column may already exist: {e}")
        
        try:
            db.session.execute(db.text(
                "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS platform_identifier VARCHAR(500)"
            ))
            print("[OK] Added platform_identifier to request_submissions")
        except Exception as e:
            print(f"[INFO] platform_identifier column may already exist: {e}")
        
        db.session.commit()
        print("[OK] Migration completed successfully")

if __name__ == '__main__':
    run_migration()
