#!/usr/bin/env python3
"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Migration: Ajout champs consultation et investigation OSINT a RequestSubmission.
"""

import sys
sys.path.insert(0, '/home/runner/workspace')

from __init__ import create_app, db

def run_migration():
    """Add consultation_type, organization_size, business_sector, priority, investigation_type, context, target_identifier, timeline, and known_information columns"""
    app = create_app()
    
    with app.app_context():
        # Using ALTER TABLE to add new columns safely
        migrations = [
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS consultation_type VARCHAR(100);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS organization_size VARCHAR(50);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS business_sector VARCHAR(100);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS priority VARCHAR(50);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS investigation_type VARCHAR(100);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS context VARCHAR(100);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS target_identifier VARCHAR(500);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS timeline VARCHAR(50);",
            "ALTER TABLE request_submissions ADD COLUMN IF NOT EXISTS known_information TEXT;",
        ]
        
        for migration_sql in migrations:
            try:
                db.session.execute(db.text(migration_sql))
                print(f"[OK] Executed: {migration_sql}")
            except Exception as e:
                print(f"[ERROR] Failed: {migration_sql}")
                print(f"        Error: {str(e)}")
                db.session.rollback()
                return False
        
        db.session.commit()
        print("\n[OK] Migration completed successfully!")
        print("    - Added 9 new columns for consultation and OSINT investigation data")
        return True

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)
