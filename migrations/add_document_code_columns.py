#!/usr/bin/env python3
"""
Migration: Add document_code column to BreachAnalysis, SecurityAnalysis, and QuizResult tables
"""
import sys
sys.path.insert(0, '/home/runner/workspace')

from __init__ import create_app, db

def run_migration():
    """Add document_code column to document tables"""
    app = create_app()
    
    with app.app_context():
        try:
            db.session.execute(db.text(
                "ALTER TABLE breach_analyses ADD COLUMN IF NOT EXISTS document_code VARCHAR(20) UNIQUE"
            ))
            db.session.execute(db.text(
                "CREATE INDEX IF NOT EXISTS ix_breach_analyses_document_code ON breach_analyses (document_code)"
            ))
            print("[OK] Added document_code to breach_analyses")
        except Exception as e:
            print(f"[INFO] breach_analyses column may already exist: {e}")
        
        try:
            db.session.execute(db.text(
                "ALTER TABLE security_analyses ADD COLUMN IF NOT EXISTS document_code VARCHAR(20) UNIQUE"
            ))
            db.session.execute(db.text(
                "CREATE INDEX IF NOT EXISTS ix_security_analyses_document_code ON security_analyses (document_code)"
            ))
            print("[OK] Added document_code to security_analyses")
        except Exception as e:
            print(f"[INFO] security_analyses column may already exist: {e}")
        
        try:
            db.session.execute(db.text(
                "ALTER TABLE quiz_results ADD COLUMN IF NOT EXISTS document_code VARCHAR(20) UNIQUE"
            ))
            db.session.execute(db.text(
                "CREATE INDEX IF NOT EXISTS ix_quiz_results_document_code ON quiz_results (document_code)"
            ))
            print("[OK] Added document_code to quiz_results")
        except Exception as e:
            print(f"[INFO] quiz_results column may already exist: {e}")
        
        db.session.commit()
        print("[OK] Migration completed successfully")

if __name__ == '__main__':
    run_migration()
