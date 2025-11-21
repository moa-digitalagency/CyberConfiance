#!/usr/bin/env python3
"""
Database initialization and seeding script
Runs migrations and seeds data from JSON files

Usage:
    python init_db.py           # Full initialization
    python init_db.py --reset   # Drop all tables and reinitialize (DANGER!)
    python init_db.py --check   # Verify all models are loaded
"""

import os
import sys
from __init__ import create_app, db
from utils.seed_data import seed_all_data

def verify_models_loaded():
    """Verify all required models are imported and registered"""
    print("\n[VERIFICATION] Checking all models are loaded...")
    
    from models import (
        User, Rule, Scenario, GlossaryTerm, Tool, News, 
        RequestSubmission, Contact, QuizResult, BreachAnalysis,
        SecurityAnalysis, AttackType, Newsletter, ActivityLog,
        ThreatLog, SiteSettings, SEOMetadata
    )
    
    required_tables = [
        'users', 'rules', 'scenarios', 'glossary', 'tools', 'news',
        'request_submissions', 'contacts', 'quiz_results', 'breach_analyses',
        'security_analyses', 'attack_types', 'newsletter', 'activity_logs',
        'threat_logs', 'site_settings', 'seo_metadata'
    ]
    
    registered_tables = [table.name for table in db.metadata.sorted_tables]
    
    print(f"✓ Found {len(registered_tables)} registered tables")
    
    missing_tables = set(required_tables) - set(registered_tables)
    if missing_tables:
        print(f"⚠️  WARNING: Missing tables: {', '.join(missing_tables)}")
        print("   This may cause errors during database creation")
        return False
    
    print("✓ All required models are loaded and registered")
    return True

def verify_table_columns():
    """Verify all critical tables have required columns"""
    print("\n[VERIFICATION] Checking table columns...")
    
    from sqlalchemy import inspect
    
    inspector = inspect(db.engine)
    
    # Define required columns for critical tables
    required_columns = {
        'breach_analyses': ['id', 'email', 'breach_count', 'pdf_report', 'pdf_generated_at', 'ip_address'],
        'security_analyses': ['id', 'input_value', 'input_type', 'pdf_report', 'pdf_generated_at', 'breach_analysis_id'],
        'quiz_results': ['id', 'email', 'overall_score', 'pdf_report', 'pdf_generated_at', 'document_code'],
    }
    
    all_valid = True
    
    for table_name, expected_cols in required_columns.items():
        if table_name not in inspector.get_table_names():
            print(f"✗ Table missing: {table_name}")
            all_valid = False
            continue
        
        actual_cols = {col['name'] for col in inspector.get_columns(table_name)}
        missing_cols = set(expected_cols) - actual_cols
        
        if missing_cols:
            print(f"✗ {table_name}: Missing columns: {', '.join(missing_cols)}")
            all_valid = False
        else:
            print(f"✓ {table_name}: All required columns present")
            # Show column details
            for col in inspector.get_columns(table_name):
                if col['name'] in ['id', 'pdf_report', 'pdf_generated_at']:
                    print(f"    - {col['name']:25} {str(col['type']):20}")
    
    if all_valid:
        print("\n✓ All critical table columns verified!")
    else:
        print("\n⚠️  Some columns are missing - this may cause issues")
    
    return all_valid

def init_database(reset=False):
    """Initialize database and seed data
    
    Args:
        reset: If True, drop all tables before recreating (DANGER!)
    """
    print("=" * 80)
    print("DATABASE INITIALIZATION")
    print("=" * 80)
    
    app = create_app()
    
    with app.app_context():
        try:
            if reset:
                print("\n⚠️  WARNING: Resetting database - ALL DATA WILL BE LOST!")
                confirmation = input("Type 'YES' to confirm: ")
                if confirmation != 'YES':
                    print("✗ Reset cancelled")
                    return False
                
                print("\n[RESET] Dropping all tables...")
                db.drop_all()
                print("✓ All tables dropped")
            
            # Verify all models are loaded
            models_ok = verify_models_loaded()
            if not models_ok:
                print("\n⚠️  Some models may be missing - continuing anyway...")
            
            # Create all tables
            print("\n[1/3] Creating database tables...")
            db.create_all()
            
            # Verify all columns are created
            columns_ok = verify_table_columns()
            if not columns_ok:
                print("\n⚠️  Some columns may be missing - please check model definitions")
            
            created_tables = [table.name for table in db.metadata.sorted_tables]
            print(f"✓ Database tables created successfully ({len(created_tables)} tables)")
            print(f"   Tables: {', '.join(created_tables)}")
            
            # Initialize sample data (users, basic content)
            print("\n[2/3] Initializing sample data...")
            from __init__ import initialize_data
            initialize_data()
            print("✓ Sample data initialized")
            
            # Seed all data from JSON files
            print("\n[3/3] Seeding database with content...")
            seed_all_data(db)
            print("✓ Database seeding completed")
            
            print("\n" + "=" * 80)
            print("✓ DATABASE INITIALIZATION COMPLETED SUCCESSFULLY")
            print("=" * 80)
            
            # Display admin credentials if in development
            if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't'):
                print("\n📝 Admin Credentials (Development):")
                print("   Username: admin")
                print("   Password: admin123" if not os.environ.get('ADMIN_PASSWORD') else "   Password: [from ADMIN_PASSWORD env var]")
                print("\n⚠️  Remember to set ADMIN_PASSWORD in production!")
                print("=" * 80)
            
            return True
            
        except Exception as e:
            print(f"\n✗ ERROR during database initialization: {e}")
            print("=" * 80)
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    reset_mode = '--reset' in sys.argv or '-r' in sys.argv
    success = init_database(reset=reset_mode)
    sys.exit(0 if success else 1)
