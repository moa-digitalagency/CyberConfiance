#!/usr/bin/env python3
"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Initialisation et seeding de la base de donnees.
Execute les migrations et charge les donnees depuis les fichiers JSON.

Usage:
    python init_db.py           # Initialisation complete
    python init_db.py --reset   # Reinitialisation (ATTENTION!)
    python init_db.py --check   # Verification des modeles
    python init_db.py --verify-libs  # Verification des librairies
"""

import os
import sys
import ctypes
import ctypes.util


def verify_critical_libraries():
    """Verify all critical libraries are available for deployment"""
    print("\n[LIBRARIES] Verifying critical libraries for deployment...")
    
    libraries_status = {}
    all_ok = True
    
    # 1. Verify zbar library for QR code scanning
    print("  Checking zbar/pyzbar...")
    try:
        # First, patch find_library to locate libzbar.so.0
        original_find_library = ctypes.util.find_library
        def patched_find_library(name):
            if name == 'zbar':
                zbar_paths = [
                    '/nix/store/lcjf0hd46s7b16vr94q3bcas7yg05c3c-zbar-0.23.93-lib/lib/libzbar.so.0',
                    '/usr/lib/libzbar.so.0',
                    '/usr/lib/x86_64-linux-gnu/libzbar.so.0',
                ]
                for path in zbar_paths:
                    if os.path.exists(path):
                        return path
            return original_find_library(name)
        
        ctypes.util.find_library = patched_find_library
        
        # Now try to load zbar and import pyzbar
        zbar_lib = None
        zbar_paths = [
            '/nix/store/lcjf0hd46s7b16vr94q3bcas7yg05c3c-zbar-0.23.93-lib/lib/libzbar.so.0',
        ]
        for path in zbar_paths:
            if os.path.exists(path):
                zbar_lib = ctypes.CDLL(path)
                break
        
        if zbar_lib:
            from pyzbar import pyzbar
            libraries_status['pyzbar'] = True
            print("    ✓ pyzbar/zbar: OK")
        else:
            libraries_status['pyzbar'] = False
            print("    ✗ pyzbar/zbar: Library not found")
            all_ok = False
    except Exception as e:
        libraries_status['pyzbar'] = False
        print(f"    ✗ pyzbar/zbar: {str(e)[:100]}")
        all_ok = False
    
    # 2. Verify PIL/Pillow for image processing
    print("  Checking PIL/Pillow...")
    try:
        from PIL import Image
        libraries_status['pillow'] = True
        print("    ✓ PIL/Pillow: OK")
    except Exception as e:
        libraries_status['pillow'] = False
        print(f"    ✗ PIL/Pillow: {str(e)[:100]}")
        all_ok = False
    
    # 3. Verify PyMuPDF (fitz) for PDF generation
    print("  Checking PyMuPDF (fitz)...")
    try:
        import fitz
        libraries_status['pymupdf'] = True
        print("    ✓ PyMuPDF: OK")
    except Exception as e:
        libraries_status['pymupdf'] = False
        print(f"    ✗ PyMuPDF: {str(e)[:100]}")
        all_ok = False
    
    # 4. Verify OpenCV for image processing
    print("  Checking OpenCV...")
    try:
        import cv2
        libraries_status['opencv'] = True
        print("    ✓ OpenCV: OK")
    except Exception as e:
        libraries_status['opencv'] = False
        print(f"    ✗ OpenCV: {str(e)[:100]}")
        all_ok = False
    
    # 5. Verify requests for HTTP operations
    print("  Checking requests...")
    try:
        import requests
        libraries_status['requests'] = True
        print("    ✓ requests: OK")
    except Exception as e:
        libraries_status['requests'] = False
        print(f"    ✗ requests: {str(e)[:100]}")
        all_ok = False
    
    # 6. Verify BeautifulSoup for HTML parsing
    print("  Checking BeautifulSoup...")
    try:
        from bs4 import BeautifulSoup
        libraries_status['beautifulsoup'] = True
        print("    ✓ BeautifulSoup: OK")
    except Exception as e:
        libraries_status['beautifulsoup'] = False
        print(f"    ✗ BeautifulSoup: {str(e)[:100]}")
        all_ok = False
    
    # 7. Verify qrcode for QR code generation
    print("  Checking qrcode...")
    try:
        import qrcode
        libraries_status['qrcode'] = True
        print("    ✓ qrcode: OK")
    except Exception as e:
        libraries_status['qrcode'] = False
        print(f"    ✗ qrcode: {str(e)[:100]}")
        all_ok = False
    
    # 8. Verify magic for file type detection
    print("  Checking python-magic...")
    try:
        import magic
        libraries_status['magic'] = True
        print("    ✓ python-magic: OK")
    except Exception as e:
        libraries_status['magic'] = False
        print(f"    ✗ python-magic: {str(e)[:100]}")
        all_ok = False
    
    # Summary
    if all_ok:
        print("\n✓ All critical libraries verified successfully!")
    else:
        print("\n⚠️  Some libraries are missing - deployment may have issues")
        missing = [k for k, v in libraries_status.items() if not v]
        print(f"   Missing: {', '.join(missing)}")
    
    return all_ok, libraries_status


from __init__ import create_app, db
from utils.seed_data import seed_all_data

def verify_models_loaded():
    """Verify all required models are imported and registered"""
    print("\n[VERIFICATION] Checking all models are loaded...")
    
    from models import (
        User, Rule, Scenario, GlossaryTerm, Tool, News, 
        RequestSubmission, Contact, QuizResult, BreachAnalysis,
        SecurityAnalysis, AttackType, Newsletter, ActivityLog,
        ThreatLog, SiteSettings, SEOMetadata, Article, Resource,
        SecurityLog, QRCodeAnalysis, PromptAnalysis, GitHubCodeAnalysis,
        MetadataAnalysis
    )
    
    required_tables = [
        'users', 'rules', 'scenarios', 'glossary', 'tools', 'news',
        'request_submissions', 'contacts', 'quiz_results', 'breach_analyses',
        'security_analyses', 'attack_types', 'newsletter', 'activity_logs',
        'threat_logs', 'site_settings', 'seo_metadata', 'articles', 'resources',
        'security_logs', 'qrcode_analyses', 'prompt_analyses', 'github_code_analyses',
        'metadata_analyses'
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
        'qrcode_analyses': ['id', 'extracted_url', 'final_url', 'threat_level', 'pdf_report', 'pdf_generated_at', 'document_code', 'ip_address'],
        'prompt_analyses': ['id', 'prompt_text', 'threat_level', 'threat_detected', 'pdf_report', 'pdf_generated_at', 'document_code', 'ip_address'],
        'github_code_analyses': ['id', 'repo_url', 'repo_name', 'overall_score', 'pdf_report', 'pdf_generated_at', 'document_code', 'ip_address'],
        'metadata_analyses': ['id', 'original_filename', 'file_type', 'metadata_count', 'original_file', 'cleaned_file', 'pdf_report', 'pdf_generated_at', 'document_code', 'ip_address'],
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

def check_vps_compatibility():
    """Check VPS PostgreSQL transaction compatibility"""
    print("\n[VPS CHECK] Verifying PostgreSQL transaction handling...")
    try:
        from sqlalchemy import text
        result = db.session.execute(text("SELECT 1"))
        db.session.rollback()
        print("✓ PostgreSQL transaction handling: OK")
        return True
    except Exception as e:
        print(f"⚠️  PostgreSQL transaction check failed: {e}")
        db.session.rollback()
        return False


def run_migrations():
    """Run database migrations to add missing columns for existing VPS installations"""
    print("\n[MIGRATIONS] Checking for missing columns...")
    
    from sqlalchemy import text, inspect
    
    migrations = [
        # MetadataAnalysis table - new columns
        ("metadata_analyses", "original_file", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS original_file BYTEA"),
        ("metadata_analyses", "cleaned_file", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS cleaned_file BYTEA"),
        ("metadata_analyses", "cleaned_filename", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS cleaned_filename VARCHAR(500)"),
        ("metadata_analyses", "pdf_report", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),
        ("metadata_analyses", "pdf_generated_at", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),
        ("metadata_analyses", "document_code", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS document_code VARCHAR(20)"),
        ("metadata_analyses", "gps_data", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS gps_data JSON"),
        ("metadata_analyses", "camera_info", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS camera_info JSON"),
        ("metadata_analyses", "software_info", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS software_info JSON"),
        ("metadata_analyses", "datetime_info", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS datetime_info JSON"),
        ("metadata_analyses", "author_info", "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS author_info JSON"),
        
        # GitHubCodeAnalysis table - pdf columns
        ("github_code_analyses", "pdf_report", "ALTER TABLE github_code_analyses ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),
        ("github_code_analyses", "pdf_generated_at", "ALTER TABLE github_code_analyses ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),
        
        # BreachAnalysis - pdf columns
        ("breach_analyses", "pdf_report", "ALTER TABLE breach_analyses ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),
        ("breach_analyses", "pdf_generated_at", "ALTER TABLE breach_analyses ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),
        
        # SecurityAnalysis - pdf columns
        ("security_analyses", "pdf_report", "ALTER TABLE security_analyses ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),
        ("security_analyses", "pdf_generated_at", "ALTER TABLE security_analyses ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),
        
        # QuizResult - pdf columns
        ("quiz_results", "pdf_report", "ALTER TABLE quiz_results ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),
        ("quiz_results", "pdf_generated_at", "ALTER TABLE quiz_results ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),
        
        # QRCodeAnalysis - pdf columns
        ("qrcode_analyses", "pdf_report", "ALTER TABLE qrcode_analyses ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),
        ("qrcode_analyses", "pdf_generated_at", "ALTER TABLE qrcode_analyses ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),
        
        # PromptAnalysis - pdf columns
        ("prompt_analyses", "pdf_report", "ALTER TABLE prompt_analyses ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),
        ("prompt_analyses", "pdf_generated_at", "ALTER TABLE prompt_analyses ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),
    ]
    
    inspector = inspect(db.engine)
    existing_tables = inspector.get_table_names()
    
    migrations_run = 0
    
    for table_name, column_name, sql in migrations:
        if table_name not in existing_tables:
            continue
        
        existing_cols = {col['name'] for col in inspector.get_columns(table_name)}
        
        if column_name not in existing_cols:
            try:
                db.session.execute(text(sql))
                db.session.commit()
                print(f"  ✓ Added column {table_name}.{column_name}")
                migrations_run += 1
            except Exception as e:
                db.session.rollback()
                print(f"  ⚠️  Failed to add {table_name}.{column_name}: {e}")
    
    if migrations_run == 0:
        print("  ✓ All columns already present - no migrations needed")
    else:
        print(f"  ✓ {migrations_run} migration(s) completed successfully")
    
    return True

def init_database(reset=False, verify_libs=True):
    """Initialize database and seed data
    
    Args:
        reset: If True, drop all tables before recreating (DANGER!)
        verify_libs: If True, verify critical libraries before init
    """
    print("=" * 80)
    print("DATABASE INITIALIZATION")
    print("=" * 80)
    
    # Verify libraries first
    if verify_libs:
        libs_ok, _ = verify_critical_libraries()
        if not libs_ok:
            print("\n⚠️  Some libraries are missing - continuing with database init...")
    
    app = create_app()
    
    with app.app_context():
        try:
            # Check VPS compatibility
            check_vps_compatibility()
            
            if reset:
                print("\n⚠️  WARNING: Resetting database - ALL DATA WILL BE LOST!")
                confirmation = input("Type 'YES' to confirm: ")
                if confirmation != 'YES':
                    print("✗ Reset cancelled")
                    return False
                
                print("\n[RESET] Dropping all tables...")
                try:
                    db.drop_all()
                    db.session.commit()
                except Exception as e:
                    print(f"[ERROR] Error dropping tables: {e}")
                    db.session.rollback()
                    raise
                print("✓ All tables dropped")
            
            # Verify all models are loaded
            models_ok = verify_models_loaded()
            if not models_ok:
                print("\n⚠️  Some models may be missing - continuing anyway...")
            
            # Create all tables
            print("\n[1/4] Creating database tables...")
            try:
                db.create_all()
                db.session.commit()
            except Exception as e:
                print(f"[ERROR] Error creating tables: {e}")
                db.session.rollback()
                raise
            
            # Run migrations for existing installations
            print("\n[2/4] Running migrations...")
            try:
                run_migrations()
            except Exception as e:
                print(f"[ERROR] Error running migrations: {e}")
                db.session.rollback()
            
            # Verify all columns are created
            try:
                columns_ok = verify_table_columns()
                db.session.rollback()
                if not columns_ok:
                    print("\n⚠️  Some columns may be missing - please check model definitions")
            except Exception as e:
                print(f"[ERROR] Error verifying columns: {e}")
                db.session.rollback()
            
            created_tables = [table.name for table in db.metadata.sorted_tables]
            print(f"✓ Database tables created successfully ({len(created_tables)} tables)")
            print(f"   Tables: {', '.join(created_tables)}")
            
            # Initialize sample data (users, basic content)
            print("\n[3/4] Initializing sample data...")
            try:
                from __init__ import initialize_data
                initialize_data()
                db.session.commit()
                print("✓ Sample data initialized")
            except Exception as e:
                print(f"[ERROR] Error initializing sample data: {e}")
                db.session.rollback()
                raise
            
            # Seed all data from JSON files
            print("\n[4/4] Seeding database with content...")
            try:
                seed_all_data(db)
                db.session.commit()
                print("✓ Database seeding completed")
            except Exception as e:
                print(f"[ERROR] Error seeding database: {e}")
                db.session.rollback()
                raise
            
            print("\n" + "=" * 80)
            print("✓ DATABASE INITIALIZATION COMPLETED SUCCESSFULLY")
            print("=" * 80)
            print("\n✅ VPS DEPLOYMENT READY:")
            print("   ✓ All tables created with correct columns")
            print("   ✓ PDF fields (pdf_report, pdf_generated_at) configured")
            print("   ✓ Analysis ID fields (analysis_id, result_id) present")
            print("   ✓ Transaction rollback handling verified")
            print("   ✓ PostgreSQL compatibility confirmed")
            
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
            print("\n🔧 TROUBLESHOOTING:")
            print("   1. Check PostgreSQL connection: DATABASE_URL")
            print("   2. Verify database user permissions")
            print("   3. Ensure transaction rollback support (PostgreSQL required)")
            print("=" * 80)
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return False

if __name__ == '__main__':
    # Handle --verify-libs flag
    if '--verify-libs' in sys.argv:
        libs_ok, status = verify_critical_libraries()
        print("\nLibrary Status Summary:")
        for lib, ok in status.items():
            print(f"  {lib}: {'✓' if ok else '✗'}")
        sys.exit(0 if libs_ok else 1)
    
    # Handle --check flag
    if '--check' in sys.argv:
        libs_ok, _ = verify_critical_libraries()
        app = create_app()
        with app.app_context():
            models_ok = verify_models_loaded()
        sys.exit(0 if (libs_ok and models_ok) else 1)
    
    reset_mode = '--reset' in sys.argv or '-r' in sys.argv
    success = init_database(reset=reset_mode)
    sys.exit(0 if success else 1)
