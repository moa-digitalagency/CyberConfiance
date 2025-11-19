#!/usr/bin/env python3
"""
Database initialization and seeding script
Runs migrations and seeds data from JSON files

Usage:
    python init_db.py           # Full initialization
    python init_db.py --reset   # Drop all tables and reinitialize (DANGER!)
"""

import os
import sys
from __init__ import create_app, db
from utils.seed_data import seed_all_data

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
            
            # Create all tables
            print("\n[1/3] Creating database tables...")
            db.create_all()
            print("✓ Database tables created successfully")
            
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
