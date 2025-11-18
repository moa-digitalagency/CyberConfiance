#!/usr/bin/env python3
"""
Database initialization and seeding script
Runs migrations and seeds data from JSON files
"""

from __init__ import create_app, db
from utils.seed_data import seed_all_data

def init_database():
    """Initialize database and seed data"""
    app = create_app()
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ Database tables created")
        
        # Seed data from JSON files
        seed_all_data(db)

if __name__ == '__main__':
    init_database()
