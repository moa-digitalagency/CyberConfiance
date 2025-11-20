#!/usr/bin/env python3
"""
Data Migration: Extract crime_type, platform, and platform_identifier from existing descriptions
and populate the new dedicated columns
"""
import sys
import re
sys.path.insert(0, '/home/runner/workspace')

from __init__ import create_app, db
from models import RequestSubmission

def parse_legacy_description(description):
    """
    Parse legacy description format to extract crime_type, platform, and platform_identifier
    
    Format: [Type: crime_type] [Plateforme: platform] [Identification: platform_identifier]
    """
    crime_type = None
    platform = None
    platform_identifier = None
    clean_description = description
    
    if description:
        type_match = re.search(r'\[Type:\s*([^\]]+)\]', description)
        if type_match:
            crime_type = type_match.group(1).strip()
        
        platform_match = re.search(r'\[Plateforme:\s*([^\]]+)\]', description)
        if platform_match:
            platform = platform_match.group(1).strip()
        
        identifier_match = re.search(r'\[Identification:\s*([^\]]+)\]', description)
        if identifier_match:
            platform_identifier = identifier_match.group(1).strip()
        
        pattern = r'\[Type:[^\]]+\]\s*\[Plateforme:[^\]]+\](?:\s*\[Identification:[^\]]+\])?\s*\n*'
        clean_description = re.sub(pattern, '', description).strip()
    
    return crime_type, platform, platform_identifier, clean_description

def run_migration():
    """Backfill crime_type, platform, and platform_identifier for existing cybercrime reports"""
    app = create_app()
    
    with app.app_context():
        cybercrime_reports = RequestSubmission.query.filter_by(request_type='cybercrime-report').all()
        
        updated_count = 0
        skipped_count = 0
        
        print(f"[INFO] Found {len(cybercrime_reports)} cybercrime reports to process")
        
        for report in cybercrime_reports:
            if report.crime_type is None and report.description:
                crime_type, platform, platform_identifier, clean_desc = parse_legacy_description(report.description)
                
                if crime_type or platform or platform_identifier:
                    report.crime_type = crime_type
                    report.platform = platform
                    report.platform_identifier = platform_identifier
                    report.description = clean_desc
                    updated_count += 1
                    print(f"[OK] Updated report #{report.id}: Type={crime_type}, Platform={platform}")
                else:
                    skipped_count += 1
            else:
                skipped_count += 1
        
        db.session.commit()
        print(f"\n[OK] Migration completed:")
        print(f"    - {updated_count} reports updated")
        print(f"    - {skipped_count} reports skipped (already have data or no parseable info)")

if __name__ == '__main__':
    run_migration()
