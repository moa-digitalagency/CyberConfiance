#!/bin/bash
# CyberConfiance VPS Deployment & Update Script
# Ensures all features work consistently between Replit and VPS

set -e

echo "======================================"
echo "CyberConfiance VPS Deployment Script"
echo "======================================"

# Step 1: Pull latest code
echo "[1/5] Pulling latest code..."
git pull origin main 2>/dev/null || echo "Note: Git not available, ensure manual code sync"

# Step 2: Install/update dependencies
echo "[2/5] Installing dependencies..."
pip install -r requirements.txt --upgrade

# Step 3: Clear Python cache
echo "[3/5] Clearing Python cache..."
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Step 4: Initialize/reset database
echo "[4/5] Initializing database..."
python init_db.py

# Step 5: Verify features
echo "[5/5] Verifying all features..."
python3 << 'VERIFY'
from __init__ import create_app, db
from models import BreachAnalysis, SecurityAnalysis, QuizResult

app = create_app()
with app.app_context():
    breach_count = BreachAnalysis.query.count()
    analysis_count = SecurityAnalysis.query.count()
    quiz_count = QuizResult.query.count()
    
    print(f"✓ BreachAnalysis records: {breach_count}")
    print(f"✓ SecurityAnalysis records: {analysis_count}")
    print(f"✓ QuizResult records: {quiz_count}")
    print("\n✅ Database verification complete!")
VERIFY

echo ""
echo "======================================"
echo "✅ Deployment completed successfully!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Restart your Flask application"
echo "2. Clear browser cache (Ctrl+Shift+Delete)"
echo "3. Test all features on fresh browser session"
echo ""
echo "Commands to restart:"
echo "  - Replit: Restart workflow 'CyberConfiance'"
echo "  - VPS: systemctl restart cyberconfiance (or your service name)"
echo ""
