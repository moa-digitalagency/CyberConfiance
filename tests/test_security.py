"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier test_security.py du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

"""

import unittest
import os
import sys

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock environment variables
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['FLASK_DEBUG'] = '0'

from __init__ import create_app, db
from models import User

class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app.config['TESTING'] = True
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Create test user
        self.user = User(username='testuser', email='test@example.com')
        self.user.set_password('password123')
        db.session.add(self.user)
        db.session.commit()

        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_open_redirect_protection(self):
        """Test that the login route protects against Open Redirect vulnerabilities."""
        response = self.client.post('/login', data={
            'username': 'testuser',
            'password': 'password123',
            'next': 'http://evil.com'
        }, follow_redirects=False)

        # Should redirect
        self.assertEqual(response.status_code, 302)

        # Should NOT redirect to evil.com
        location = response.headers.get('Location')
        self.assertNotEqual(location, 'http://evil.com')

        # Should redirect to default page (index)
        # Note: location might be full URL or relative path depending on Flask config
        # We verify it ends with / (root) or index path
        self.assertTrue(location.endswith('/') or location.endswith('/index'),
                        f"Unexpected redirect location: {location}")

    def test_safe_redirect(self):
        """Test that safe relative redirects still work."""
        response = self.client.post('/login', data={
            'username': 'testuser',
            'password': 'password123',
            'next': '/dashboard'
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        location = response.headers.get('Location')
        self.assertTrue(location.endswith('/dashboard'),
                        f"Should redirect to /dashboard, got {location}")

if __name__ == '__main__':
    unittest.main()
