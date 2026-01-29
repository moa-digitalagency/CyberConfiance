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

class SecurityHeadersTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_security_txt_exists(self):
        """Test that security.txt is accessible."""
        response = self.client.get('/.well-known/security.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Contact:', response.data)
        self.assertIn(b'Expires:', response.data)

    def test_security_headers(self):
        """Test that security headers are present."""
        response = self.client.get('/')
        headers = response.headers

        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31536000; includeSubDomains')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('X-Frame-Options'), 'SAMEORIGIN')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('Server'), 'CyberConfiance Secure Server')
        self.assertIn("default-src 'self'", headers.get('Content-Security-Policy', ''))

if __name__ == '__main__':
    unittest.main()
