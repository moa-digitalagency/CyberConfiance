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

class Error404TestCase(unittest.TestCase):
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

    def test_404_page_loads(self):
        """Test that a non-existent page returns 404 and correct content."""
        response = self.client.get('/this-page-does-not-exist-12345')
        self.assertEqual(response.status_code, 404)

        # Check for Lottie player
        content = response.data.decode('utf-8')
        self.assertIn('lottie-player', content)
        self.assertIn('https://cdn.jsdelivr.net/npm/@lottiefiles/lottie-player@latest/dist/lottie-player.js', content)

        # Check for Button content
        self.assertIn("Retour à l'accueil", content)
        self.assertIn('btn-primary', content)

        # Check for CSP update (connect-src)
        csp = response.headers.get('Content-Security-Policy', '')
        self.assertIn("https://assets2.lottiefiles.com", csp)

if __name__ == '__main__':
    unittest.main()
