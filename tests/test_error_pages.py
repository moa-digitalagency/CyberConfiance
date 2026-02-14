import unittest
from __init__ import create_app, db
from flask import abort

class ErrorPageTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        # Use in-memory SQLite for speed
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Register routes to force errors
        @self.app.route('/force-400')
        def force_400():
            abort(400)

        @self.app.route('/force-403')
        def force_403():
            abort(403)

        @self.app.route('/force-451')
        def force_451():
            abort(451)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_404_page(self):
        response = self.client.get('/non-existent-page-12345')
        self.assertEqual(response.status_code, 404)
        self.assertIn(b'404 - Perdu dans le Cyberespace', response.data)
        self.assertIn(b'Retour aux fonctionnalit', response.data)
        self.assertIn(b'Besoin d\'aide imm', response.data)
        # Check for Lottie
        self.assertIn(b'lottie-player', response.data)

    def test_400_page(self):
        response = self.client.get('/force-400')
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'400 - Mauvaise Requ', response.data)
        self.assertIn(b'Confused Robot', response.data)

    def test_403_page(self):
        response = self.client.get('/force-403')
        self.assertEqual(response.status_code, 403)
        self.assertIn(b'403 - Acc', response.data)
        self.assertIn(b'Zone Restreinte', response.data)
        self.assertIn(b'Padlock', response.data)

    def test_451_page(self):
        response = self.client.get('/force-451')
        self.assertEqual(response.status_code, 451)
        self.assertIn(b'Erreur 451', response.data)
        self.assertIn(b'Fahrenheit 451', response.data)
        self.assertIn(b'Burning Book', response.data)

if __name__ == '__main__':
    unittest.main()
