
import unittest
from unittest.mock import MagicMock, patch
from flask import Flask
import routes.main
from routes.main import bp
import os

class TestLinkAnalyzerOptimization(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'test'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()

    @patch('routes.main.render_template')
    @patch('routes.main.requests.Session')
    @patch('routes.main.is_safe_url_strict')
    def test_link_analyzer_optimization(self, mock_is_safe, mock_session_cls, mock_render):
        """
        Test that the link analyzer uses an optimized session and streams responses
        to avoid downloading large bodies, while correctly closing connections.
        """
        # Setup mock session
        mock_session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = mock_session

        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.headers = {'Location': 'http://example.com/final', 'Content-Type': 'text/html'}

        # Second response (final)
        mock_response2 = MagicMock()
        mock_response2.status_code = 200
        mock_response2.headers = {'Content-Type': 'text/html'}

        # Chain responses
        mock_session.get.side_effect = [mock_response, mock_response2]

        mock_is_safe.return_value = True
        mock_render.return_value = 'OK'

        # Make request
        response = self.client.post('/outils/analyseur-liens', data={'url': 'http://example.com'})

        # Verify Session was used
        mock_session_cls.assert_called_once()

        # Verify session.get called with stream=True for both requests
        self.assertEqual(mock_session.get.call_count, 2)
        mock_session.get.assert_any_call(
            'http://example.com',
            allow_redirects=False,
            timeout=(3.05, 5),
            stream=True
        )
        mock_session.get.assert_any_call(
            'http://example.com/final',
            allow_redirects=False,
            timeout=(3.05, 5),
            stream=True
        )

        # Verify response.close() was called for both
        mock_response.close.assert_called_once()
        mock_response2.close.assert_called_once()

        # Verify logic result
        args, kwargs = mock_render.call_args
        self.assertEqual(args[0], 'outils/link_analyzer.html')
        self.assertIn('redirects', kwargs)
        self.assertEqual(len(kwargs['redirects']), 2)
        self.assertEqual(kwargs['redirect_count'], 1)

if __name__ == '__main__':
    unittest.main()
