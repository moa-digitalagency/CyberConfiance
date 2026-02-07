import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import importlib

# Add the project root to sys.path
sys.path.append(os.getcwd())

class TestMigrationLogic(unittest.TestCase):

    def setUp(self):
        # Create a clean environment for imports
        self.modules_patcher = patch.dict(sys.modules, {
            '__init__': MagicMock(),
            'utils': MagicMock(),
            'utils.seed_data': MagicMock(),
            'models': MagicMock()
        })
        self.modules_patcher.start()

        # Reload init_db to ensure it uses the mocked modules
        if 'init_db' in sys.modules:
            importlib.reload(sys.modules['init_db'])
        else:
            import init_db

        self.init_db = sys.modules['init_db']

    def tearDown(self):
        self.modules_patcher.stop()
        # Clean up init_db from sys.modules to avoid pollution
        if 'init_db' in sys.modules:
            del sys.modules['init_db']

    @patch('sqlalchemy.inspect')
    @patch('sqlalchemy.text')
    def test_run_migrations_adds_missing_column(self, mock_text, mock_inspect):
        """Test that run_migrations adds a column if it is missing."""

        # Patch the db object in the reloaded init_db module
        # Note: init_db imports db from __init__, which is mocked.
        # So init_db.db is the mock from sys.modules['__init__'].db
        mock_db = self.init_db.db
        mock_session = MagicMock()
        mock_db.session = mock_session

        # Setup mocks
        mock_inspector = MagicMock()
        mock_inspect.return_value = mock_inspector

        # Table exists
        mock_inspector.get_table_names.return_value = ['metadata_analyses']

        # Column 'original_file' is MISSING
        mock_inspector.get_columns.return_value = [
            {'name': 'id', 'type': 'INTEGER'},
            {'name': 'file_type', 'type': 'VARCHAR'}
        ]

        # Run migrations
        self.init_db.run_migrations()

        # Assertions
        expected_sql_content = "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS original_file BYTEA"

        found = False
        for call_args in mock_text.call_args_list:
            if expected_sql_content in str(call_args):
                found = True
                break

        self.assertTrue(found, f"Expected SQL '{expected_sql_content}' not passed to text()")

        mock_session.execute.assert_called()
        mock_session.commit.assert_called()

    @patch('sqlalchemy.inspect')
    @patch('sqlalchemy.text')
    def test_run_migrations_skips_existing_column(self, mock_text, mock_inspect):
        """Test that run_migrations skips adding a column if it already exists."""

        mock_db = self.init_db.db
        mock_session = MagicMock()
        mock_db.session = mock_session

        # Setup mocks
        mock_inspector = MagicMock()
        mock_inspect.return_value = mock_inspector

        # Table exists
        mock_inspector.get_table_names.return_value = ['metadata_analyses']

        # Column 'original_file' EXISTS
        mock_inspector.get_columns.return_value = [
            {'name': 'id', 'type': 'INTEGER'},
            {'name': 'original_file', 'type': 'BYTEA'} # It exists!
        ]

        # Run migrations
        self.init_db.run_migrations()

        # Assertions
        expected_sql_content = "ALTER TABLE metadata_analyses ADD COLUMN IF NOT EXISTS original_file BYTEA"

        found = False
        for call_args in mock_text.call_args_list:
             if expected_sql_content in str(call_args):
                 found = True
                 break

        self.assertFalse(found, f"SQL '{expected_sql_content}' should NOT have been executed")

if __name__ == '__main__':
    unittest.main()
