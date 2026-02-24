import sys
import os
from unittest.mock import patch

# Add root to path so we can import services
sys.path.append(os.getcwd())

from services.qrcode_analyzer_service import QRCodeAnalyzerService

def verify_protection():
    analyzer = QRCodeAnalyzerService()

    print("Testing with mocked exception...")

    # Mock the parent class method to raise an exception
    # Note: We patch the method on the PARENT class because our wrapper calls super().analyze_qr_image
    # effectively calling the method on the class it inherited from (or rather, the method resolution order).
    # Since we inherited, we can patch the base class method.

    with patch('services.qrcode.analyzer.QRCodeAnalyzerService.analyze_qr_image') as mock_super:
        mock_super.side_effect = Exception("Simulated Critical Failure")

        results = analyzer.analyze_qr_image(b'some_data', 'test.jpg')

        print(f"Result: {results}")

        if not isinstance(results, dict):
            print("FAILED: Result is not a dictionary")
            sys.exit(1)

        if results.get('success') is not False:
            print("FAILED: success is not False")
            sys.exit(1)

        if "Simulated Critical Failure" not in results.get('error', ''):
            print("FAILED: Expected error message not found")
            sys.exit(1)

    print("SUCCESS: Wrapper caught simulated exception.")

if __name__ == "__main__":
    verify_protection()
