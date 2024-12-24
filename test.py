import unittest
import requests
import json
import os
from unittest.mock import patch
from parameterized import parameterized

BASE_URL = os.getenv('API_BASE_URL', 'http://localhost:8080')

class TestServerlessRegistry(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.register_and_login()

    def tearDown(self):
        self.logout()
        self.delete_test_user()

    def register_and_login(self):
        # Register
        data = {
            "username": "testuser",
            "password": "testpassword",
            "email": "testuser@example.com"
        }
        response = self.session.post(f"{BASE_URL}/register", json=data)
        self.assertEqual(response.status_code, 200)

        # Login
        response = self.session.post(f"{BASE_URL}/login", json=data)
        self.assertEqual(response.status_code, 200)
        self.token = response.json()["token"]
        self.session.headers.update({"Authorization": self.token})

    def logout(self):
        response = self.session.post(f"{BASE_URL}/logout")
        self.assertEqual(response.status_code, 200)

    def delete_test_user(self):
        # Implement user deletion if your API supports it
        pass

    @parameterized.expand([
        ("valid_package", "test-package", "1.0.0", 201),
        ("invalid_name", "", "1.0.0", 400),
        ("invalid_version", "test-package", "", 400),
    ])
    def test_create_package(self, name, package_name, version, expected_status):
        data = {
            "name": package_name,
            "version": version,
            "description": "A test package",
            "type": "project"
        }
        response = self.session.post(f"{BASE_URL}/releases", json=data)
        self.assertEqual(response.status_code, expected_status)
        if expected_status == 201:
            self.assertIn("name", response.json())
            self.assertIn("tag_name", response.json())

    @patch('builtins.open')
    def test_upload_package(self, mock_open):
        mock_open.return_value = "mocked_file_content"
        files = {"package": mock_open}
        response = self.session.post(f"{BASE_URL}/upload/test-upload-id", files=files)
        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.json())

    def test_rate_limit(self):
        for _ in range(110):  # Assuming rate limit is 100 requests per minute
            self.session.get(f"{BASE_URL}/search?search=test")
        response = self.session.get(f"{BASE_URL}/search?search=test")
        self.assertEqual(response.status_code, 429)

    # Add more tests...

if __name__ == '__main__':
    unittest.main()