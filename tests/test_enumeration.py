import unittest
from unittest.mock import patch, MagicMock
from src.attack_tools.manual_ssh import ManualSSHEnumerator

class TestManualSSHEnumerator(unittest.TestCase):
    @patch('paramiko.SSHClient')
    def test_auth_failure_recorded(self, mock_client):
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        mock_instance.connect.side_effect = __import__('paramiko').AuthenticationException()

        e = ManualSSHEnumerator("192.168.56.10")
        result = e.test_single_username("fakeuser", "wrongpass", samples=1)
        self.assertEqual(result["result"], "auth_failed")

if __name__ == "__main__":
    unittest.main()
