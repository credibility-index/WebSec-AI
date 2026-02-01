import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from websec import ai_analysis, client, scan_crypto_wallet
from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf
from scanners.network_scanner import scan_network_segmentation


class TestWebSecAI(unittest.TestCase):

    @patch('websec.client')
    def test_ai_analysis_no_vulns(self, mock_client):
        """AI-аналитика без уязвимостей не обращается к OpenAI"""
        result_en, result_ru = ai_analysis([])
        self.assertIn("No significant vulnerabilities", result_en)
        self.assertIn("Существенных уязвимостей не обнаружено", result_ru)
        mock_client.chat.completions.create.assert_not_called()

    @patch('websec.client')
    def test_ai_analysis_with_vulns(self, mock_client):
        """AI-аналитика с уязвимостями вызывает OpenAI два раза"""
        mock_resp_en = MagicMock()
        mock_resp_en.choices = [MagicMock()]
        mock_resp_en.choices[0].message.content = "- Fix CSRF tokens"

        mock_resp_ru = MagicMock()
        mock_resp_ru.choices = [MagicMock()]
        mock_resp_ru.choices[0].message.content = "- Исправьте CSRF токены"

        mock_client.chat.completions.create.side_effect = [mock_resp_en, mock_resp_ru]

        result_en, result_ru = ai_analysis(["CSRF"])
        self.assertIn("Fix CSRF", result_en)
        self.assertIn("CSRF", result_en)
        self.assertIn("CSRF", result_ru)
        self.assertEqual(mock_client.chat.completions.create.call_count, 2)

    @patch('requests.get')
    def test_sql_injection_detected(self, mock_get):
        """SQLi обнаружен"""
        mock_get.return_value.text = "SQL syntax error near '1=1'"
        mock_get.return_value.status_code = 200
        result = scan_sql_injection("http://test.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_sql_injection_not_detected(self, mock_get):
        """SQLi не обнаружен"""
        mock_get.return_value.text = "Welcome"
        mock_get.return_value.status_code = 200
        result = scan_sql_injection("http://test.com")
        self.assertFalse(result)

    @patch('requests.get')
    def test_sql_injection_union_attack(self, mock_get):
        """SQLi UNION attack"""
        mock_get.return_value.text = "UNION attack detected"
        result = scan_sql_injection("http://test.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_xss_detected(self, mock_get):
        mock_get.return_value.text = "<script>alert(1)</script>"
        mock_get.return_value.status_code = 200
        result = scan_xss("http://test.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_xss_dom_based(self, mock_get):
        mock_get.return_value.text = "<img src=x onerror=alert(1)>"
        result = scan_xss("http://test.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_csrf_missing_token(self, mock_get):
        """CSRF без токена"""
        mock_get.return_value.text = "<form method='POST'><input name='submit'></form>"
        mock_get.return_value.status_code = 200
        result = check_csrf_protection("http://test.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_csrf_token_in_header(self, mock_get):
        """CSRF с токеном в заголовке"""
        mock_get.return_value.text = "<form method='POST' headers='X-CSRF-TOKEN: abc123'></form>"
        result = check_csrf_protection("http://test.com")
        self.assertFalse(result)

    @patch('requests.post')
    def test_ssrf_not_detected(self, mock_post):
        """SSRF не обнаружен"""
        mock_post.return_value.text = "Page not found"
        result = scan_ssrf("http://test.com")
        self.assertFalse(result)

    @patch('requests.post')
    def test_ssrf_internal_ip(self, mock_post):
        """SSRF internal IP"""
        mock_post.return_value.text = "Internal server error"
        result = scan_ssrf("http://192.168.1.1")
        self.assertTrue(result)

    def test_network_segmentation_localhost(self):
        """Network scan localhost"""
        issues = scan_network_segmentation("http://127.0.0.1")
        self.assertIsInstance(issues, list)

    @patch('scanners.network_scanner.get_open_ports')
    def test_network_segmentation_detects_ssh(self, mock_get_open_ports):
        """Network SSH exposed"""
        mock_get_open_ports.return_value = ["22/tcp"]
        issues = scan_network_segmentation("http://192.168.0.10")
        self.assertTrue(any("SSH exposed in public zone" in i for i in issues))

    @patch('scanners.network_scanner.get_open_ports')
    def test_network_segmentation_ftp_port(self, mock_get_open_ports):
        """Network FTP exposed"""
        mock_get_open_ports.return_value = ["21/tcp"]
        issues = scan_network_segmentation("http://192.168.0.10")
        self.assertTrue(any("FTP exposed" in i for i in issues))

    @patch('requests.get', side_effect=requests.exceptions.ConnectionError)
    def test_sql_injection_connection_error(self, mock_get):
        """SQLi connection error"""
        result = scan_sql_injection("http://unreachable.com")
        self.assertFalse(result)

    @patch('scanners.crypto_scanner.validate_wallet')
    def test_crypto_scanner_valid_wallet(self, mock_validate):
        """Crypto wallet valid"""
        mock_validate.return_value = True
        result = scan_crypto_wallet("valid_address")
        self.assertTrue(result)

    @patch('websec.client')
    def test_ai_analysis_multiple_vulns(self, mock_client):
        """AI multiple vulns"""
        result_en, result_ru = ai_analysis(["CSRF", "XSS", "SQLi"])
        self.assertIn("CSRF", result_en)
        self.assertIn("XSS", result_en)
        self.assertIn("SQLi", result_en)


if __name__ == '__main__':
    unittest.main()
