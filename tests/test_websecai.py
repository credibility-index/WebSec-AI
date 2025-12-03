import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Добавляем корень проекта в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from websec.py import ai_analysis  # основной файл
from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf

class TestWebSecAI(unittest.TestCase):

    @patch('openai.OpenAI.chat.completions.create')
    def test_ai_analysis_no_vulns(self, mock_openai):
        """Тест AI-анализа без уязвимостей"""
        mock_response = MagicMock()
        mock_response.choices[0].message.content = "No issues"
        mock_openai.return_value = mock_response
        
        result = ai_analysis([])
        self.assertIn("No significant vulnerabilities", result[0])
        self.assertIn("Существенных уязвимостей не обнаружено", result[1])

    @patch('openai.OpenAI.chat.completions.create')
    def test_ai_analysis_with_vulns(self, mock_openai):
        """Тест AI-анализа с уязвимостями"""
        mock_response_en = MagicMock()
        mock_response_en.choices[0].message.content = "- Fix CSRF tokens"
        mock_openai.side_effect = [mock_response_en, MagicMock()]
        
        result = ai_analysis(["CSRF"])
        self.assertIn("CSRF", str(result))

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
    def test_xss_detected(self, mock_get):
        """XSS отражен"""
        mock_get.return_value.text = "<script>alert(1)</script>"
        mock_get.return_value.status_code = 200
        result = scan_xss("http://test.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_csrf_missing_token(self, mock_get):
        """CSRF без токена"""
        mock_get.return_value.text = "<form method='POST'><input name='submit'></form>"
        mock_get.return_value.status_code = 200
        result = check_csrf_protection("http://test.com")
        self.assertTrue(result)  # True = уязвимость

    @patch('requests.post')
    def test_ssrf_not_detected(self, mock_post):
        """SSRF не обнаружен"""
        mock_post.return_value.text = "Page not found"
        result = scan_ssrf("http://test.com")
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
