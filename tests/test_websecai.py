import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Добавляем корень проекта в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from websec import ai_analysis, client  # основной файл
from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf


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

        # Мокаем ответ для EN
        mock_resp_en = MagicMock()
        mock_resp_en.choices = [MagicMock()]
        mock_resp_en.choices[0].message.content = "- Fix CSRF tokens"

        # Мокаем ответ для RU
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
    def test_xss_detected(self, mock_get):
        """XSS обнаружен"""
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
        self.assertTrue(result)  # True = уязвимость есть

    @patch('requests.post')
    def test_ssrf_not_detected(self, mock_post):
        """SSRF не обнаружен"""
        mock_post.return_value.text = "Page not found"

        result = scan_ssrf("http://test.com")
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
