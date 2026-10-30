import unittest

from app.detector import analyze_event
from app.providers import identify_provider


class DetectorTests(unittest.TestCase):
    def test_detects_openai_provider(self):
        result = analyze_event({"process": "python.exe", "destination": "api.openai.com", "url": "https://api.openai.com/v1/chat/completions", "content": "hello"})
        self.assertEqual(result["provider"], "openai")
        self.assertTrue(any(f["type"] == "AI provider traffic" for f in result["findings"]))

    def test_flags_api_key_without_echoing_value(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
        result = analyze_event({"destination": "api.openai.com", "content": f"api_key={secret}"})
        self.assertTrue(any(f["type"] == "OpenAI-style API key" for f in result["findings"]))
        self.assertNotIn(secret, str(result))

    def test_flags_github_token(self):
        result = analyze_event({"content": "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"})
        self.assertTrue(any(f["type"] == "GitHub token" for f in result["findings"]))

    def test_flags_sensitive_file_read(self):
        result = analyze_event({"process": "powershell.exe", "content": "Get-Content .env", "action": "shell_command"})
        self.assertTrue(any(f["type"] == "Agent reading sensitive file" for f in result["findings"]))
        self.assertGreaterEqual(result["risk_score"], 60)

    def test_ollama_local_endpoint(self):
        result = analyze_event({"destination": "127.0.0.1:11434", "url": "http://127.0.0.1:11434/api/chat", "content": "synthetic prompt"})
        self.assertEqual(result["provider"], "ollama")

    def test_lookalike_domain_not_misclassified(self):
        self.assertEqual(identify_provider({"destination": "api.openai.com.attacker.example"}), "unknown")

    def test_empty_event_is_safe(self):
        result = analyze_event({})
        self.assertEqual(result["provider"], "unknown")
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
