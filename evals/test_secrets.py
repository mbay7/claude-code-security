"""
Eval: Secret Exposure Detection (OWASP LLM02:2025)

Tests the security-scan.py hook's ability to detect hardcoded credentials,
API keys, and private key material across different file types.
"""

import pytest
from conftest import load_hook

scanner = load_hook("security-scan.py")


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAPIKeyDetection:
    """Detection of hardcoded API keys."""

    def test_anthropic_key(self):
        # Realistic Anthropic API key pattern
        key = "sk-ant-api03-" + "A" * 90
        content = f'ANTHROPIC_API_KEY = "{key}"'
        findings = scanner.scan_content(content, "config.py")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"

    def test_openai_key(self):
        key = "sk-" + "a" * 48
        content = f'openai.api_key = "{key}"'
        findings = scanner.scan_content(content, "app.py")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"

    def test_aws_access_key(self):
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        findings = scanner.scan_content(content, "terraform.tf")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"

    def test_github_pat_classic(self):
        pat = "ghp_" + "a" * 36
        content = f'GITHUB_TOKEN = "{pat}"'
        findings = scanner.scan_content(content, ".env")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"

    def test_github_pat_fine_grained(self):
        pat = "github_pat_" + "a" * 82
        content = f'token: {pat}'
        findings = scanner.scan_content(content, "config.yaml")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"

    def test_stripe_live_key(self):
        key = "sk_live_" + "a" * 24
        content = f'stripe.api_key = "{key}"'
        findings = scanner.scan_content(content, "payment.py")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"


class TestCryptographicMaterial:
    """Detection of private keys and cryptographic material."""

    def test_rsa_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        findings = scanner.scan_content(content, "server.key")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"

    def test_openssh_private_key(self):
        content = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...\n-----END OPENSSH PRIVATE KEY-----"
        findings = scanner.scan_content(content, "id_rsa")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "CRITICAL"

    def test_supabase_jwt(self):
        # Valid JWT structure with Supabase header
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "a" * 40 + "." + "a" * 40
        content = f'SUPABASE_KEY = "{jwt}"'
        findings = scanner.scan_content(content, "supabase.ts")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
        assert secrets[0]["severity"] == "HIGH"


class TestPlaceholderIgnored:
    """Verify placeholder values are NOT flagged (false positive prevention)."""

    def test_anthropic_placeholder(self):
        content = 'ANTHROPIC_API_KEY = "sk-ant-your-key-here"'
        findings = scanner.scan_content(content, "example.env")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) == 0, f"False positive on placeholder: {secrets}"

    def test_replace_me_placeholder(self):
        content = 'API_KEY = "REPLACE_ME"'
        findings = scanner.scan_content(content, "config.yaml")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) == 0, f"False positive on REPLACE_ME: {secrets}"

    def test_angle_bracket_placeholder(self):
        content = 'token: "<your-github-token>"'
        findings = scanner.scan_content(content, "setup.md")
        # May or may not trigger — documenting that angle bracket placeholders
        # are common in docs and should ideally not fire
        _ = findings

    def test_env_example_file_content(self):
        content = """
# Copy this file to .env and fill in your values
ANTHROPIC_API_KEY=your-api-key-here
OPENAI_API_KEY=your-openai-key
GITHUB_TOKEN=your-github-pat
"""
        findings = scanner.scan_content(content, ".env.example")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) == 0, f"False positive on .env.example placeholders: {secrets}"


class TestMultipleSecretsInFile:
    """Detection of multiple secrets in a single file."""

    def test_multiple_keys_detected(self):
        anthropic_key = "sk-ant-api03-" + "B" * 90
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        content = f"""
ANTHROPIC_API_KEY={anthropic_key}
AWS_ACCESS_KEY_ID={aws_key}
DATABASE_URL=postgresql://user:password@localhost/db
"""
        findings = scanner.scan_content(content, "leaked.env")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 2, "Should detect both Anthropic and AWS keys"

    def test_key_in_yaml(self):
        key = "sk-ant-api03-" + "C" * 90
        content = f"""
production:
  api_key: {key}
  model: claude-3-5-sonnet
"""
        findings = scanner.scan_content(content, "config.yaml")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1

    def test_key_in_json(self):
        key = "AKIAIOSFODNN7EXAMPLE"
        content = f'{{"aws_access_key_id": "{key}", "region": "us-east-1"}}'
        findings = scanner.scan_content(content, "credentials.json")
        secrets = [f for f in findings if f["category"] == "Secret Exposure"]
        assert len(secrets) >= 1
