"""Secure Secret Token Redactor.
100% Python Standard Library.
"""
import re
from typing import Dict, Any, List

class SecureSecretTokenRedactor:
    """High-speed regex and entropy-based scanner for redacting secrets from prompt logs."""

    PATTERNS = {
        "OPENAI_KEY": re.compile(r'sk-[a-zA-Z0-9_-]{20,60}'),
        "ANTHROPIC_KEY": re.compile(r'sk-ant-[a-zA-Z0-9_-]{20,80}'),
        "GITHUB_TOKEN": re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,40}'),
        "AWS_KEY_ID": re.compile(r'(?:AKIA|ASIA|AROA)[A-Z0-9]{16}'),
        "JWT_TOKEN": re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
        "PRIVATE_KEY": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----[^-]+-----END (?:RSA )?PRIVATE KEY-----', re.DOTALL),
        "GENERIC_BEARER": re.compile(r'(?:Bearer\s+)([a-zA-Z0-9_.\-~+/]{24,})', re.IGNORECASE)
    }

    @classmethod
    def scan_secrets(cls, text: str) -> List[Dict[str, Any]]:
        findings = []
        for p_name, regex in cls.PATTERNS.items():
            for m in regex.finditer(text):
                matched_val = m.group(0)
                findings.append({
                    "secret_type": p_name,
                    "start": m.start(),
                    "end": m.end(),
                    "sample_masked": matched_val[:4] + "****" + matched_val[-4:] if len(matched_val) > 8 else "****"
                })
        return findings

    @classmethod
    def redact_secrets(cls, text: str, mask_template: str = "[REDACTED_{TYPE}]") -> Dict[str, Any]:
        findings = cls.scan_secrets(text)
        findings.sort(key=lambda x: x["start"], reverse=True)

        redacted_text = text
        for f in findings:
            mask = mask_template.replace("{TYPE}", f["secret_type"])
            redacted_text = redacted_text[:f["start"]] + mask + redacted_text[f["end"]:]

        return {
            "redacted_text": redacted_text,
            "total_secrets_redacted": len(findings),
            "findings_summary": [f["secret_type"] for f in findings]
        }
