"""Example usage for GenPark Secure Secret Token Redactor."""
from client import SecureSecretTokenRedactor

def main():
    sensitive_log = """
    Agent debug dump:
    Connecting to OpenAI using sk-proj-mock1234567890abcdef1234567890
    GitHub authentication: ghp_EXAMPLE_TOKEN_FOR_REDACTION_TEST_ONLY_1234
    AWS Access ID: AKIAIOSFODNN7EXAMPLE
    """

    print("Scanning secrets in log:")
    findings = SecureSecretTokenRedactor.scan_secrets(sensitive_log)
    for f in findings:
        print(f" - Found {f['secret_type']}: {f['sample_masked']}")

    print("\nRedacted log output:")
    redacted = SecureSecretTokenRedactor.redact_secrets(sensitive_log)
    print(redacted["redacted_text"])

if __name__ == "__main__":
    main()
