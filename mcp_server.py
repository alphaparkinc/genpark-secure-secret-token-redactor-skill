"""MCP Stdio Server for Secure Secret Token Redactor.
100% Python Standard Library.
"""
import sys
import json
from client import SecureSecretTokenRedactor

redactor = SecureSecretTokenRedactor()

def handle_rpc(line):
    try:
        req = json.loads(line)
    except Exception:
        return
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        res = {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "genpark-secure-secret-token-redactor-skill", "version": "1.0.1"},
            "capabilities": {"tools": {}}
        }
        send_response(req_id, res)
    elif method == "tools/list":
        tools = [
            {
                "name": "scan_secrets",
                "description": "Scan prompt text or logs for sensitive API keys, tokens, and credentials",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"}
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "redact_secrets",
                "description": "Redact and mask all detected secrets with secure replacement tokens",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "mask_template": {"type": "string", "default": "[REDACTED_{TYPE}]"}
                    },
                    "required": ["text"]
                }
            }
        ]
        send_response(req_id, {"tools": tools})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "scan_secrets":
            out = {"findings": redactor.scan_secrets(args.get("text", ""))}
        elif name == "redact_secrets":
            out = redactor.redact_secrets(args.get("text", ""), args.get("mask_template", "[REDACTED_{TYPE}]"))
        else:
            send_error(req_id, -32601, f"Unknown tool: {name}")
            return
        send_response(req_id, {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]})

def send_response(req_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n")
    sys.stdout.flush()

def send_error(req_id, code, message):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}) + "\n")
    sys.stdout.flush()

def main():
    for line in sys.stdin:
        if line.strip():
            handle_rpc(line.strip())

if __name__ == "__main__":
    main()
