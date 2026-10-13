#!/usr/bin/env python3
"""Mock container-credentials endpoint (ECS task role / EKS Pod Identity) for tests.

Serves the JSON document the real 169.254.170.2 endpoint returns, on loopback so the
AWS SDK's GeneralHTTPCredentialsProvider accepts the AWS_CONTAINER_CREDENTIALS_FULL_URI.

Usage: run_container_credentials_test_server.py [port] [expected_authorization]

If expected_authorization is given, requests whose Authorization header does not match
are rejected with 401 — a passing test then proves AWS_CONTAINER_AUTHORIZATION_TOKEN
was forwarded by the provider.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

EXPECTED_AUTHORIZATION = sys.argv[2] if len(sys.argv) > 2 else None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if EXPECTED_AUTHORIZATION and self.headers.get("Authorization") != EXPECTED_AUTHORIZATION:
            self.send_response(401)
            self.end_headers()
            sys.stdout.write(f"rejected: Authorization={self.headers.get('Authorization')}\n")
            sys.stdout.flush()
            return
        expiration = (datetime.now(timezone.utc) + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = json.dumps(
            {
                "AccessKeyId": "ASIAMOCKCONTAINERKEY",
                "SecretAccessKey": "mock-container-secret-key",
                "Token": "mock-container-session-token",
                "Expiration": expiration,
                "RoleArn": "arn:aws:iam::123456789012:role/mock-task-role",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        sys.stdout.write(f"served: {self.path}\n")
        sys.stdout.flush()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
