#!/usr/bin/env python3
"""Test configured endpoints with temporary AWS files and a local HTTP server."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENDPOINT = "https://default.example.com/"
SERVICE_ENDPOINT = "https://service.example.com:9443/gateway/"
GLOBAL_ENDPOINT = "http://global.example.com:9000/"
FALLBACK_ENDPOINT = "s3.amazonaws.com"


class S3Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.respond(False)

    def do_GET(self):
        self.respond(True)

    def respond(self, send_body):
        if self.path != "/gateway/test-bucket/endpoint.csv":
            self.server.requests.append((self.command, self.path, 404))
            self.send_error(404)
            return
        self.server.requests.append((self.command, self.path, 200))
        body = b"value\n42\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/csv")
        self.send_header("ETag", '"endpoint-test"')
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def log_message(self, *_args):
        pass


def run_test(unittest, test, env, directory):
    # A missing extension or require-env can otherwise be reported as success.
    # Check the JUnit report to ensure that assertions actually ran, without skips.
    report = directory / "results.xml"
    report.unlink(missing_ok=True)
    try:
        result = subprocess.run(
            [str(unittest), test, "--reporter", "junit", "--out", str(report)],
            cwd=ROOT,
            env=env,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        print(f"Timed out: {test}")
        return False
    if not report.is_file():
        print(f"Missing test report: {test}")
        return False
    results = ET.parse(report).getroot()
    passed = (
        result.returncode == 0
        and bool(results.findall(".//testcase"))
        and not any(results.findall(f".//{tag}") for tag in ("failure", "error", "skipped"))
    )
    if not passed:
        print(report.read_text())
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unittest", type=Path, default=ROOT / "build/release/test/unittest")
    args = parser.parse_args()
    unittest = args.unittest.resolve()
    if not unittest.is_file():
        parser.error(f"test binary not found: {unittest}")

    # Remove all inherited AWS settings, including credential process/container/STS
    # configuration. No real credentials or remote AWS requests are needed.
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
    failures = []
    with tempfile.TemporaryDirectory(prefix="duckdb-aws-endpoints-") as directory:
        directory = Path(directory)
        config = directory / "config"
        credentials = directory / "credentials"
        profiles = ["default", "service", "global", "empty", "ignored", "missing-services", "local"]
        credentials.write_text(
            "\n".join(
                f"[{profile}]\naws_access_key_id=endpoint-test-id\naws_secret_access_key=endpoint-test-key\n"
                for profile in profiles
            )
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), S3Handler)
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config.write_text(
                f"""[default]
region = us-east-1
services = default-services

[profile service]
region = us-east-1
services = service-endpoints
endpoint_url = {GLOBAL_ENDPOINT}

[profile global]
region = us-east-1
endpoint_url = {GLOBAL_ENDPOINT}

[profile empty]
region = us-east-1

[profile ignored]
region = us-east-1
services = service-endpoints
ignore_configured_endpoint_urls = true

[profile missing-services]
region = us-east-1
services = nonexistent
endpoint_url = {GLOBAL_ENDPOINT}

[profile local]
region = us-east-1
services = local-endpoints

[services default-services]
s3 =
  endpoint_url = {DEFAULT_ENDPOINT}

[services service-endpoints]
s3 =
  endpoint_url = {SERVICE_ENDPOINT}
sts =
  endpoint_url = https://sts.example.com/

[services local-endpoints]
s3 =
  endpoint_url = http://127.0.0.1:{server.server_port}/gateway/
"""
            )
            env.update(
                HOME=str(directory),
                AWS_CONFIG_FILE=str(config),
                AWS_SHARED_CREDENTIALS_FILE=str(credentials),
                AWS_EC2_METADATA_DISABLED="true",
                AWS_ACCESS_KEY_ID="endpoint-test-id",
                AWS_SECRET_ACCESS_KEY="endpoint-test-key",
                DUCKDB_AWS_ENDPOINT_TESTS_AVAILABLE="1",
                NO_PROXY="127.0.0.1,localhost,::1",
                no_proxy="127.0.0.1,localhost,::1",
            )
            cases = [
                ("default profile", {}, DEFAULT_ENDPOINT, SERVICE_ENDPOINT),
                ("AWS_PROFILE", {"AWS_PROFILE": "global"}, GLOBAL_ENDPOINT, SERVICE_ENDPOINT),
                ("service overrides profile endpoint", {"AWS_PROFILE": "service"}, SERVICE_ENDPOINT, SERVICE_ENDPOINT),
                ("AWS_DEFAULT_PROFILE", {"AWS_DEFAULT_PROFILE": "global"}, GLOBAL_ENDPOINT, SERVICE_ENDPOINT),
                (
                    "SDK profile precedence when both environment variables are set",
                    {"AWS_PROFILE": "global", "AWS_DEFAULT_PROFILE": "service"},
                    SERVICE_ENDPOINT,
                    SERVICE_ENDPOINT,
                ),
                (
                    "global environment overrides profile",
                    {"AWS_ENDPOINT_URL": "http://env.example.com:8000/"},
                    "http://env.example.com:8000/",
                    "http://env.example.com:8000/",
                ),
                (
                    "service environment overrides global environment",
                    {
                        "AWS_ENDPOINT_URL": "http://env.example.com/",
                        "AWS_ENDPOINT_URL_S3": "https://s3-env.example.com/",
                    },
                    "https://s3-env.example.com/",
                    "https://s3-env.example.com/",
                ),
                (
                    "blank service environment falls through",
                    {"AWS_ENDPOINT_URL_S3": "", "AWS_ENDPOINT_URL": "http://env.example.com/"},
                    "http://env.example.com/",
                    "http://env.example.com/",
                ),
                ("no configured endpoint", {"AWS_PROFILE": "empty"}, FALLBACK_ENDPOINT, SERVICE_ENDPOINT),
                (
                    "missing services falls through",
                    {"AWS_PROFILE": "missing-services"},
                    GLOBAL_ENDPOINT,
                    SERVICE_ENDPOINT,
                ),
                ("profile ignore flag", {"AWS_PROFILE": "ignored"}, FALLBACK_ENDPOINT, SERVICE_ENDPOINT),
                (
                    "profile ignore flag suppresses environment endpoints",
                    {"AWS_PROFILE": "ignored", "AWS_ENDPOINT_URL_S3": "https://s3-env.example.com/"},
                    FALLBACK_ENDPOINT,
                    "https://s3-env.example.com/",
                ),
                (
                    "false environment ignore flag",
                    {"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false"},
                    DEFAULT_ENDPOINT,
                    SERVICE_ENDPOINT,
                ),
                (
                    "environment ignore flag",
                    {
                        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
                        "AWS_ENDPOINT_URL_S3": "https://ignored.example.com/",
                    },
                    FALLBACK_ENDPOINT,
                    FALLBACK_ENDPOINT,
                ),
            ]
            for name, settings, expected, profile_expected in cases:
                print(f"\n=== {name} ===", flush=True)
                case_env = dict(env, **settings)
                case_env.update(
                    AWS_TEST_ENDPOINT_EXPECTED=expected,
                    AWS_TEST_ENDPOINT_PROFILE_EXPECTED=profile_expected,
                )
                if not run_test(unittest, "test/sql/env/aws_secret_endpoints_env.test", case_env, directory):
                    failures.append(name)

            print("\n=== local HTTP endpoint with port and base path ===", flush=True)
            local_env = dict(
                env,
                AWS_PROFILE="local",
                AWS_TEST_ENDPOINT_EXPECTED=f"http://127.0.0.1:{server.server_port}/gateway/",
            )
            local_passed = run_test(unittest, "test/sql/env/aws_secret_endpoints_http.test", local_env, directory)
            # A request alone proves nothing: require an actual successful read of
            # the expected object, even if the SQL test runner reports success.
            expected_read = ("GET", "/gateway/test-bucket/endpoint.csv", 200)
            if not local_passed or expected_read not in server.requests:
                print(f"Local HTTP requests: {server.requests}")
                failures.append("local HTTP endpoint")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    if failures:
        print(f"\nFailed endpoint cases: {', '.join(failures)}")
        return 1
    print(f"\nAll {len(cases) + 1} endpoint cases passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
