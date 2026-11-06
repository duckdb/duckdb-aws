from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import generate_aws_secret


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
CREDENTIALS = {
    "AccessKeyId": "test-key-id",
    "SecretAccessKey": "test-secret'quoted",
    "SessionToken": "test-session-token",
    "Expiration": (NOW + timedelta(minutes=15)).isoformat(),
}
ENVIRONMENT = {"AWS_PROFILE": "test-profile", "AWS_REGION": "eu-central-1"}


class GenerateAwsSecretTests(unittest.TestCase):
    def invoke(self, result, arguments=("--force",), environment=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, ENVIRONMENT if environment is None else environment, clear=True),
            patch("quack_redshift.run_command") as command,
            patch.object(generate_aws_secret, "datetime", wraps=datetime) as clock,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            clock.now.return_value = NOW
            if isinstance(result, Exception):
                command.side_effect = result
            else:
                command.return_value = result
            status = generate_aws_secret.main(list(arguments))
        return status, stdout.getvalue(), stderr.getvalue(), command

    def exported(self, credentials):
        return subprocess.CompletedProcess([], 0, json.dumps(credentials), "")

    def test_sql_only_output_uses_selected_profile_and_escapes_values(self):
        environment = {
            **ENVIRONMENT,
            "AWS_ACCESS_KEY_ID": "unrelated-key",
            "AWS_SECRET_ACCESS_KEY": "unrelated-secret",
            "AWS_SESSION_TOKEN": "unrelated-token",
            "AWS_DEFAULT_PROFILE": "unrelated-profile",
        }
        status, stdout, stderr, command = self.invoke(self.exported(CREDENTIALS), environment=environment)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(stdout, """CREATE OR REPLACE TEMPORARY SECRET aws_session_token (
    TYPE aws,
    PROVIDER config,
    KEY_ID 'test-key-id',
    SECRET 'test-secret''quoted',
    SESSION_TOKEN 'test-session-token',
    REGION 'eu-central-1'
);
""")
        command.assert_called_once()
        arguments, environment, _ = command.call_args.args
        self.assertIn("configure", arguments)
        self.assertIn("export-credentials", arguments)
        self.assertEqual(arguments[arguments.index("--profile") + 1], "test-profile")
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_PROFILE"):
            self.assertNotIn(key, environment)

    def test_preview_does_not_export_or_print_sql(self):
        status, stdout, stderr, command = self.invoke(None, arguments=(), environment={})
        self.assertEqual(status, 0)
        self.assertEqual(stdout, "")
        self.assertIn("FORCE=1", stderr)
        command.assert_not_called()

    def test_missing_configuration_stops_before_export(self):
        for environment in ({}, {"AWS_PROFILE": "test-profile"}, {"AWS_REGION": "eu-central-1"}):
            with self.subTest(environment=environment):
                status, stdout, stderr, command = self.invoke(None, environment=environment)
                self.assertEqual(status, 1)
                self.assertEqual(stdout, "")
                self.assertIn("Set AWS_PROFILE and AWS_REGION", stderr)
                command.assert_not_called()

    def test_rejects_invalid_credentials_without_printing_them(self):
        invalid = [None, [], {}, {**CREDENTIALS, "AccessKeyId": 42}]
        invalid.extend({key: value for key, value in CREDENTIALS.items() if key != missing} for missing in CREDENTIALS)
        invalid.extend({**CREDENTIALS, field: value} for field in CREDENTIALS for value in (None, ""))
        invalid.extend({**CREDENTIALS, "Expiration": expiration} for expiration in (
            None, "", "test-session-token", "2026-01-01T00:15:00",
            (NOW - timedelta(seconds=1)).isoformat(), NOW.isoformat(),
            (NOW + timedelta(seconds=901)).isoformat(),
        ))
        for index, credentials in enumerate(invalid):
            with self.subTest(case=index):
                status, stdout, stderr, _ = self.invoke(self.exported(credentials))
                self.assertEqual(status, 1)
                self.assertEqual(stdout, "")
                self.assertTrue(stderr.startswith("error:"))
                for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                    self.assertNotIn(CREDENTIALS[field], stderr)

    def test_cli_failures_do_not_leak_raw_output(self):
        raw = json.dumps(CREDENTIALS)
        failures = (
            subprocess.CompletedProcess([], 1, raw, f"(AccessDenied) {raw}"),
            subprocess.CompletedProcess([], 1, raw, f"({CREDENTIALS['SessionToken']}) {raw}"),
            subprocess.CompletedProcess([], 0, f"invalid-json {raw}", ""),
            subprocess.TimeoutExpired(["aws"], 90, output=raw, stderr=raw),
            OSError(raw),
        )
        for index, failure in enumerate(failures):
            with self.subTest(case=index):
                status, stdout, stderr, _ = self.invoke(failure)
                self.assertEqual(status, 1)
                self.assertEqual(stdout, "")
                self.assertTrue(stderr.startswith("error:"))
                for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                    self.assertNotIn(CREDENTIALS[field], stderr)


if __name__ == "__main__":
    unittest.main()
