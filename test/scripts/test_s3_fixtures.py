import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = [
    "scripts/s3/create_bucket.sh",
    "scripts/s3/destroy_bucket.sh",
    "scripts/s3tables/create_s3tables_test_fixture.sh",
    "scripts/s3tables/destroy_s3tables_test_fixture.sh",
]
LOCAL_DUCKDB = shutil.which(os.environ.get("DUCKDB_BIN", "duckdb")) or shutil.which(str(ROOT / "build/release/duckdb"))

AWS_STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
state = Path(os.environ["AWS_STATE_DIR"])
state.mkdir(exist_ok=True)
with open(os.environ["AWS_CALL_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")

def option(name):
    return args[args.index(name) + 1]

def emit(value):
    print(json.dumps(value))
    sys.exit(0)

def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)

if "export-credentials" in args:
    if os.environ.get("FAIL_EXPORT"):
        fail("Profile login expired")
    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_SESSION_TOKEN"):
        fail("Stale environment credentials reached profile export")
    emit({"AccessKeyId": "fixture-key", "SecretAccessKey": "fixture-secret",
          "SessionToken": os.environ.get("TOKEN", "fixture-token+/="), "Version": 1})
if "list-profiles" in args:
    print("fixture-profile")
    sys.exit(0)
if "get-caller-identity" in args:
    if "--query" in args:
        print("123456789012")
        sys.exit(0)
    emit({"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test"})
if "s3api" in args:
    cmd = args[args.index("s3api") + 1]
    if cmd == "head-bucket":
        if os.environ.get("HEAD_ERROR"):
            fail(os.environ["HEAD_ERROR"])
        if os.environ.get("NEW_FIXTURE") and not (state / "bucket").exists():
            fail("An error occurred (404): Not Found")
        sys.exit(0)
    if cmd == "get-bucket-tagging":
        emit({"TagSet": [{"Key": "ManagedBy", "Value": os.environ.get("STUB_MANAGED_BY", "duckdb-aws-s3-test")},
                         {"Key": "Project", "Value": "duckdb-aws"}]})
    if cmd == "get-bucket-location":
        emit({"LocationConstraint": os.environ.get("BUCKET_REGION", "eu-central-1")})
    if cmd == "get-bucket-versioning":
        emit({"Status": "Suspended"} if os.environ.get("VERSIONED") else {})
    if cmd == "list-objects-v2":
        emit({"Contents": [{"Key": "keep-me.txt"}]} if os.environ.get("UNRELATED") else {})
    if cmd == "head-object":
        if os.environ.get("OBJECT_ERROR"):
            fail(os.environ["OBJECT_ERROR"])
        emit({"ContentLength": 123})
    if cmd.startswith(("put-", "delete-", "create-")):
        if cmd == "create-bucket":
            (state / "bucket").touch()
        if cmd == "put-bucket-cors":
            Path(os.environ["CORS_RESULT"]).write_text(option("--cors-configuration"))
        emit({})
if "s3tables" in args:
    cmd = args[args.index("s3tables") + 1]
    bucket = "arn:aws:s3tables:eu-central-1:123456789012:bucket/test-bucket"
    if cmd == "help":
        sys.exit(0)
    if cmd == "get-table-bucket" and os.environ.get("LOOKUP_ERROR"):
        fail(os.environ["LOOKUP_ERROR"])
    resource = {"get-table-bucket": "table-bucket", "get-namespace": "namespace", "get-table": "table"}.get(cmd)
    if resource and os.environ.get("NEW_FIXTURE") and not (state / resource).exists():
        fail("NotFoundException")
    if cmd.startswith("create-"):
        (state / cmd.removeprefix("create-")).touch()
        emit({"tableARN": bucket + "/table/example"} if cmd == "create-table" else {})
    if cmd == "get-table-bucket":
        emit({"arn": bucket, "name": "test-bucket", "type": "customer"})
    if cmd == "get-namespace":
        emit({"namespace": ["123test"]})
    if cmd == "get-table":
        if os.environ.get("TABLE_ABSENT"):
            fail("NotFoundException")
        emit({"tableARN": bucket + "/table/example", "versionToken": "one", "name": "daily_sales",
              "namespace": ["123test"], "type": "customer", "format": "ICEBERG"})
    if cmd == "list-tags-for-resource":
        table = "/table/" in option("--resource-arn")
        owner = os.environ.get("STUB_MANAGED_BY", "duckdb-aws-s3tables-test")
        if table and os.environ.get("FOREIGN_TABLE"):
            owner = "someone-else"
        emit({"tags": {"ManagedBy": owner,
                       "FixtureId": "s3tables-sql-fixture-v1", "Prefix": "tester", "Region": "eu-central-1",
                       "ResourceName": "daily_sales" if table else "test-bucket",
                       "TableBucket": "test-bucket", "Namespace": "123test"}})
    if cmd == "list-tables":
        emit({"tables": [{"namespace": ["123test"], "name": "keep_me"}]} if os.environ.get("UNRELATED") else {"tables": []})
    if cmd == "list-namespaces":
        emit({"namespaces": []})
    if cmd.startswith("delete-"):
        emit({})
fail("Unexpected AWS command: " + str(args))
'''


class FixtureScriptsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.log = self.directory / "calls.jsonl"
        self.env_file = self.directory / "fixture.env"
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("AWS_", "S3_", "S3TABLES_"))
        }
        self.env.update({
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "AWS_PROFILE": "fixture-profile",
            "AWS_REGION": "eu-central-1",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CALL_LOG": str(self.log),
            "AWS_STATE_DIR": str(self.directory / "state"),
            "CORS_RESULT": str(self.directory / "cors.json"),
            "PREFIX": "tester",
            "S3_BUCKET_NAME": "test-bucket",
            "S3_ENV_FILE": str(self.env_file),
            "S3TABLES_TABLE_BUCKET_NAME": "test-bucket",
            "S3TABLES_NAMESPACE": "123test",
            "S3TABLES_ENV_FILE": str(self.env_file),
            "DUCKDB_BIN": str(self.bin / "duckdb"),
            "SQL_CAPTURE": str(self.directory / "sql.txt"),
        })
        self.stub("aws", AWS_STUB)
        self.stub("duckdb", '#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\nPath(os.environ["SQL_CAPTURE"]).write_text(sys.argv[-1])\n')
        self.stub("curl", '#!/usr/bin/env bash\necho "Unexpected download" >&2\nexit 99\n')

    def stub(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def run_script(self, script, *args, **overrides):
        return subprocess.run(
            ["bash", str(ROOT / script), *args], cwd=ROOT,
            env={**self.env, **overrides}, capture_output=True, text=True, timeout=20,
        )

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def mutations(self):
        return [args for args in self.calls() if any(arg.startswith(("put-", "create-", "delete-")) for arg in args)]

    def test_help_dry_run_and_invalid_arguments_never_call_aws(self):
        for script in SCRIPTS:
            for args, succeeds in [((), True), (("--help",), True), (("--invalid",), False)]:
                with self.subTest(script=script, args=args):
                    result = self.run_script(script, *args)
                    self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                    self.assertEqual(self.calls(), [])

    def test_ordinary_bucket_refuses_unsafe_resources(self):
        cases = [
            {"STUB_MANAGED_BY": "someone-else"},
            {"BUCKET_REGION": "us-east-1"},
            {"VERSIONED": "1"},
            {"HEAD_ERROR": "An error occurred (403): AccessDenied"},
            {"HEAD_ERROR": "Network timed out"},
        ]
        for script in SCRIPTS[:2]:
            for case in cases:
                with self.subTest(script=script, case=case):
                    result = self.run_script(script, "--force", **case)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.mutations(), [])
        result = self.run_script(SCRIPTS[1], "--force", UNRELATED="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_bucket_creation_uses_regional_configuration(self):
        for region in ["us-east-1", "eu-central-1"]:
            with self.subTest(region=region):
                call_count = len(self.calls())
                result = self.run_script(
                    SCRIPTS[0], "--force", NEW_FIXTURE="1", AWS_REGION=region,
                    AWS_STATE_DIR=str(self.directory / region),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                creations = [args for args in self.calls()[call_count:] if "create-bucket" in args]
                self.assertEqual(len(creations), 1)
                self.assertEqual("--create-bucket-configuration" in creations[0], region != "us-east-1")
                if region != "us-east-1":
                    self.assertIn(f"LocationConstraint={region}", creations[0])
                self.assertTrue(self.env_file.exists())

    def test_bucket_setup_writes_cors_and_refreshable_secret_free_config(self):
        result = self.run_script(SCRIPTS[0], "--force", AWS_ACCESS_KEY_ID="stale", AWS_SESSION_TOKEN="stale")
        self.assertEqual(result.returncode, 0, result.stderr)
        config = self.env_file.read_text()
        for credential in ["fixture-key", "fixture-secret", "fixture-token", "stale"]:
            self.assertNotIn(credential, config)
            self.assertNotIn(credential, result.stdout + result.stderr)
        self.assertEqual(self.env_file.stat().st_mode & 0o777, 0o600)
        rule = json.loads((self.directory / "cors.json").read_text())["CORSRules"][0]
        self.assertIn("http://127.0.0.1:*", rule["AllowedOrigins"])
        self.assertIn("http://localhost", rule["AllowedOrigins"])
        self.assertIn("x-amz-*", rule["AllowedHeaders"])
        self.assertIn("amz-sdk-*", rule["AllowedHeaders"])
        self.assertIn("x-host-override", rule["AllowedHeaders"])
        for shell in [name for name in ["bash", "zsh"] if shutil.which(name)]:
            with self.subTest(shell=shell):
                source = subprocess.run(
                    [shell, "-c", 'source "$1" && [[ "$S3_TEST_AVAILABLE" == 1 && "$AWS_SESSION_TOKEN" == "fixture-token+/=" ]]', shell, str(self.env_file)],
                    env=self.env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(source.returncode, 0, source.stderr)
        result = self.run_script(SCRIPTS[1], "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.env_file.exists())
        deletion = [arg for args in self.calls() for arg in args if arg.startswith("delete-")]
        self.assertEqual(deletion, ["delete-object", "delete-object", "delete-bucket"])

    def test_bad_credentials_stop_before_any_resource_operation(self):
        for token in ["first\nsecond", "trailing\n", "first\rsecond"]:
            with self.subTest(token=repr(token)):
                result = self.run_script(SCRIPTS[0], "--force", TOKEN=token)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(token, result.stdout + result.stderr)
                self.assertFalse(self.env_file.exists())
                self.assertEqual(self.mutations(), [])
        self.assertFalse(any("s3api" in args for args in self.calls()))

    def test_refresh_failure_clears_existing_test_guard(self):
        result = self.run_script(SCRIPTS[0], "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(
            ["bash", "-c", 'export S3_TEST_AVAILABLE=1; source "$1"; status=$?; [[ "$status" != 0 && -z "${S3_TEST_AVAILABLE:-}" ]]', "bash", str(self.env_file)],
            env={**self.env, "FAIL_EXPORT": "1"}, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_download_cannot_upload_partial_railway_object(self):
        result = self.run_script(SCRIPTS[0], "--force", OBJECT_ERROR="An error occurred (404): Not Found")
        self.assertNotEqual(result.returncode, 0)
        uploads = [args for args in self.calls() if "put-object" in args]
        self.assertEqual(len(uploads), 1)
        self.assertIn("duckdb-fixture/data.csv.gz", uploads[0])
        self.assertFalse(self.env_file.exists())

    def test_static_profile_refresh_removes_stale_session_token(self):
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; fixture_credentials && [[ -z "$AWS_SESSION_TOKEN" && "$AWS_ACCESS_KEY_ID" == "fixture-key" ]]', "bash", str(ROOT / "scripts/test_aws_credentials.sh")],
            env={**self.env, "TOKEN": "", "AWS_SESSION_TOKEN": "stale-token"},
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_tables_refuse_foreign_tags(self):
        for script in SCRIPTS[2:]:
            for case in [{"STUB_MANAGED_BY": "someone-else"}, {"FOREIGN_TABLE": "1"}]:
                with self.subTest(script=script, case=case):
                    result = self.run_script(script, "--force", **case)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.mutations(), [])

    def test_tables_bucket_lookup_errors_stop_before_mutation(self):
        for script in SCRIPTS[2:]:
            for error in ["AccessDeniedException", "Network timed out"]:
                with self.subTest(script=script, error=error):
                    result = self.run_script(script, "--force", LOOKUP_ERROR=error)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)
                    self.assertEqual(self.mutations(), [])
                    self.assertFalse(self.env_file.exists())

    def test_tables_first_setup_creates_dependencies_and_sourceable_config(self):
        self.env_file = self.directory / "config with 'quotes'.env"
        result = self.run_script(SCRIPTS[2], "--force", NEW_FIXTURE="1", S3TABLES_ENV_FILE=str(self.env_file))
        self.assertEqual(result.returncode, 0, result.stderr)
        creation = [arg for args in self.calls() for arg in args if arg.startswith("create-")]
        self.assertEqual(creation, ["create-table-bucket", "create-namespace", "create-table"])
        self.assertEqual(self.env_file.stat().st_mode & 0o777, 0o600)
        for shell in [name for name in ["bash", "zsh"] if shutil.which(name)]:
            with self.subTest(shell=shell):
                source = subprocess.run(
                    [shell, "-c", 'source "$1" && [[ "$S3TABLES_TEST_AVAILABLE" == 1 && "$AWS_S3TABLES_NAMESPACE" == 123test && "$S3TABLES_ENV_FILE" == "$1" ]]', shell, str(self.env_file)],
                    env=self.env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(source.returncode, 0, source.stderr)

    @unittest.skipUnless(LOCAL_DUCKDB, "Local DuckDB executable required for SQL validation")
    def test_tables_row_check_rejects_bad_data(self):
        result = self.run_script(SCRIPTS[2], "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        sql = (self.directory / "sql.txt").read_text()
        row_check = next(statement for statement in sql.split(";") if "Unexpected rows in the managed S3 Tables fixture" in statement)
        expected = [
            "(DATE '2020-07-21', 'SHOES', 21)",
            "(DATE '2020-07-22', 'JACKET', 3)",
            "(DATE '2020-07-24', 'SOCKS', 87)",
        ]
        cases = [
            ("exact", expected, True),
            ("reordered", expected[::-1], True),
            ("empty", [], False),
            ("missing", expected[:2], False),
            ("duplicate replacing row", [expected[0], expected[0], expected[2]], False),
            ("extra duplicate", expected + [expected[0]], False),
            ("wrong value", [expected[0].replace("SHOES", "BOOTS"), *expected[1:]], False),
            ("null", [expected[0].replace("'SHOES'", "NULL"), *expected[1:]], False),
        ]
        for name, rows, succeeds in cases:
            with self.subTest(rows=name):
                setup = '''
                    SET enable_external_access=false;
                    ATTACH ':memory:' AS s3tables_fixture;
                    CREATE SCHEMA s3tables_fixture."123test";
                    CREATE TABLE s3tables_fixture."123test".daily_sales (
                        sale_date DATE, product VARCHAR, quantity INTEGER
                    );
                '''
                if rows:
                    setup += 'INSERT INTO s3tables_fixture."123test".daily_sales VALUES ' + ", ".join(rows) + ";"
                checked = subprocess.run(
                    [LOCAL_DUCKDB, "-batch", "-bail", "-no-init", "-c", setup + row_check + ";"],
                    capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(checked.returncode == 0, succeeds, checked.stderr)
                if not succeeds:
                    self.assertIn("Unexpected rows in the managed S3 Tables fixture", checked.stderr)

    def test_tables_partial_cleanup_disables_environment(self):
        for absent in ["", "1"]:
            with self.subTest(already_absent=absent):
                result = self.run_script(SCRIPTS[2], "--force")
                self.assertEqual(result.returncode, 0, result.stderr)
                sql = (self.directory / "sql.txt").read_text()
                self.assertIn('s3tables_fixture."123test"."daily_sales"', sql)
                self.assertIn("CHAIN 'env'", sql)
                self.assertNotIn("fixture-secret", self.env_file.read_text())
                result = self.run_script(SCRIPTS[3], "--force", UNRELATED="1", TABLE_ABSENT=absent)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.env_file.exists())
                self.assertFalse(any("delete-namespace" in args or "delete-table-bucket" in args for args in self.calls()))

    def test_tables_cleanup_orders_dependencies(self):
        result = self.run_script(SCRIPTS[2], "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script(SCRIPTS[3], "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        deletion = [arg for args in self.calls() for arg in args if arg.startswith("delete-")]
        self.assertEqual(deletion, ["delete-table", "delete-namespace", "delete-table-bucket"])
        self.assertFalse(self.env_file.exists())


if __name__ == "__main__":
    unittest.main()
