# Env tests
These tests should be run with the following env:

```sh
export DUCKDB_AWS_TESTING_ENV_AVAILABLE=1
export AWS_ACCESS_KEY_ID=duckdb_env_testing_id
export AWS_SECRET_ACCESS_KEY=duckdb_env_testing_key
export AWS_DEFAULT_REGION=duckdb_env_testing_region
```

## Configured S3 endpoints

After building the extension and test dependencies, run:

```sh
python3 scripts/run_aws_endpoint_tests.py
```

This runs the endpoint precedence tests in separate processes with temporary AWS
config and credentials files and dummy credentials. It also reads a CSV from a
local HTTP server using an endpoint resolved from AWS config. It does not modify
`~/.aws` or require access to AWS. Use `--unittest /path/to/unittest` to test another
build.

Configured endpoint resolution currently applies to `TYPE s3`. Explicit SQL
`ENDPOINT` options take precedence; HTTP/HTTPS schemes, ports, and base paths are
preserved for httpfs. Addressing-style settings in AWS config are not imported:
use `URL_STYLE 'path'` explicitly when required by your S3-compatible service.
