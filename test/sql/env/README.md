# Env tests
These tests should be run with the following env:

```sh
export DUCKDB_AWS_TESTING_ENV_AVAILABLE=1
export AWS_ACCESS_KEY_ID=duckdb_env_testing_id
export AWS_SECRET_ACCESS_KEY=duckdb_env_testing_key
export AWS_DEFAULT_REGION=duckdb_env_testing_region
```

## Rotated credentials file

`aws_default_secret_rotated_credentials_file.test` rewrites a credentials file to check that the
default secrets follow a rotation. It only writes to the file declared scratch, and the default
chain must get to that file (no `AWS_ACCESS_KEY_ID`, no `AWS_PROFILE`):

```sh
export DUCKDB_AWS_SCRATCH_CREDENTIALS_FILE=/some/scratch/credentials
export AWS_SHARED_CREDENTIALS_FILE=$DUCKDB_AWS_SCRATCH_CREDENTIALS_FILE
build/release/test/unittest test/sql/env/aws_default_secret_rotated_credentials_file.test
```
