# Redshift Tests

These tests connect to a provisioned Redshift cluster through the `aws` extension.

## Create a test cluster

From the repository root:

```bash
./scripts/create_redshift_test_cluster.sh
source test/sql/redshift/redshift.env
```

The script creates a cluster, IAM role, security group, and TICKIT sample data.
It overwrites `test/sql/redshift/redshift.env` with
`AWS_REDSHIFT_CLUSTER_NAME`, `AWS_REDSHIFT_ARN`, `AWS_REDSHIFT_HOST`, and
`AWS_REDSHIFT_DATABASE`. Set `REDSHIFT_ENV_FILE` to use another path.

Resources use your username as `PREFIX`, `eu-central-1` as
`AWS_DEFAULT_REGION`, and `dev` as `AWS_REDSHIFT_DATABASE` unless overridden.

## Run tests

Build the extension, then configure the AWS profile and credentials used by the tests:

```bash
export AWS_CONFIG_FILE="$HOME/.aws/config"
export AWS_SHARED_CREDENTIALS_FILE="$HOME/.aws/credentials"
export AWS_PROFILE=<profile-name>
export AWS_ACCESS_KEY_ID=<your_key>
export AWS_SECRET_ACCESS_KEY=<your_secret>
```

Run all Redshift tests:

```bash
source test/sql/redshift/redshift.env && ./build/release/test/unittest "test/sql/redshift/*"
```

The cluster-ID and pinned-host tests use the selected credential-chain profile
and `AWS_REDSHIFT_DATABASE` from `redshift.env`.
`redshift_arn_attach.test` discovers the cluster database and also requires
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

`postgres_scanner` is a loadable extension. For an interactive DuckDB session,
start `./build/release/duckdb -unsigned` and run:

```sql
LOAD './build/release/extension/postgres_scanner/postgres_scanner.duckdb_extension';
```

## Destroy cluster

Destroy the temporary cluster and its supporting resources after testing:

```bash
./scripts/destroy_redshift_test_cluster.sh
```
