# Redshift Tests

These tests connect to a provisioned Redshift cluster through the `aws` extension.

## Cluster lifecycle

The cluster runs until it is deleted and may incur AWS charges.

The cluster name is `$PREFIX-redshift-$AWS_REGION`. Rerunning the script reuses a cluster with the same name. Set `PREFIX` to share a cluster or create a separate one.

### Create a test cluster

From the repository root:

```bash
./scripts/redshift/create_cluster.sh --force
source test/sql/redshift/redshift.env
```

Without `--force`, the script prints the creation plan. With `--force`, it creates the cluster, IAM role, security group, and TICKIT data.

The script writes the cluster settings and AWS profile settings to `test/sql/redshift/redshift.env`. Set `REDSHIFT_ENV_FILE` to use another path.

Defaults:

- `PREFIX`: local username
- `AWS_REGION`: `eu-central-1`
- `AWS_REDSHIFT_DATABASE`: `dev`
- `AWS_CONFIG_FILE`: `~/.aws/config`
- `AWS_SHARED_CREDENTIALS_FILE`: `~/.aws/credentials`

The script uses `AWS_PROFILE`, then `AWS_DEFAULT_PROFILE`. If neither is set, it uses `default` or the only configured profile. Set `AWS_PROFILE` when several non-default profiles exist.

#### TICKIT sample data

The script loads AWS's [TICKIT sample database](https://docs.aws.amazon.com/redshift/latest/dg/c_sampledb.html), a fictional online ticket-sales dataset. It uses Redshift `COPY` commands to read the public files at `s3://redshift-downloads/tickit` in `us-east-1` and creates the seven standard tables: `users`, `venue`, `category`, `date`, `event`, `listing`, and `sales`.

The dedicated Redshift IAM role has only `s3:GetObject` and `s3:ListBucket` permissions on `redshift-downloads`. The script only reads from this public bucket. Later runs skip the data load when all seven tables exist.

### Destroy a test cluster

After testing, remove the cluster and its supporting resources:

```bash
./scripts/redshift/destroy_cluster.sh --force
```

Without `--force`, the script prints the deletion plan. The cluster is deleted without a final snapshot.

## Run tests

### Build `postgres_scanner` locally

Redshift tests require `postgres_scanner`. Uncomment its `duckdb_extension_load` block in `extension_config.cmake` and rebuild the extension. Do not commit that local change.

Create the cluster and source `redshift.env` before running the tests.

Run all Redshift tests:

```bash
source test/sql/redshift/redshift.env && ./build/release/test/unittest "test/sql/redshift/*"
```

The cluster-ID and pinned-host tests use the selected credential-chain profile and `AWS_REDSHIFT_DATABASE` from `redshift.env`. `redshift_arn_attach.test` discovers the cluster database and also requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

`redshift_arn_attach_credential_chain.test` attaches through `AWS_REDSHIFT_ARN` using an `s3` secret built with `PROVIDER credential_chain`.

### Interactive DuckDB sessions

Start DuckDB with unsigned extension loading enabled:

```bash
./build/release/duckdb -unsigned
```

Then load the locally built `postgres_scanner` extension:

```sql
LOAD './build/release/extension/postgres_scanner/postgres_scanner.duckdb_extension';
```
