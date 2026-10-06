# Redshift Tests

These tests connect to a provisioned Redshift cluster through the `aws` extension.

## Cluster lifecycle

The cluster does not expire or stop automatically. It keeps running, and may continue to incur AWS charges, until the cleanup script removes it with its IAM role and security group.

The cluster name is `$PREFIX-redshift-$AWS_REGION`. Cluster creation is idempotent: rerunning the script reuses a cluster with the same name. Different usernames create separate clusters. Users share a cluster only when they use the existing `PREFIX` and region. Set `PREFIX` explicitly to choose shared or isolated clusters.

### Create a test cluster

From the repository root:

```bash
./scripts/create_redshift_test_cluster.sh
source test/sql/redshift/redshift.env
```

The script creates the cluster, its IAM role and security group, and the TICKIT sample data. It writes `AWS_REDSHIFT_CLUSTER_NAME`, `AWS_REDSHIFT_ARN`, `AWS_REDSHIFT_HOST`, `AWS_REDSHIFT_DATABASE`, and `AWS_REGION` to `test/sql/redshift/redshift.env`. `AWS_REGION` is the region selected for the cluster. Set `REDSHIFT_ENV_FILE` to write these variables elsewhere.

By default, `PREFIX` is the local Unix account name returned by `id -un`, and `AWS_REDSHIFT_DATABASE` is `dev`. `AWS_REGION` defaults to `eu-central-1`. Set `PREFIX` explicitly to override it, for example: `PREFIX=my-test-cluster ./scripts/create_redshift_test_cluster.sh`.

#### TICKIT sample data

The script loads AWS's [TICKIT sample database](https://docs.aws.amazon.com/redshift/latest/dg/c_sampledb.html), a fictional online ticket-sales dataset. It uses Redshift `COPY` commands to read the public files at `s3://redshift-downloads/tickit` in `us-east-1` and creates the seven standard tables: `users`, `venue`, `category`, `date`, `event`, `listing`, and `sales`.

The dedicated Redshift IAM role has only `s3:GetObject` and `s3:ListBucket` permissions on `redshift-downloads`. The script only reads from this public bucket. Later runs skip the data load when all seven tables exist.

### Destroy a test cluster

After testing, remove the cluster and its supporting resources:

```bash
./scripts/destroy_redshift_test_cluster.sh
```

## Run tests

### Build `postgres_scanner` locally

Redshift tests require `postgres_scanner`. The `duckdb_extension_load(postgres_scanner ...)` block in `extension_config.cmake` is commented out because CI cannot build it. For local Redshift development or testing, uncomment the entire block, rebuild the extension, and do not commit that local change.

Build the extension, then set the AWS profile and credentials for the tests:

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

The cluster-ID and pinned-host tests use the selected credential-chain profile and `AWS_REDSHIFT_DATABASE` from `redshift.env`. `redshift_arn_attach.test` discovers the cluster database and also requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

### Interactive DuckDB sessions

Start DuckDB with unsigned extension loading enabled:

```bash
./build/release/duckdb -unsigned
```

Then load the locally built `postgres_scanner` extension:

```sql
LOAD './build/release/extension/postgres_scanner/postgres_scanner.duckdb_extension';
```
