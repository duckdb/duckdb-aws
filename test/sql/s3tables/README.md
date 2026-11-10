# S3 Tables

`s3tables_table_buckets`, `s3tables_namespaces` and `s3tables_tables` browse the S3 Tables control
plane; `s3tables_create_table_bucket`, `s3tables_get_table_bucket`, `s3tables_table_bucket_tags` and
`s3tables_delete_table_bucket` manage a table bucket; `aws:s3tables:table-bucket` is the matching
external-resource type, a catalog, so `ATTACH TO EXTERNAL RESOURCE` works on it. A table bucket
also attaches directly by ARN: `ATTACH 'arn:aws:s3tables:...' AS db`, through the iceberg extension.
The rest of this file covers the tests and the table bucket fixture they run against. The
generated function reference is in the [repository README](../../../README.md#s3-buckets-and-s3-tables).
General-purpose S3 buckets, a different product with its own functions and fixture, are in the
[S3 buckets README](../s3/README.md).

## Functions

Sign in first: `aws login --profile <name>`, and export `AWS_PROFILE` and `AWS_REGION`. Attaching
needs the iceberg extension: `INSTALL iceberg;` once.

```shell
./build/release/duckdb -unsigned \
  -cmd "LOAD '$PWD/build/release/extension/aws/aws.duckdb_extension';"
```

```sql
CREATE SECRET (TYPE s3, PROVIDER credential_chain, REGION 'eu-central-1');
FROM s3tables_table_buckets('eu-central-1');
FROM s3tables_create_table_bucket('my-duckdb-table-bucket', region := 'eu-central-1');
FROM s3tables_get_table_bucket('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-duckdb-table-bucket');
FROM s3tables_table_bucket_tags('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-duckdb-table-bucket');
FROM s3tables_namespaces('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-duckdb-table-bucket');
FROM s3tables_delete_table_bucket('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-duckdb-table-bucket', cascade := true);
```

The first call lists the region's table buckets; the create returns one row with the new `arn`
(use it in place of the example ARN above), the tags call shows `created-by = duckdb`, the
namespaces call returns no rows for a new bucket, and the delete returns `status = deleted`.

## Tests

```shell
./build/release/test/unittest 'test/sql/s3tables/*'
```

Without the fixture environment, `s3tables_functions.test` (ARN and argument validation) and
`s3tables_resource.test` (the `aws:s3tables:table-bucket` type and its callbacks) run; every AWS
call in them is made with a key that cannot resolve and expected to fail. After
`source test/sql/s3tables/s3tables.env` (see [Create the fixture](#create-the-fixture)),
`s3tables.test` attaches the fixture table bucket and reads its table. The `s3tables_*`
lifecycle functions have no AWS-backed test yet.

## Fixture

`s3tables.test` connects to a real Amazon S3 Tables table bucket. The fixture
scripts create a dedicated, prefix- and region-scoped table bucket containing
one namespace and one Apache Iceberg table:

```text
<prefix>-duckdb-s3tables-test-<region>
└── test
    └── daily_sales
```

The defaults are `test.daily_sales`; `S3TABLES_NAMESPACE` and
`S3TABLES_TABLE` can override them. The SQL test does not hardcode these names,
the AWS account, region, or table-bucket ARN.

### Prerequisites

- A current AWS CLI v2 with the `aws s3tables` commands.
- `jq`.
- AWS credentials available to both the AWS CLI and DuckDB. Prefer temporary
  credentials, IAM Identity Center, or an assumed role rather than committed
  access keys.
- A DuckDB build containing the `aws`, `httpfs`, `iceberg`, `parquet`, `avro`,
  and `json` extensions. The create script defaults to
  `build/release/duckdb`; set `DUCKDB_BIN` to another compatible executable.

Amazon S3 Tables is regional. The scripts default to `eu-central-1`; set
`AWS_REGION` to a region in the current AWS
[S3 Tables endpoints and quotas list](https://docs.aws.amazon.com/general/latest/gr/s3-tables.html).
The SQL test currently supports listed regions whose S3 Tables endpoint uses
the standard `amazonaws.com` suffix. DuckDB's `ENDPOINT_TYPE s3_tables`
shorthand does not yet construct the `amazonaws.com.cn` endpoints required by
the `aws-cn` partition.

#### IAM permissions

The provisioning identity needs `sts:GetCallerIdentity` and these S3 Tables
actions:

```text
s3tables:CreateTableBucket
s3tables:GetTableBucket
s3tables:DeleteTableBucket
s3tables:CreateNamespace
s3tables:GetNamespace
s3tables:ListNamespaces
s3tables:DeleteNamespace
s3tables:CreateTable
s3tables:GetTable
s3tables:ListTables
s3tables:DeleteTable
s3tables:GetTableData
s3tables:PutTableData
s3tables:GetTableMetadataLocation
s3tables:UpdateTableMetadataLocation
s3tables:TagResource
s3tables:ListTagsForResource
```

Scope permissions to the fixture table-bucket ARN and its resources where the
action supports resource-level permissions. S3 Tables encrypts table data at
rest and uses TLS in transit. The fixture uses the service default
S3-managed encryption; if you change it to SSE-KMS, also grant the S3 Tables
maintenance principal the required KMS permissions.

For shared or production accounts, enable CloudTrail and relevant CloudWatch
monitoring for S3 Tables activity.

### Create the fixture

From the repository root, first inspect the dry-run plan:

```bash
./scripts/s3tables/create_s3tables_test_fixture.sh
```

Create the resources with the explicit force flag:

```bash
export AWS_PROFILE=my-test-profile
PREFIX="$(id -un)" AWS_REGION="eu-central-1" \
  ./scripts/s3tables/create_s3tables_test_fixture.sh --force
source test/sql/s3tables/s3tables.env
```

`PREFIX` must contain only lowercase letters, digits, and hyphens. If the
local username does not satisfy that rule, set a safe prefix explicitly. You
can also override the complete bucket name with
`S3TABLES_TABLE_BUCKET_NAME`.

The script creates the table bucket and table with exact management tags.
Existing resources are reused only when their identity and management tags
match. Namespaces do not support S3 Tables resource tags, so the script only
reuses the exact namespace inside the already verified dedicated table bucket.

The table is created with three required columns:

```text
sale_date DATE, product VARCHAR, quantity INTEGER
```

The create script verifies the existing schema, deletes the current rows,
inserts the deterministic dataset through DuckDB's Iceberg REST Catalog
integration, and verifies the final result. Rerunning the create command
therefore converges to exactly these rows without duplicates:

```text
2020-07-21  SHOES   21
2020-07-22  JACKET   3
2020-07-24  SOCKS   87
```

The generated, ignored `s3tables.env` contains only resource identifiers,
lifecycle inputs, credential selectors and the path to the local credential helper.
With `AWS_PROFILE` (or `AWS_DEFAULT_PROFILE`) selected, setup and each `source`
clear stale exported credentials and use `aws configure export-credentials` to
refresh that profile. With neither set, existing exported credentials are used,
otherwise the default or sole profile is selected. The helper never prints or
writes access keys or tokens. It rejects credentials containing line breaks.

The default `S3TABLES_AWS_CREDENTIAL_CHAIN=env` makes native DuckDB use those same
credentials, including session tokens. This also works with federated CLI login
profiles that the embedded SDK cannot read directly. Override the chain only if
DuckDB should use another credential source. Source the file again before later
test runs; environment-only credentials must be refreshed by the caller.
`S3TABLES_ENV_FILE` overrides the generated path. Regenerate the file if this
checkout moves.

Dry-run commands do not contact AWS. Provisioning, including population through
DuckDB, is only performed with `--force`. Do not run create or destroy concurrently.

### Run the test

```bash
source test/sql/s3tables/s3tables.env
./build/release/test/unittest test/sql/s3tables/s3tables.test
```

The `S3TABLES_TEST_AVAILABLE=1` guard is exported only after credentials load
successfully. Without it the test skips before extension loading or AWS calls.

### Destroy the fixture

Inspect the cleanup plan:

```bash
./scripts/s3tables/destroy_s3tables_test_fixture.sh
```

Delete the fixture with the same prefix and region used for creation:

```bash
source test/sql/s3tables/s3tables.env
./scripts/s3tables/destroy_s3tables_test_fixture.sh --force
unset S3TABLES_TEST_AVAILABLE
```

Cleanup verifies the exact table-bucket and table management tags, then
deletes the managed table, the exact fixture namespace, and the managed table
bucket in dependency order. If unrelated tables or namespaces are present,
the script stops and preserves them. Partially deleted fixtures are safe to
rerun. As soon as the managed table is deleted or confirmed absent, the
matching generated environment file is removed, even if unrelated resources
prevent the remaining namespace or table-bucket cleanup. Unset the guard in
shells that already sourced the file; deleting it cannot change their environment.

### Cost and cleanup expectations

Amazon S3 Tables charges for stored table data, requests, object monitoring,
and automated maintenance such as compaction. See
[Amazon S3 pricing](https://aws.amazon.com/s3/pricing/) for current prices.

This fixture is intentionally tiny, but resources do not expire automatically.
Run the destroy command after testing and verify cleanup in the AWS account.
