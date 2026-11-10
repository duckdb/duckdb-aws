# DuckDB AWS Extension

This is a DuckDB extension that provides features that depend on the AWS SDK. It adds functionality such as loading AWS credentials from the AWS default credential provider chain.

## Supported architectures
The extension is tested & distributed for Linux (x64, arm64), macOS (x64, arm64) and Windows (x64).

## Building & Loading the Extension

The `duckdb` and `extension-ci-tools` submodules must be initialized prior to building.
```bash
git submodule init
git pull --recurse-submodules
```

To build, type:
```
VCPKG_TOOLCHAIN_PATH=$PWD/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make
```

### VCPKG
`vcpkg` can instead be cloned into your home directory or another location:
```bash
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
```
Point `VCPKG_TOOLCHAIN_PATH` at that checkout when building:
```
VCPKG_TOOLCHAIN_PATH=~/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make
```

## CloudFormation, Quack, and Redshift setup

The setup command reuses `scripts/redshift/create_cluster.sh`, creates a Quack stack through DuckDB's `cloudformation_create_stack`, discovers both resources' security groups, and allows Quack to reach Redshift's actual database port. It then registers the stack, attaches Quack, installs temporary AWS credentials on the remote server, and queries the TICKIT `category` table through Redshift.

Prerequisites:

- Bash, Python 3, AWS CLI v2 with `configure export-credentials`, and a signed-in federated profile.
- A release build containing `aws`, `httpfs`, `quack`, and `json`.
- A default VPC. This workflow requires Redshift and Quack in that VPC and the same account and region.
- Permissions for the existing Redshift creation script, CloudFormation stack creation/deletion, EC2 security-group inspection and ingress changes, and Redshift IAM database credentials. A console login alone does not grant those permissions.

The default Quack template supports `us-east-1`, `us-east-2`, `us-west-1`, `us-west-2`, and `eu-central-1`. It uses a public AMI and opens HTTP/HTTPS for Quack and certificate issuance. The Redshift rule added by this workflow allows only the Quack security group, never public database access.

The examples use profile `quack-ec2` and region `eu-central-1` (Frankfurt). Replace the profile if yours has a different name. Omit `PREFIX` to use your local username, or set `PREFIX="$USER"` explicitly. Use the same prefix and state directory for every command; changing them selects a different setup. All targets preview by default, including a read-only caller-identity check:

```bash
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 make quack-redshift-setup
```

After checking the account and plan, create or reuse the resources and run the smoke test:

```bash
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 make quack-redshift-setup FORCE=1
```

The script reads the Redshift env file as data; it does not source it or execute its credential-export command. It verifies the saved cluster name, ARN, and region against the selected profile and live cluster. Stale or mismatched identities stop the setup rather than switching accounts or changing another cluster's rules.

Rerunning setup reuses the saved resources and skips an existing ingress rule. The Quack stack has a stable name, so a lost create response can be recovered without creating a second stack. Failed stacks are reported, not replaced automatically. The script does not delete resources on failure; CloudFormation's own rollback still applies.

To refresh the remote credentials and repeat only the connectivity test:

```bash
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 make quack-redshift-check FORCE=1
```

The test uses a remote database alias printed as `redshift_<setup-id>`. Before attaching Quack, a direct `quack_query` checks that an existing alias is PostgreSQL-backed and its saved target matches this setup. It accepts a matching namespace ARN, cluster label, or parsed libpq host/port/database; it does not print the stored connection string. It then refreshes only that alias with `ATTACH OR REPLACE` and verifies Redshift's `current_namespace` and `current_database()` before loading Quack's catalogs. A different or unverifiable saved target stops the check without replacing the attachment.

This ordering handles expired Redshift IAM database passwords. They default to a 15-minute lifetime and are separate from the generated AWS session credentials. Quack loads remote catalogs when it attaches, so a stale Redshift attachment can block Quack itself. Setup/check and standalone Python generation refresh the database attachment before that catalog load. Long-running connection pools do not automatically renew it: regenerate the manual file before running it again after expiry.

Temporary credentials carry the selected profile's permissions to Quack until expiry. Use a trusted test instance. The script disables remote logging before sending credentials and leaves it disabled; raw DuckDB error output is withheld because it can contain credentials. Credentials are kept out of the setup state and env file. After setup passes its smoke test, it writes them to the private manual-test file described below.

### Generated manual-test SQL

Setup generates `manual_test_with_secrets.sql` after its smoke test passes. Standalone `scripts/generate_manual_test_with_secrets.py --force` first prepares the remote attachment and runs the same guarded TICKIT check, then writes the file. It uses the saved deployment and fresh credentials; no template file or manually supplied stack ARN is needed. The original WASM helper remains unchanged.

The manual SQL contains only the local and remote secrets, Quack registration/attachment, Redshift attachment, and test queries. Recovery and validation stay in the Python preparation step. The optional stack-creation example is commented out. The first and last SQL statements are `CALL enable_logging(level='trace', storage='stdout');`; logging pauses during credential setup and resumes for the queries.

Run the file soon after generation in a fresh session. If Quack attachment fails with an expired IAM password, regenerate the file to prepare the remote connection again.

To prepare the remote test attachment and generate the private file without creating or deleting AWS resources:

```bash
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 make quack-redshift-manual-test
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 make quack-redshift-manual-test FORCE=1
# Equivalent:
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 python3 scripts/generate_manual_test_with_secrets.py --force
```

Use the same `AWS_PROFILE`, `AWS_REGION`, `PREFIX`, and state directory as setup. Preparation refreshes only the `redshift_<setup-id>` attachment and checks its namespace/database; Redshift data and AWS resources are unchanged. If preparation fails, the previous manual file stays intact. The output replaces that file at mode `0600` and is git-ignored. Set `MANUAL_TEST_WITH_SECRETS_FILE` to change the path; its directory must already exist, and a path inside this repository must be git-ignored.

To run the SQL in a fresh native DuckDB session:

```bash
./build/release/duckdb -unsigned \
  -cmd "LOAD '$PWD/build/release/extension/httpfs/httpfs.duckdb_extension';" \
  -cmd "LOAD '$PWD/build/release/extension/aws/aws.duckdb_extension';" \
  -cmd "LOAD '$PWD/build/release/extension/quack/quack.duckdb_extension';"
```

```sql
.read manual_test_with_secrets.sql
```

For the WASM shell, load compatible `httpfs`, `aws`, and `quack` extensions and run the file's SQL in a fresh session. Keep the file private and do not share SQL or errors containing credentials. Do not remove the logging-off guards around credential setup or paste credential statements into a session with trace logging enabled. Regenerate the file when its credentials expire. Python generation runs remote preparation queries, but does not execute the generated file or clean up AWS resources.

### Print only the AWS secret SQL

Unlike setup or manual-test generation, this command does not inspect or prepare Quack or Redshift:

```bash
AWS_PROFILE=s3resources AWS_REGION=eu-central-1 make sql-aws-session-token FORCE=1
```

Stdout contains only `CREATE OR REPLACE TEMPORARY SECRET aws_session_token (...)`, using
`TYPE aws`, `PROVIDER config`, and the selected profile's temporary credentials.
Nothing is executed in DuckDB, and the command writes no SQL file. Omit `FORCE=1`
for a preview on stderr without exporting credentials. Requires Python 3 and AWS
CLI v2 with `configure export-credentials`; no DuckDB build is needed.

An [`aws login` profile](https://docs.aws.amazon.com/sdkref/latest/guide/feature-login-credentials.html)
issues 15-minute credentials. This command exports the current credentials, which
may be cached and have less than 15 minutes left. It rejects expired credentials,
missing expiration or session tokens, and credentials with more than 15 minutes
remaining; it does not shorten an existing session. The SQL contains no refresh
token, so rerun the command after expiry. Keep the output private and execute it
only after loading `aws`, with SQL logging disabled.

### Optional: create a new Quack stack manually

This creates another billable EC2 instance, unlike the generated test's `REGISTER` command. Run it in a separate DuckDB session with an AWS secret and the `aws` and `quack` extensions loaded:

```sql
CREATE EXTERNAL RESOURCE 'aws:cloudformation:quack-on-ec2' AS remote (REGION 'eu-central-1', TEMPLATE 'https://quack-on-ec2-259911478022.s3.amazonaws.com/quack.yaml');
ATTACH TO EXTERNAL RESOURCE remote AS quack;
```

Before attaching Redshift from that instance, allow its security group on the Redshift database port. The existing setup rule covers only the original Quack stack. The new stack is not recorded in this setup's state and must be cleaned up separately.

Resources remain billable until cleanup. Unlike the template's eight-hour default, this workflow defaults to **no Quack shutdown timer**. Keep the state file until cleanup; it records which resources and ingress rules the workflow owns.

```bash
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 make quack-redshift-cleanup
AWS_PROFILE=quack-ec2 AWS_REGION=eu-central-1 make quack-redshift-cleanup FORCE=1
```

Cleanup removes recorded ingress rules before deleting an owned Quack stack. It deletes an owned Redshift test cluster **without a final snapshot**, then its owned loader role and security group. Resources that predated setup are retained. Changed resource identities or unexpected role policies stop cleanup. Cleanup can be retried after interruption; a later setup can recreate resources after cleanup completes.

Configuration is through environment variables:

| Variable | Default / purpose |
|---|---|
| `AWS_PROFILE`, `AWS_REGION` | Required; used for every AWS operation |
| `PREFIX` | Local username; 1-25 lowercase letters, digits, or hyphens, starting with a letter |
| `REDSHIFT_ENV_FILE` | `test/sql/redshift/redshift.env`; choose a separate file for each concurrent setup |
| `AWS_REDSHIFT_DATABASE` | `dev` when creating Redshift, as in the existing creation script |
| `DUCKDB_BUILD_DIR` | `build/release` under this repository |
| `QUACK_MACHINE_TYPE` | `t4g.small` |
| `QUACK_MAX_DURATION_HOURS` | `0` disables shutdown; otherwise 1-144 hours. Redshift and the stack still need cleanup |
| `QUACK_TEMPLATE_URL` | [Public Quack template](https://quack-on-ec2-259911478022.s3.amazonaws.com/quack.yaml); an override must accept `machinetype`/`maxduration` and expose `InstanceId`/`QuackURI`/`Token`, with the instance's group named `QuackSG` in the template |
| `MANUAL_TEST_WITH_SECRETS_FILE` | `manual_test_with_secrets.sql` under this repository; private generated manual-test SQL with temporary credentials |
| `QUACK_REDSHIFT_STATE_DIR` | `.quack-redshift` under this repository; state is separated by account, region, and prefix |
| `QUACK_REDSHIFT_WAIT_SECONDS` | `1800` for Redshift creation and each stack wait; individual DuckDB calls time out after 120 seconds |

The script can also be called directly as `python3 scripts/quack_redshift.py <action> [--force]`, where the action is `setup`, `check`, `cleanup`, or `manual-test`.

## S3 buckets and S3 Tables

- [S3 buckets](test/sql/s3/README.md): the `s3_*` table functions, the `aws:s3:bucket`
  external-resource type, their tests and the private fixture bucket.
- [S3 Tables](test/sql/s3tables/README.md): the `s3tables_*` table functions, the
  `aws:s3tables:table-bucket` external-resource type, their tests and the table bucket fixture.

The function references below, here and under [AWS system tables](#aws-system-tables), are
generated from the description, example and category each function registers through
`Documented()` (`src/utils/utils.cpp`). After changing a function or its documentation, rebuild
and run `make docs`; `make docs-check` exits 1 if a reference is stale, and a public function
registered without documentation fails either. Only the text between the `generated` markers is
rewritten.

### S3 bucket functions

<!-- generated:s3 -->
#### `s3_buckets`

```sql
FROM s3_buckets(region := 'eu-central-1');
```

Lists the general-purpose S3 buckets the account owns, with each bucket's region and creation time. `region` filters to one region; without it every region in the partition is listed.

Signatures:

- `s3_buckets()`

Options:

- `region := VARCHAR`
- `secret := VARCHAR`

#### `s3_create_bucket`

```sql
FROM s3_create_bucket('my-bucket', region := 'eu-central-1', versioning := true, tags := MAP {'team': 'data'});
```

Creates a general-purpose S3 bucket in `region`, tags it with `created-by = duckdb` plus `tags`, and optionally enables versioning and blocks public access. Returns a handle MAP the other s3_* functions accept in place of the name. `dry_run` resolves region and credentials and makes no S3 call.

Signatures:

- `s3_create_bucket(name VARCHAR)`

Options:

- `region := VARCHAR`
- `tags := MAP(VARCHAR, VARCHAR)`
- `versioning := BOOLEAN`
- `block_public_access := BOOLEAN`
- `secret := VARCHAR`
- `dry_run := BOOLEAN`

#### `s3_get_bucket`

```sql
FROM s3_get_bucket('my-bucket');
```

Returns one row for a bucket given by name or handle: its region as S3 reports it, ARN, versioning status and whether all public access is blocked. Fails with NoSuchBucket when the bucket does not exist.

Signatures:

- `s3_get_bucket(name VARCHAR)`
- `s3_get_bucket(handle MAP(VARCHAR, VARCHAR))`

Options:

- `region := VARCHAR`
- `secret := VARCHAR`

#### `s3_bucket_tags`

```sql
FROM s3_bucket_tags('my-bucket');
```

Returns a bucket's tags as (key, value) rows; zero rows for an untagged bucket.

Signatures:

- `s3_bucket_tags(name VARCHAR)`
- `s3_bucket_tags(handle MAP(VARCHAR, VARCHAR))`

Options:

- `region := VARCHAR`
- `secret := VARCHAR`

#### `s3_update_bucket`

```sql
FROM s3_update_bucket('my-bucket', tags := MAP {'owner': NULL}, block_public_access := true);
```

Changes a bucket's tags, versioning and public-access block, in that order; pass non-empty tags or a setting. `tags` merges into the existing set and a NULL value removes a key; `versioning := false` suspends, since S3 cannot disable versioning. `dry_run` reports the result without writing.

Signatures:

- `s3_update_bucket(name VARCHAR)`
- `s3_update_bucket(handle MAP(VARCHAR, VARCHAR))`

Options:

- `tags := MAP(VARCHAR, VARCHAR)`
- `versioning := BOOLEAN`
- `block_public_access := BOOLEAN`
- `region := VARCHAR`
- `secret := VARCHAR`
- `dry_run := BOOLEAN`

#### `s3_delete_bucket`

```sql
FROM s3_delete_bucket('my-bucket', cascade := true);
```

Deletes a bucket given by name or handle. S3 only deletes an empty bucket; `cascade := true` first removes every object version and delete marker, irreversibly. `dry_run` counts what a cascade would remove.

Signatures:

- `s3_delete_bucket(name VARCHAR)`
- `s3_delete_bucket(handle MAP(VARCHAR, VARCHAR))`

Options:

- `cascade := BOOLEAN`
- `region := VARCHAR`
- `secret := VARCHAR`
- `dry_run := BOOLEAN`
<!-- /generated -->

### S3 Tables functions

<!-- generated:s3tables -->
#### `s3tables_table_buckets`

```sql
FROM s3tables_table_buckets('eu-central-1');
```

Lists S3 Tables table buckets: in one region, in a list of regions, or without an argument in every default region in parallel. A region that answers with an error becomes one row with `error` set.

Signatures:

- `s3tables_table_buckets()`
- `s3tables_table_buckets(region VARCHAR)`
- `s3tables_table_buckets(regions VARCHAR[])`

Options:

- `secret := VARCHAR`

#### `s3tables_namespaces`

```sql
FROM s3tables_namespaces('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-table-bucket');
```

Lists the namespaces of a table bucket; a namespace is what a schema of the attached catalog maps to.

Signatures:

- `s3tables_namespaces(table_bucket_arn VARCHAR)`

Options:

- `secret := VARCHAR`

#### `s3tables_tables`

```sql
FROM s3tables_tables('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-table-bucket', 'sales');
```

Lists the tables of a table bucket, in one namespace or across all of them, with each table's type, ARN and timestamps.

Signatures:

- `s3tables_tables(table_bucket_arn VARCHAR)`
- `s3tables_tables(table_bucket_arn VARCHAR, namespace VARCHAR)`

Options:

- `secret := VARCHAR`

#### `s3tables_create_table_bucket`

```sql
FROM s3tables_create_table_bucket('my-table-bucket', region := 'eu-central-1');
```

Creates an S3 Tables table bucket in `region`, tagged with `created-by = duckdb` plus `tags`, and returns its ARN and a handle MAP. `dry_run` resolves region and credentials and makes no AWS call.

Signatures:

- `s3tables_create_table_bucket(name VARCHAR)`

Options:

- `region := VARCHAR`
- `tags := MAP(VARCHAR, VARCHAR)`
- `secret := VARCHAR`
- `dry_run := BOOLEAN`

#### `s3tables_get_table_bucket`

```sql
FROM s3tables_get_table_bucket('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-table-bucket');
```

Returns one row for a table bucket given by ARN: name, region, owner account, bucket id, type and creation time. Fails with NotFoundException when it does not exist.

Signatures:

- `s3tables_get_table_bucket(table_bucket_arn VARCHAR)`

Options:

- `secret := VARCHAR`

#### `s3tables_table_metadata_location`

```sql
FROM s3tables_table_metadata_location('arn:aws:s3tables:us-east-1:123456789012:bucket/aws-catalog', 'glue', 'tables');
```

Returns where a table's current Iceberg metadata file is, with the warehouse location and version token: all an Iceberg reader needs to scan the table without a catalog. `metadata_location` is NULL while the table is still being created.

Signatures:

- `s3tables_table_metadata_location(table_bucket_arn VARCHAR, namespace VARCHAR, name VARCHAR)`

Options:

- `secret := VARCHAR`

#### `s3tables_table_bucket_tags`

```sql
FROM s3tables_table_bucket_tags('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-table-bucket');
```

Returns a table bucket's tags as (key, value) rows.

Signatures:

- `s3tables_table_bucket_tags(table_bucket_arn VARCHAR)`

Options:

- `secret := VARCHAR`

#### `s3tables_delete_table_bucket`

```sql
FROM s3tables_delete_table_bucket('arn:aws:s3tables:eu-central-1:123456789012:bucket/my-table-bucket', cascade := true);
```

Deletes a table bucket given by ARN or handle. AWS only deletes an empty bucket; `cascade := true` first deletes every table and namespace. It first tries to seal the bucket against new writes unless `seal := false` or a resource policy already exists; sealing failures are reported as warnings. `dry_run` counts what a cascade would remove.

Signatures:

- `s3tables_delete_table_bucket(table_bucket_arn VARCHAR)`
- `s3tables_delete_table_bucket(handle MAP(VARCHAR, VARCHAR))`

Options:

- `cascade := BOOLEAN`
- `seal := BOOLEAN`
- `secret := VARCHAR`
- `dry_run := BOOLEAN`
<!-- /generated -->

## AWS system tables

AWS services publish inventories and logs as Apache Iceberg tables in AWS-managed S3 table buckets, one bucket per
service, account and region, named `aws-<service>`: S3 Metadata (`aws-s3`: `b_<bucket>.journal`, `inventory`,
`annotation`), the Glue Data Catalog export (`aws-catalog`: `glue.tables`, `glue.table_columns`,
`catalog_metadata.*`), Athena usage (`aws-athena`: `metadata.query_executions`), Redshift (`aws-redshift`: the
`sys_*` views), CloudWatch Logs (`aws-cloudwatch`). Each family is enabled per region in the owning service; once it
is, the extension finds and reads its tables through the S3 Tables API alone, no Glue or Lake Formation involved.

```sql
FROM aws_system_tables();                              -- every system table in the default regions
FROM aws_system_tables(region := 'us-east-1');         -- one region, its errors thrown; regions := [...] for several
FROM aws_system_table('aws-catalog', 'glue', 'tables', region := 'us-east-1');  -- scan one (iceberg_scan)
FROM aws_system_table_families();                      -- the known families and the resource type each is the inventory of
FROM s3tables_table_metadata_location('arn:aws:s3tables:us-east-1:123456789012:bucket/aws-catalog', 'glue', 'tables');
```

`aws_system_tables` lists the tables of every `aws-*` bucket (`ListTableBuckets` of type `aws`, then `ListTables`),
one row per table with `region`, `bucket`, `service`, `namespace`, `name`, `table_arn` and the table's type, owner
service and timestamps; a region or bucket that cannot be listed is one row with `error` set. `aws_system_table`
scans one table by bucket name (in `region`, or the region the usual resolution yields) or bucket ARN: it fetches
the table's current metadata location and reads it with `iceberg_scan`, so the `iceberg` extension is loaded on
demand and the data files are read with the ordinary S3 secret.

The same tables are the external resource type `aws:system-table`, named by path:

```sql
SHOW ALL EXTERNAL RESOURCES;                           -- aws-catalog/glue/tables, aws-s3/b_my-bucket/inventory, ... alongside the table buckets
ATTACH 'arn:aws:s3tables:us-east-1:123456789012:bucket/aws-catalog' AS c;   -- the bucket, through the arn storage route
SELECT name, database_name FROM c.glue.tables;
```

The listing's rows carry the table ARN as handle and `region`, `bucket`, `namespace`, `table`, `service` and the
table's type and timestamps as metadata. The status callback hands ATTACH the bucket ARN with the table's namespace
as `default_schema`.

A family of system tables is enabled with `CREATE EXTERNAL RESOURCE`, in one region, named by the resource type it
is the inventory of; `DESTROY` turns it off again, which for S3 Metadata deletes the bucket's journal and inventory
tables (never the bucket's objects):

```sql
CREATE EXTERNAL RESOURCE 'aws:system-table' AS meta (TYPE 'aws:s3:bucket', BUCKET 'my-bucket', REGION 'us-east-1');
ATTACH TO EXTERNAL RESOURCE meta AS m;             -- the aws-s3 bucket, default schema b_my-bucket
SELECT count(*) FROM m.inventory;
DESTROY EXTERNAL RESOURCE meta;
```

Only the S3 Metadata family (`TYPE 'aws:s3:bucket'`) can be enabled with the AWS SDK version this extension links;
`TYPE 'aws:glue'` and `'aws:athena'` are refused until the vcpkg port moves to aws-sdk-cpp 1.11.924 or later, which
has `PutDataCatalogExportConfiguration` and `CreateSystemTableConfiguration`. The configuration calls are also
available directly as the `s3_*_metadata_configuration` functions below.

### System table functions

<!-- generated:system-tables -->
#### `s3_bucket_metadata_configuration`

```sql
FROM s3_bucket_metadata_configuration('my-bucket', region := 'us-east-1');
```

Returns a bucket's S3 Metadata configuration as one row: the `aws-s3` table bucket and namespace its tables live in, and the status and ARN of the journal and inventory tables. No row when the bucket has no configuration.

Signatures:

- `s3_bucket_metadata_configuration(bucket VARCHAR)`

Options:

- `region := VARCHAR`
- `secret := VARCHAR`

#### `s3_create_bucket_metadata_configuration`

```sql
FROM s3_create_bucket_metadata_configuration('my-bucket', region := 'us-east-1', inventory := true, journal_expiration_days := 30);
```

Enables S3 Metadata for a bucket: a journal table always, an inventory table unless `inventory := false`, journal records kept forever unless `journal_expiration_days` is set. S3 creates the region's `aws-s3` table bucket on the first configuration. Returns the configuration as `s3_bucket_metadata_configuration` does, so the tables are typically still CREATING.

Signatures:

- `s3_create_bucket_metadata_configuration(bucket VARCHAR)`

Options:

- `region := VARCHAR`
- `secret := VARCHAR`
- `inventory := BOOLEAN`
- `journal_expiration_days := BIGINT`

#### `s3_delete_bucket_metadata_configuration`

```sql
FROM s3_delete_bucket_metadata_configuration('my-bucket', region := 'us-east-1');
```

Disables S3 Metadata for a bucket, which deletes its journal and inventory tables, irreversibly; the bucket's objects are untouched. Returns `status = deleted`, or `absent` when there was no configuration.

Signatures:

- `s3_delete_bucket_metadata_configuration(bucket VARCHAR)`

Options:

- `region := VARCHAR`
- `secret := VARCHAR`

#### `aws_system_tables`

```sql
FROM aws_system_tables(regions := ['us-east-1', 'eu-central-1']);
```

Lists every table of every AWS-managed `aws-*` table bucket, one row per table with its region, bucket, service, namespace, name, ARN, type and timestamps. Without an argument it sweeps the default regions; `regions` lists those regions; `region` lists one and throws its errors. Otherwise a region or bucket that cannot be listed becomes one row with `error` set.

Signatures:

- `aws_system_tables()`

Options:

- `region := VARCHAR`
- `regions := VARCHAR[]`
- `secret := VARCHAR`

#### `aws_system_table`

```sql
FROM aws_system_table('aws-catalog', 'glue', 'tables', region := 'us-east-1');
```

Scans one system table through `iceberg_scan`, from the table's current metadata location. `bucket` is a table bucket name, looked up in `region` or the region the usual resolution yields, or a table bucket ARN, which carries its own region. Fails while the table is still being created and has no metadata.

Signatures:

- `aws_system_table(bucket VARCHAR, namespace VARCHAR, name VARCHAR)`

Options:

- `region := VARCHAR`
- `secret := VARCHAR`

#### `aws_system_table_families`

```sql
FROM aws_system_table_families();
```

Lists the known families of system tables: the `aws-*` bucket each lands in, its namespace and table patterns, the external-resource type it is the inventory of and the AWS call that enables it. Static; no AWS call.

Signatures:

- `aws_system_table_families()`
<!-- /generated -->

## Tests

- [Redshift test setup](test/sql/redshift/README.md)

## Documentation

See the [AWS page in the DuckDB documentation](https://duckdb.org/docs/extensions/aws).
