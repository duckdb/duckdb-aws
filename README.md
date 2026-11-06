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

## S3 buckets

Six control-plane table functions for general-purpose S3 buckets: list, create, inspect, update
and delete.

```sql
LOAD aws;
CREATE SECRET (TYPE aws, PROVIDER credential_chain, REGION 'eu-central-1');

FROM s3_buckets();
FROM s3_create_bucket('my-duckdb-bucket', dry_run := true);
FROM s3_create_bucket('my-duckdb-bucket', versioning := true, tags := MAP {'team': 'data'});
FROM s3_get_bucket('my-duckdb-bucket');
FROM s3_bucket_tags('my-duckdb-bucket');
FROM s3_update_bucket('my-duckdb-bucket', tags := MAP {'team': 'platform', 'owner': NULL});
FROM s3_delete_bucket('my-duckdb-bucket', cascade := true);
```

### Running against a local build

Build with `make` as described above, then start the built binary with unsigned extension
loading and load the extension from the build tree:

```bash
./build/release/duckdb -unsigned \
  -cmd "LOAD '$PWD/build/release/extension/aws/aws.duckdb_extension';"
```

Credentials come from an `aws` or `s3` secret; `PROVIDER credential_chain` picks up the
environment, `AWS_PROFILE`, SSO and instance roles the same way the AWS CLI does.
`s3_create_bucket` refuses to run without a region: pass `region :=`, set `REGION` on the
secret, `SET s3_region = '...'`, or export `AWS_REGION`. The other functions start from that
region, or the SDK default; the four that take a bucket follow S3 to the bucket's own region.
When `aws_network_calls_via_duckdb` is on, also load `httpfs`, since these calls use PUT, POST,
HEAD and DELETE.

### Listing: `s3_buckets`

```sql
FROM s3_buckets();
FROM s3_buckets(region := 'eu-central-1');
FROM s3_buckets(region := 'eu-central-1', secret := 'my_aws_secret');
```

`s3_buckets` lists general-purpose buckets owned by the authenticated account. It returns
`name VARCHAR`, `region VARCHAR`, and `created_at TIMESTAMP WITH TIME ZONE`. The timestamp
is S3's reported creation date, which can change after bucket configuration updates.
Directory buckets, S3 table buckets, and buckets merely shared with the caller are not included.

Without `region`, the listing covers all regions in the caller's AWS partition. An explicit
`region` filters the listing server-side and selects the matching regional endpoint. A region
configured on a secret, in `s3_region`, in the environment, or in the AWS profile selects the
endpoint but does not filter the results.

The caller needs `s3:ListAllMyBuckets`; `s3:ListBucket` alone is not sufficient.

### Creating: `s3_create_bucket`

```sql
FROM s3_create_bucket('my-duckdb-bucket');
FROM s3_create_bucket('my-duckdb-bucket', region := 'us-east-1', versioning := true,
                      block_public_access := true, tags := MAP {'team': 'data'});
FROM s3_create_bucket('my-duckdb-bucket', dry_run := true);
```

Returns one row: `handle MAP(VARCHAR, VARCHAR)`, `name`, `region`, `arn`. The handle holds
`name` and `region` and can be passed to `s3_get_bucket`, `s3_bucket_tags`, `s3_update_bucket`
and `s3_delete_bucket` in place of the name.

The region is where the bucket is created and must resolve; the function refuses to fall back
to the SDK default. Two provenance tags, `created-by = duckdb` and `duckdb-version`, are set
on every bucket; caller tags win on conflict. `versioning := true` enables versioning;
`block_public_access` sets all four public access block flags to the given value. Options not
given leave the AWS defaults. If any configuration step after `CreateBucket` fails, the new
empty bucket is deleted again and the original error is raised, so a retry does not hit
`BucketAlreadyOwnedByYou`. In us-east-1, where S3 answers `CreateBucket` for a bucket the
account already owns with 200 instead of `BucketAlreadyOwnedByYou`, the function first probes
the name with `HeadBucket` and refuses unless S3 answers 404; a creator racing between the probe
and the create is not detected. `dry_run := true` resolves the identity and region, makes no S3
call, and returns the row with a NULL `handle` and `arn`.

### Inspecting: `s3_get_bucket` and `s3_bucket_tags`

```sql
FROM s3_get_bucket('my-duckdb-bucket');
FROM s3_bucket_tags('my-duckdb-bucket');
```

`s3_get_bucket` returns `name`, `region`, `arn`, `versioning VARCHAR` (`Enabled`, `Suspended`,
or NULL when never versioned) and `block_public_access BOOLEAN` (true only when all four flags
are on, NULL when the bucket has no configuration of its own). A missing bucket fails with
`NoSuchBucket`. `s3_bucket_tags` returns `key`, `value` rows and zero rows for an untagged bucket.

### Updating: `s3_update_bucket`

```sql
FROM s3_update_bucket('my-duckdb-bucket', tags := MAP {'team': 'platform', 'owner': NULL});
FROM s3_update_bucket('my-duckdb-bucket', versioning := false);
FROM s3_update_bucket('my-duckdb-bucket', block_public_access := true, dry_run := true);
```

S3 has no update call, so this applies the individual settings: `tags`, then `versioning`,
then `block_public_access`. At least one must be given; an empty `tags` map counts as not
given. Tags merge into the existing set; a NULL value removes that key, and an update that
empties the set removes the tag set. Setting `versioning := false` suspends versioning, since
S3 cannot disable it once enabled. If one step fails, the function stops there and leaves the
changes from earlier steps in place; the error names the call that failed.

Returns one row: `status` (`updated` or `dry_run`), `name`, `region`, and the resulting
`tags`, `versioning` and `block_public_access`, NULL for settings the call did not touch.
`dry_run := true` reads the current tags and reports what would be written without writing.

### Deleting: `s3_delete_bucket`

```sql
FROM s3_delete_bucket('my-duckdb-bucket');
FROM s3_delete_bucket('my-duckdb-bucket', cascade := true);
FROM s3_delete_bucket('my-duckdb-bucket', cascade := true, dry_run := true);
```

`DeleteBucket` only succeeds on an empty bucket. With `cascade := true` the function first
lists every object version and delete marker and removes them in batches of 1000, then deletes
the bucket. This is irreversible. Objects under Object Lock retention, or in a bucket with MFA
delete, fail the cascade; objects already deleted stay deleted and the error says how many. A
writer racing the cascade makes the final delete fail with `BucketNotEmpty`. Unlike
`s3tables_delete_table_bucket`, the function does not lock the bucket against writers during
the cascade: a Deny bucket policy would also lock out the owner if the process died halfway.

Returns one row: `status` (`deleted` or `dry_run`), `name`, `region`, `deleted_objects BIGINT`,
`warning`. `dry_run := true` counts the objects a cascade would remove and warns when the bucket
is not empty and `cascade` is off.

### Behaviour shared by all S3 bucket functions

Authentication uses an existing `aws` or `s3` secret. Without `secret`, a single explicit `aws`
secret is preferred over a single explicit `s3` secret, then the default AWS credential chain
is used. More than one `aws` secret, or no `aws` secret and more than one `s3` secret, is an
error: name one with `secret :=`. Explicit NULL or empty arguments are rejected.

Region resolution order is the `region` argument, the secret's `REGION`, `s3_region`,
`AWS_REGION`/`AWS_DEFAULT_REGION`, then the AWS profile. For `s3_get_bucket`, `s3_bucket_tags`,
`s3_update_bucket` and `s3_delete_bucket` that region is only where the lookup starts: the
bucket's real region is taken from S3's `HeadBucket` answer and used for every further call, so
these work on buckets in any region.

Required permissions, per function:

| Function | Actions |
|---|---|
| `s3_buckets` | `s3:ListAllMyBuckets` |
| `s3_create_bucket` | `s3:CreateBucket`, `s3:PutBucketTagging`; `s3:PutBucketVersioning` and `s3:PutBucketPublicAccessBlock` when used; `s3:DeleteBucket` for the rollback; `s3:ListBucket` for the us-east-1 probe |
| `s3_get_bucket` | `s3:ListBucket` (HeadBucket), `s3:GetBucketVersioning`, `s3:GetBucketPublicAccessBlock` |
| `s3_bucket_tags` | `s3:ListBucket`, `s3:GetBucketTagging` |
| `s3_update_bucket` | `s3:ListBucket`; `s3:GetBucketTagging` and `s3:PutBucketTagging` for `tags`; `s3:PutBucketVersioning` for `versioning`; `s3:PutBucketPublicAccessBlock` for `block_public_access` |
| `s3_delete_bucket` | `s3:ListBucket`, `s3:DeleteBucket`; `s3:ListBucketVersions` for `cascade` or `dry_run`; `s3:DeleteObject` and `s3:DeleteObjectVersion` for `cascade` |

AWS errors fail the query rather than returning an empty or silently incomplete result. All of
these functions are blocked by `enable_external_access = false`, including statements prepared
before the setting changed. `dry_run` is BOOLEAN; a value that does not cast to BOOLEAN is an
error, never a real run.

These functions use the AWS SDK's endpoints, including the SDK's own endpoint overrides from the
environment and profile. S3-specific settings of an `s3` secret, such as `ENDPOINT` and
`URL_STYLE`, are ignored, so S3-compatible providers are not supported.

## Tests

- [Redshift test setup](test/sql/redshift/README.md)
- [Private S3 bucket tests and railway example](test/sql/s3/README.md)
- [S3 Tables test setup](test/sql/s3tables/README.md)

## Documentation

See the [AWS page in the DuckDB documentation](https://duckdb.org/docs/extensions/aws).
