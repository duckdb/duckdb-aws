# S3 buckets

`s3_buckets`, `s3_create_bucket`, `s3_get_bucket`, `s3_bucket_tags`, `s3_update_bucket` and
`s3_delete_bucket` manage general-purpose S3 buckets from SQL; `aws:s3:bucket` is the matching
external-resource type, for a bucket DuckDB provisions and tears down itself. The rest of this
file covers the tests and the private fixture bucket they run against. S3 Tables, a different
product with its own functions and fixture, is in the [S3 Tables README](../s3tables/README.md).

## Functions

Sign in first: `aws login --profile <name>`, and export `AWS_PROFILE` and `AWS_REGION`.

```shell
./build/release/duckdb -unsigned \
  -cmd "LOAD '$PWD/build/release/extension/aws/aws.duckdb_extension';"
```

```sql
CREATE SECRET (TYPE s3, PROVIDER credential_chain, REGION 'eu-central-1');
FROM s3_buckets();
FROM s3_create_bucket('my-duckdb-bucket', versioning := true, tags := MAP {'team': 'data'});
FROM s3_get_bucket('my-duckdb-bucket');
FROM s3_bucket_tags('my-duckdb-bucket');
FROM s3_update_bucket('my-duckdb-bucket', tags := MAP {'owner': NULL}, block_public_access := true);
FROM s3_delete_bucket('my-duckdb-bucket', cascade := true);
```

The first call lists the account's buckets; the create returns one row with a `handle` MAP, the
tags call shows `created-by = duckdb` next to `team`, and the delete returns `status = deleted`.

The external-resource type uses the same functions: `CREATE EXTERNAL RESOURCE 'aws:s3:bucket' AS
scratch (REGION 'eu-central-1', NAME 'my-duckdb-bucket')` creates a bucket tagged
`duckdb-external-resource-type = aws:s3:bucket`, and `REGISTER EXTERNAL RESOURCE ... FROM MAP
{'name': ..., 'region': ...}` registers an existing one. `DESTROY EXTERNAL RESOURCE scratch`
deletes an empty bucket, including an adopted bucket. For a non-empty bucket it fails without
deleting objects or versions and leaves the resource registered. The resource-type tag records
which buckets DuckDB created; it does not make `DESTROY` empty them.

To delete the contents of a registered bucket deliberately, inspect its exact handle and preview
the deletion first. After reviewing the preview, run the cascade call separately:

```sql
SELECT handle FROM duckdb_external_resources() WHERE name = 'scratch';
SET VARIABLE scratch_handle = (SELECT handle FROM duckdb_external_resources() WHERE name = 'scratch');
FROM s3_delete_bucket(getvariable('scratch_handle'), cascade := true, dry_run := true);
FROM s3_delete_bucket(getvariable('scratch_handle'), cascade := true);
FROM deregister_external_resource('scratch');
```

The preview returns `status = dry_run` and an object count without changing the bucket. The
cascade call permanently deletes all objects, versions and delete markers, then the bucket.
Deregister only after successful deletion: `s3_delete_bucket` does not remove the local
registration. Ordinary resource cleanup, including provisioning rollback, never cascades.
Non-empty buckets that survive cleanup continue incurring storage charges.

## Tests

```shell
./build/release/test/unittest '*/test/sql/s3/*'
```

Without the fixture environment, `s3_functions.test` (argument handling, the external-access
guard) and `s3_resource.test` (the `aws:s3:bucket` type and its callbacks) run. The resource tests
use persistent SQL substitutes to reject implicit cascade and check registration after failed
deletes; other AWS calls use AWS's documented example key pair and are expected to fail. After
`source test/sql/s3/s3.env` (see [Setup](#setup)), three more run against the account:

- `s3.test` reads the fixture object through an S3 secret.
- `s3_functions_aws.test` lists and inspects the fixture bucket, then creates
  `$AWS_S3_BUCKET-fn`, reconfigures it, fills it and cascade-deletes it.
- `s3_resource_aws.test` checks that `DESTROY` preserves objects and versions in tagged
  `$AWS_S3_BUCKET-res` and `$AWS_S3_BUCKET-adopt` buckets, then explicitly cascade-deletes them.
  It also adopts and destroys the empty `$AWS_S3_BUCKET-empty` bucket.

If a run dies midway, remove the leftovers by hand before the next run:
`FROM s3_delete_bucket('<bucket>', cascade := true);`. S3 can refuse to re-create a just-deleted
name for a while (`OperationAborted`), and bucket configuration reads are eventually consistent,
so a check right after a write can occasionally see the old value; rerun.

## Setup

The fixture scripts provision a general-purpose S3 bucket for the native tests above and
for manual browser examples.

Prerequisites: Bash, a current AWS CLI v2, `jq`, `curl`, `gzip`, and an authenticated
AWS profile or exported AWS credentials. The native tests need a DuckDB build with
`aws`, `httpfs` and `parquet`. Setup and cleanup are opt-in; the offline tests do not create
resources.

From the repository root:

```bash
export AWS_PROFILE=my-test-profile
export AWS_REGION=eu-central-1
./scripts/s3/create_bucket.sh
./scripts/s3/create_bucket.sh --force
source test/sql/s3/s3.env
./build/release/test/unittest '*/test/sql/s3/*'
```

Without `--force`, setup and cleanup only print a plan. They do not call AWS.
With `--force`, setup creates or reuses
`$PREFIX-duckdb-aws-$AWS_ACCOUNT_ID-$AWS_REGION`, where `PREFIX` defaults to your
Unix username. Use lowercase letters, digits and hyphens in the prefix.
Creation always derives the name from the current prefix, authenticated AWS
account and region; `S3_BUCKET_NAME` is ignored, including values from a
previously sourced `s3.env`. Bucket names are globally unique. Dotted names are
not supported by these scripts because the browser example uses HTTPS virtual-hosted access.

To create or refresh another prefix/profile/region fixture:

```bash
PREFIX=vvvv AWS_PROFILE=s3resources AWS_REGION=us-west-1 \
  ./scripts/s3/create_bucket.sh --force
source test/sql/s3/s3.env
```

A matching managed bucket is reused and its test data and configuration are
refreshed. The environment file is overwritten with the latest fixture settings.
Buckets from earlier prefixes, accounts or regions are left untouched.

The bucket contains:

- `duckdb-fixture/data.csv.gz`: the three rows in [data.csv](data.csv). Setup replaces
  this fixture on each run, and `s3.test` checks the exact rows through an S3 secret.
  `s3_functions_aws.test` reads the bucket's `Project = duckdb-aws` tag and its region.
- `nl-railway/services-2025-03.csv.gz`: the public
  [Dutch railway services archive](https://blobs.duckdb.org/nl-railway/services-2025-03.csv.gz).
  Setup downloads it completely before uploading; reruns preserve an existing copy.
  Override `S3_DATA_URL` and `S3_OBJECT_KEY` to use another gzip-compressed CSV.

Reused buckets must belong to the current account, have the expected management
and project tags, and be in the selected region. Versioned or suspended buckets
are refused. A failed first setup may leave partial resources; inspect the failure
and rerun. If initial tagging failed, the untagged bucket requires manual inspection
rather than automatic adoption or deletion.

## Credentials

The generated, ignored `s3.env` stores identifiers, profile selectors and the path
to the local credential helper, not access keys or tokens. Set `S3_ENV_FILE` to use
another location. With `AWS_PROFILE` (or `AWS_DEFAULT_PROFILE`) set, setup and each
`source` clear stale exported credentials, then run `aws configure export-credentials`
for that profile. Without a selected profile, existing exported credentials are
used; otherwise the default or sole configured profile is selected.

Source the file again before a later run to refresh profile credentials. If you use
only exported environment credentials, refresh those yourself before sourcing.
Malformed credentials with line breaks are rejected without printing their values.
`CHAIN 'env'` lets the native AWS extension use the same credentials, including
`AWS_SESSION_TOKEN`, without relying on SDK support for the profile's login method.

`S3_TEST_AVAILABLE=1` is exported only after credential loading succeeds. The live
SQL tests skip unless this guard is set. Merely having AWS credentials in your shell
does not enable it. Generated files are local to this checkout; regenerate them if
you move the checkout.

## Railway example

After sourcing the generated environment, run with the native build:

```bash
./build/release/duckdb -unsigned -batch -bail -no-init -c "
  LOAD httpfs;
  LOAD aws;
  CREATE TEMPORARY SECRET railway (
    TYPE s3, PROVIDER credential_chain, CHAIN 'env',
    REGION '$AWS_REGION', SCOPE 's3://$AWS_S3_BUCKET/'
  );
  SELECT * FROM read_csv_auto('s3://$AWS_S3_BUCKET/$AWS_S3_OBJECT_KEY') LIMIT 10;
"
```

This query reads the archive; the deterministic regression uses the small local
fixture instead. The scripts and native tests do not build or run DuckDB-Wasm.

For a manual browser session, use `PROVIDER config` with freshly obtained temporary
credentials and the same region and S3 URL. Native `CHAIN 'env'` cannot read your
terminal environment inside a browser. Keep the session token on one physical line,
never put credentials in a page URL or committed SQL, and do not use builds that log
request headers. `which_secret` confirms secret selection, not authentication.

## Browser CORS

The bucket stays private: ACLs are disabled, public access is blocked, and SSE-S3 is
explicitly enabled. CORS permits signed `GET` and `HEAD` from
`http://127.0.0.1:*`, `http://localhost:*`, and `https://shell.duckdb.org` by default,
including loopback origins without a port. Narrow these with, for example:

```bash
S3_CORS_ALLOWED_ORIGINS='http://127.0.0.1:8081' ./scripts/s3/create_bucket.sh --force
```

Allowed request headers include `Authorization`, `Content-Type`, `Range`,
`amz-sdk-*`, `x-amz-*`, and `x-host-override`. The rule exposes range, length, ETag,
and AWS request-ID headers. CORS neither grants S3 permissions nor validates
credentials. Native tests cannot verify browser preflight enforcement; that needs a
browser test in DuckDB-Wasm.

## Cleanup

Use the generated configuration to select the exact saved bucket for cleanup:

```bash
source test/sql/s3/s3.env
./scripts/s3/destroy_bucket.sh
./scripts/s3/destroy_bucket.sh --force
unset S3_TEST_AVAILABLE
```

Cleanup verifies account, region, tags and versioning, refuses unrelated objects,
then deletes only the two named objects and the bucket. It does not recursively
empty a bucket, and it does not know about the `-fn`, `-res`, `-adopt` and `-empty` buckets the
AWS-backed tests create; those tests delete their own, see [Tests](#tests) for the
manual fallback. Once the test object is gone, cleanup removes a matching generated
environment file even if a later step fails. Already-sourced shells retain their
variables, so unset the guard there. Do not run setup or cleanup concurrently.

## Permissions, costs and local checks

Use a dedicated test identity scoped to the bucket and its objects. Setup needs
`s3:CreateBucket`, `s3:ListBucket`, `s3:GetBucketLocation`, `s3:GetBucketVersioning`,
`s3:GetBucketTagging`, `s3:PutBucketTagging`, `s3:PutBucketOwnershipControls`,
`s3:PutBucketPublicAccessBlock`, `s3:PutEncryptionConfiguration`, `s3:PutBucketCORS`,
`s3:PutObject`, and `s3:GetObject`. Cleanup additionally needs `s3:DeleteObject` and
`s3:DeleteBucket`. The scripts also use `sts:GetCallerIdentity`. `s3.test` only needs to
read the fixture; `s3:ListBucket` is useful for missing-key diagnostics.

The function tests need more, since they create and delete their own buckets:
`s3:ListAllMyBuckets`, `s3:CreateBucket`, `s3:ListBucket`, `s3:GetBucketTagging`,
`s3:PutBucketTagging`, `s3:GetBucketVersioning`, `s3:PutBucketVersioning`,
`s3:GetBucketPublicAccessBlock`, `s3:PutBucketPublicAccessBlock`, `s3:ListBucketVersions`,
`s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion` and `s3:DeleteBucket`.

Data is encrypted at rest and AWS traffic uses TLS. Storage, requests and data
transfer incur [S3 charges](https://aws.amazon.com/s3/pricing/) until cleanup.
For longer-lived fixtures, enable access logging, CloudTrail S3 data events and
CloudWatch request metrics; these can add charges and are not created by the scripts.

Local script tests use fake AWS commands and do not contact AWS:

```bash
python3 -m unittest discover -s test/scripts -p 'test_s3_fixtures.py' -v
```

The suite also executes the S3 Tables row check against in-memory data when it finds
`DUCKDB_BIN`, `duckdb` on `PATH`, or `build/release/duckdb`. Otherwise that check skips.
