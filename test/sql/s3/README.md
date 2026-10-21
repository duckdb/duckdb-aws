# Private S3 bucket tests

These scripts provision a general-purpose S3 bucket for native DuckDB tests and
manual browser examples.

## Setup

Prerequisites: Bash, a current AWS CLI v2, `jq`, `curl`, `gzip`, and an authenticated
AWS profile or exported AWS credentials. The native test needs a DuckDB build with
`aws` and `httpfs`. Setup and cleanup are opt-in; normal tests do not create resources.

From the repository root:

```bash
export AWS_PROFILE=my-test-profile
export AWS_REGION=eu-central-1
./scripts/s3/create_bucket.sh
./scripts/s3/create_bucket.sh --force
source test/sql/s3/s3.env
./build/release/test/unittest 'test/sql/s3/*'
```

Without `--force`, setup and cleanup only print a plan. They do not call AWS.
With `--force`, setup creates or reuses
`$PREFIX-duckdb-aws-$AWS_ACCOUNT_ID-$AWS_REGION`, where `PREFIX` defaults to your
Unix username. Use lowercase letters, digits and hyphens in the prefix, or set
`S3_BUCKET_NAME` explicitly. Bucket names are globally unique. Dotted names are
not supported by these scripts because the browser example uses HTTPS virtual-hosted access.

The bucket contains:

- `duckdb-fixture/data.csv.gz`: the three rows in [data.csv](data.csv). Setup replaces
  this fixture on each run, and `s3.test` checks the exact rows through an S3 secret.
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
SQL test skips unless this guard is set. Merely having AWS credentials in your shell
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

Use the generated configuration to preserve any naming overrides:

```bash
source test/sql/s3/s3.env
./scripts/s3/destroy_bucket.sh
./scripts/s3/destroy_bucket.sh --force
unset S3_TEST_AVAILABLE
```

Cleanup verifies account, region, tags and versioning, refuses unrelated objects,
then deletes only the two named objects and the bucket. It does not recursively
empty a bucket. Once the test object is gone, cleanup removes a matching generated
environment file even if a later step fails. Already-sourced shells retain their
variables, so unset the guard there. Do not run setup or cleanup concurrently.

## Permissions, costs and local checks

Use a dedicated test identity scoped to the bucket and its objects. Setup needs
`s3:CreateBucket`, `s3:ListBucket`, `s3:GetBucketLocation`, `s3:GetBucketVersioning`,
`s3:GetBucketTagging`, `s3:PutBucketTagging`, `s3:PutBucketOwnershipControls`,
`s3:PutBucketPublicAccessBlock`, `s3:PutEncryptionConfiguration`, `s3:PutBucketCORS`,
`s3:PutObject`, and `s3:GetObject`. Cleanup additionally needs `s3:DeleteObject` and
`s3:DeleteBucket`. The scripts also use `sts:GetCallerIdentity`. The test reader only
needs access to read the fixture; `s3:ListBucket` is useful for missing-key diagnostics.

Data is encrypted at rest and AWS traffic uses TLS. Storage, requests and data
transfer incur [S3 charges](https://aws.amazon.com/s3/pricing/) until cleanup.
For longer-lived fixtures, enable access logging, CloudTrail S3 data events and
CloudWatch request metrics; these can add charges and are not created by the scripts.

Local script tests use fake AWS commands and do not contact AWS:

```bash
python3 -m unittest discover -s test/scripts -p 'test_s3_fixtures.py' -v
```
