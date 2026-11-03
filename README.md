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

## Tests

- [Redshift test setup](test/sql/redshift/README.md)

## Documentation

See the [AWS page in the DuckDB documentation](https://duckdb.org/docs/extensions/aws).
