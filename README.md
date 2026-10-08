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

## Tests

- [Redshift test setup](test/sql/redshift/README.md)

## Configured S3 endpoints

`TYPE s3` secrets using `PROVIDER credential_chain` pick up endpoint URLs from
AWS environment variables and the selected AWS config profile. For example:

```ini
[profile local-s3]
region = us-east-1
services = local-services

[services local-services]
s3 =
  endpoint_url = http://localhost:9000
```

With credentials for `local-s3` in your AWS credentials file:

```sql
CREATE SECRET (
    TYPE s3, PROVIDER credential_chain, CHAIN 'config',
    PROFILE 'local-s3', URL_STYLE 'path'
);
```

Explicit SQL `ENDPOINT` options override configured endpoints. Otherwise, the
AWS SDK resolves `AWS_ENDPOINT_URL_S3`, `AWS_ENDPOINT_URL`, the profile's
service-specific endpoint, then its profile-level `endpoint_url`, honoring the
SDK's configured-endpoint ignore flags. Without a configured endpoint, existing
defaults apply. HTTP/HTTPS schemes, ports, and base paths are preserved.

Addressing-style settings in AWS config are not imported; specify
`URL_STYLE 'path'` when your S3-compatible service requires it.

## Documentation

See the [AWS page in the DuckDB documentation](https://duckdb.org/docs/extensions/aws).
