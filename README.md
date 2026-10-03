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

## Redshift Tests

The Redshift tests use `postgres_scanner`, which is built as a loadable extension but is not statically linked into the local DuckDB binary. From the repository root, start DuckDB with unsigned extension loading enabled:

```bash
./build/release/duckdb -unsigned
```

Then load the locally built extension:

```sql
LOAD './build/release/extension/postgres_scanner/postgres_scanner.duckdb_extension';
```

## Documentation

See the [AWS page in the DuckDB documentation](https://duckdb.org/docs/extensions/aws).
