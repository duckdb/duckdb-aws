#!/usr/bin/env python3

import argparse
from datetime import datetime, timezone
import os
import subprocess
import sys

from generate_manual_test_with_secrets import secret_sql
from quack_redshift import CREDENTIAL_FIELDS, SetupError, aws, require


def validate_credentials(credentials, now):
    require(isinstance(credentials, dict), "AWS CLI did not export temporary credentials")
    for field in CREDENTIAL_FIELDS:
        require(isinstance(credentials.get(field), str) and credentials[field], f"AWS CLI export is missing {field}")
    expiration = credentials.get("Expiration")
    require(isinstance(expiration, str) and expiration, "AWS CLI export is missing Expiration")
    try:
        expires_at = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
    except ValueError:
        raise SetupError("AWS CLI exported an invalid expiration timestamp") from None
    require(expires_at.tzinfo is not None, "AWS CLI expiration timestamp has no timezone")
    remaining = (expires_at - now).total_seconds()
    require(remaining > 0, "Exported credentials have expired; sign in again")
    require(remaining <= 900, "Exported credentials last longer than 15 minutes; use an aws login profile")


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Print AWS session credentials as a temporary DuckDB secret.")
    parser.add_argument("--force", action="store_true", help="Print credentials to stdout; otherwise preview without exporting")
    config = parser.parse_args(arguments)
    if not config.force:
        print("Preview only. Add --force (or FORCE=1 with make) to print private credential SQL.", file=sys.stderr)
        return 0
    try:
        config.profile = os.environ.get("AWS_PROFILE", "")
        config.region = os.environ.get("AWS_REGION", "")
        require(config.profile and config.region, "Set AWS_PROFILE and AWS_REGION")
        try:
            credentials = aws(config, ["configure", "export-credentials", "--format", "process"])
        except SetupError:
            raise SetupError("AWS CLI credential export failed; check the selected profile and login") from None
        validate_credentials(credentials, datetime.now(timezone.utc))
        print(secret_sql("aws_session_token", credentials, config.region))
        return 0
    except SetupError as error:
        print(f"error: {error}", file=sys.stderr)
    except (OSError, subprocess.TimeoutExpired):
        print("error: AWS CLI could not run or timed out; check the CLI installation and profile login", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
