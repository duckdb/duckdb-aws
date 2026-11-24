#!/usr/bin/env python3
"""AWS credential_process helper for the offline secret-refresh test.

Every invocation bumps <state_dir>/counter and emits a fresh key pair
"refresh_key_<N>" in the credential_process JSON format (version 1), with an
Expiration one hour out. The stub S3 server (stub_s3_server.py) accepts a key
iff its counter value is >= <state_dir>/min_valid.txt, so a test can revoke all
keys issued so far by writing a higher number to that file: the next S3 request
400s with ExpiredToken, and a working refresh path re-runs this process and
retries with the new key.

The AWS SDK appends `2>&1` to the configured command, so nothing may be printed
to stderr. Keep stdout as the JSON document only.
"""
import datetime
import json
import os
import sys


def main() -> int:
    if len(sys.argv) != 2:
        return 1
    state_dir = sys.argv[1]
    counter_path = os.path.join(state_dir, "counter")
    try:
        with open(counter_path, "r", encoding="utf-8") as handle:
            counter = int(handle.read().strip() or "0")
    except (OSError, ValueError):
        counter = 0
    counter += 1
    with open(counter_path, "w", encoding="utf-8") as handle:
        handle.write(str(counter))

    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    print(
        json.dumps(
            {
                "Version": 1,
                "AccessKeyId": "refresh_key_%d" % counter,
                "SecretAccessKey": "refresh_secret_%d" % counter,
                "SessionToken": "refresh_session_%d" % counter,
                "Expiration": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
