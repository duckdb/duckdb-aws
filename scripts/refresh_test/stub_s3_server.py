#!/usr/bin/env python3
"""Minimal S3-compatible HTTP stub for the offline secret-refresh test.

Serves the objects under <state_dir>/objects/<bucket>/<key> (path-style URLs
only) and decides authorization purely from the SigV4 key id in the
Authorization header:

- key id matching refresh_key_<N> with N >= int(<state_dir>/min_valid.txt)
  (file absent -> 0): request is served.
- key id matching refresh_key_<N> with a lower N: 400 with an ExpiredToken
  error document -- exactly what S3 returns for expired temporary credentials,
  and what duckdb-httpfs's refresh trigger matches on.
- anything else: 403 InvalidAccessKeyId.

A test revokes every key issued so far by writing a higher number to
min_valid.txt (reachable from SQL via COPY TO), which makes credential expiry
deterministic: no clocks, no sleeps.

Usage: stub_s3_server.py <state_dir> [port]
Prints "LISTENING <port>" on stdout once ready.
"""
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY_PATTERN = re.compile(r"Credential=refresh_key_(\d+)/")

EXPIRED_TOKEN_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<Error><Code>ExpiredToken</Code><Message>The provided token has expired."
    "</Message></Error>"
)
INVALID_KEY_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<Error><Code>InvalidAccessKeyId</Code><Message>The AWS Access Key Id you "
    "provided does not exist in our records.</Message></Error>"
)
NO_SUCH_KEY_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist."
    "</Message></Error>"
)


class StubS3Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state_dir = None

    def log_message(self, fmt, *args):  # quiet; the test reads nothing from us
        pass

    def _send_error(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _min_valid(self):
        try:
            with open(os.path.join(self.state_dir, "min_valid.txt"), "r", encoding="utf-8") as handle:
                return int(handle.read().strip().splitlines()[0])
        except (OSError, ValueError, IndexError):
            return 0

    def _check_auth(self):
        auth = self.headers.get("Authorization", "")
        match = KEY_PATTERN.search(auth)
        if not match:
            self._send_error(403, INVALID_KEY_BODY)
            return False
        if int(match.group(1)) < self._min_valid():
            self._send_error(400, EXPIRED_TOKEN_BODY)
            return False
        return True

    def _object_path(self):
        path = self.path.split("?", 1)[0]
        parts = [p for p in path.split("/") if p]
        candidate = os.path.realpath(os.path.join(self.state_dir, "objects", *parts))
        root = os.path.realpath(os.path.join(self.state_dir, "objects"))
        if not candidate.startswith(root + os.sep):
            return None
        return candidate

    def _serve(self, send_body):
        if not self._check_auth():
            return
        object_path = self._object_path()
        if not object_path or not os.path.isfile(object_path):
            self._send_error(404, NO_SUCH_KEY_BODY)
            return
        with open(object_path, "rb") as handle:
            data = handle.read()

        range_header = self.headers.get("Range")
        start, end = 0, len(data) - 1
        is_range = False
        if range_header:
            range_match = re.match(r"bytes=(\d*)-(\d*)$", range_header.strip())
            if range_match and (range_match.group(1) or range_match.group(2)):
                is_range = True
                if range_match.group(1):
                    start = int(range_match.group(1))
                    if range_match.group(2):
                        end = min(int(range_match.group(2)), len(data) - 1)
                else:  # suffix range: last N bytes
                    start = max(len(data) - int(range_match.group(2)), 0)
                if start >= len(data):
                    self.send_response(416)
                    self.send_header("Content-Range", "bytes */%d" % len(data))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

        body = data[start : end + 1]
        self.send_response(206 if is_range else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(len(body)))
        if is_range:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, len(data)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def do_GET(self):
        self._serve(send_body=True)

    def do_HEAD(self):
        self._serve(send_body=False)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: stub_s3_server.py <state_dir> [port]", file=sys.stderr)
        return 1
    StubS3Handler.state_dir = os.path.realpath(sys.argv[1])
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    server = ThreadingHTTPServer(("127.0.0.1", port), StubS3Handler)
    print("LISTENING %d" % server.server_address[1], flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
