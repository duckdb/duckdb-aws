#!/usr/bin/env python3
"""Regenerate the S3, S3 Tables and system-table function reference blocks from a local extension build.

Reads registered metadata without executing examples. Text outside the generated markers
is preserved; --check reports stale blocks without writing.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD_DIR = REPO_ROOT / "build" / "release"
DEFAULT_README = REPO_ROOT / "README.md"

# The category a function registers through Documented() places it in one of these README blocks.
FAMILIES = ("s3", "s3tables", "system-tables")
# Every function with one of these prefixes is public and must be documented.
PUBLIC_PREFIXES = ("s3_", "s3tables_", "aws_system_")
END_MARKER = "<!-- /generated -->"
OPTION_IN_EXAMPLE = re.compile(r"\b(\w+)\s*:=")

# Every table function the extension registers; filtering happens in Python, so a function that
# lost its documentation is reported rather than silently dropped by a `categories` filter.
QUERY = """
SELECT function_name, function_oid, parameters, parameter_types, description, examples, categories
FROM duckdb_functions()
WHERE extension_name = 'aws' AND function_type = 'table'
ORDER BY function_oid;
"""


class GenerationError(Exception):
    pass


def start_marker(family):
    return f"<!-- generated:{family} -->"


def sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def is_public(function_name):
    return not function_name.startswith("__") and function_name.startswith(PUBLIC_PREFIXES)


def family_of(overloads):
    return overloads[0]["categories"][0]


def load_functions(duckdb, extension):
    commands = f"LOAD {sql_literal(extension)};\nSET enable_external_access = false;\n{QUERY}\n"
    # Only what the CLI needs to start; AWS_*, DUCKDB_* and fixture variables stay out.
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ}
    try:
        result = subprocess.run(
            [str(duckdb), "-no-init", "-no-agent", "-batch", "-bail", "-json", "-unsigned"],
            input=commands,
            text=True,
            capture_output=True,
            timeout=120,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GenerationError(f"could not run {duckdb}: {error}") from error
    if result.returncode != 0:
        raise GenerationError(f"duckdb failed loading {extension}:\n{result.stderr.strip()}")
    output = result.stdout.strip()
    if not output:
        return []
    try:
        rows = json.loads(output)
    except json.JSONDecodeError as error:
        raise GenerationError(f"duckdb returned no JSON result:\n{output[:500]}") from error
    if not isinstance(rows, list):
        raise GenerationError(f"duckdb returned an unexpected result: {output[:500]}")
    return rows


def public_functions(rows):
    # function_oid follows registration order; show the name/ARN overload before its handle form.
    by_function = {}
    for row in rows:
        name = row["function_name"]
        if not is_public(name):
            continue
        by_function.setdefault(name, []).append(row)

    def overload_key(row):
        types = row["parameter_types"] or []
        return (bool(types) and types[0].startswith("MAP("), len(row["parameters"] or []), row["parameters"] or [])

    for overloads in by_function.values():
        overloads.sort(key=overload_key)
    return dict(sorted(by_function.items(), key=lambda item: min(row["function_oid"] for row in item[1])))


def validate_documentation(by_function):
    problems = []
    for name, overloads in by_function.items():
        for row in overloads:
            signature = f"{name}({', '.join(row['parameters'] or [])})"
            if not row["description"]:
                problems.append(f"{signature}: no description")
            if not row["examples"]:
                problems.append(f"{signature}: no example")
            elif not row["examples"][0].startswith(f"FROM {name}("):
                problems.append(f"{signature}: example does not call {name}: {row['examples'][0]!r}")
            categories = row["categories"] or []
            if len(categories) != 1 or categories[0] not in FAMILIES:
                problems.append(f"{signature}: categories {categories!r}, expected one of {list(FAMILIES)!r}")
    if problems:
        raise GenerationError(
            "undocumented or misdocumented public functions (register them through Documented()):\n  "
            + "\n  ".join(problems)
        )
    for family in FAMILIES:
        if not any(family_of(overloads) == family for overloads in by_function.values()):
            raise GenerationError(f"no public function in category {family!r}; is the build from this source tree?")


def common_suffix(parameter_lists):
    suffix = []
    for names in zip(*(reversed(names) for names in parameter_lists)):
        if len(set(names)) != 1:
            break
        suffix.append(names[0])
    return list(reversed(suffix))


def split_options(by_function):
    """Infer options because the catalog flattens positional parameters and typed kwargs.

    The option vocabulary is every name passed with `:=` in a registered example plus the
    parameter suffix all overloads of a function share. A single-overload function whose last
    positional parameter is named like an option (region, say) would be misread; none is today.
    """
    vocabulary = set()
    option_count = {}
    for name, rows in by_function.items():
        for row in rows:
            vocabulary.update(OPTION_IN_EXAMPLE.findall(row["examples"][0]))
        if len(rows) > 1:
            suffix = common_suffix([row["parameters"] or [] for row in rows])
            option_count[name] = len(suffix)
            vocabulary.update(suffix)
    for name, rows in by_function.items():
        if len(rows) == 1:
            count = 0
            for parameter in reversed(rows[0]["parameters"] or []):
                if parameter not in vocabulary:
                    break
                count += 1
            option_count[name] = count
    return option_count


def render(by_function, option_count):
    sections = []
    for name, overloads in by_function.items():
        count = option_count[name]
        signatures = []
        for row in overloads:
            parameters = row["parameters"] or []
            types = row["parameter_types"] or []
            positional = parameters[: len(parameters) - count]
            params = ", ".join(f"{p} {t}" for p, t in zip(positional, types))
            signatures.append(f"- `{name}({params})`")
        first = overloads[0]
        example = first["examples"][0].rstrip()
        if not example.endswith(";"):
            example += ";"
        lines = [f"#### `{name}`", "", "```sql", example, "```", "", first["description"], "", "Signatures:", ""]
        lines.extend(signatures)
        parameters = first["parameters"] or []
        types = first["parameter_types"] or []
        options = parameters[len(parameters) - count :]
        option_types = types[len(types) - count :]
        if options:
            lines.extend(["", "Options:", ""])
            lines.extend(f"- `{o} := {t}`" for o, t in zip(options, option_types))
        sections.append("\n".join(lines))
    return "\n\n".join(sections)


def find_blocks(text):
    """Validate all markers before returning the replaceable body offsets."""
    starts = []
    for family in FAMILIES:
        marker = start_marker(family)
        first = text.find(marker)
        if first < 0:
            raise GenerationError(f"README has no '{marker}' marker")
        if text.find(marker, first + len(marker)) >= 0:
            raise GenerationError(f"README has more than one '{marker}' marker")
        starts.append((first, family))
    starts.sort()

    blocks = {}
    for index, (position, family) in enumerate(starts):
        body_start = position + len(start_marker(family))
        next_start = starts[index + 1][0] if index + 1 < len(starts) else len(text)
        end = text.find(END_MARKER, body_start)
        if end < 0 or end > next_start:
            raise GenerationError(f"README's '{start_marker(family)}' block is not closed by '{END_MARKER}'")
        blocks[family] = (body_start, end)
    if text.count(END_MARKER) != len(blocks):
        raise GenerationError(f"README has an '{END_MARKER}' marker that closes no generated block")
    return blocks


def replace_blocks(text, bodies):
    blocks = find_blocks(text)
    pieces = []
    cursor = 0
    for family, (start, end) in sorted(blocks.items(), key=lambda item: item[1]):
        pieces.append(text[cursor:start])
        pieces.append("\n" + bodies[family] + "\n")
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def generate(readme_text, rows):
    find_blocks(readme_text)
    by_function = public_functions(rows)
    validate_documentation(by_function)
    option_count = split_options(by_function)
    bodies = {}
    for family in FAMILIES:
        members = {name: overloads for name, overloads in by_function.items() if family_of(overloads) == family}
        bodies[family] = render(members, option_count)
    return replace_blocks(readme_text, bodies)


def write_atomically(path, text):
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        # mkstemp creates 0600; the tracked file keeps its own permissions
        os.chmod(temporary, os.stat(path).st_mode)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR, help="DuckDB build with the aws extension")
    parser.add_argument("--readme", type=Path, default=DEFAULT_README, help="file holding the generated blocks")
    parser.add_argument("--check", action="store_true", help="exit 1 if the reference is out of date; change nothing")
    args = parser.parse_args(argv)

    duckdb = args.build_dir / "duckdb"
    extension = args.build_dir / "extension" / "aws" / "aws.duckdb_extension"
    try:
        for path in (duckdb, extension):
            if not path.is_file():
                raise GenerationError(f"not found: {path}; build the extension first")
        if not args.readme.is_file():
            raise GenerationError(f"not found: {args.readme}")
        with args.readme.open(encoding="utf-8", newline="") as stream:
            text = stream.read()
        find_blocks(text)
        updated = generate(text, load_functions(duckdb, extension))
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if updated == text:
        print(f"{args.readme}: generated function reference is up to date")
        return 0
    if args.check:
        print(f"{args.readme}: generated function reference is out of date; run {Path(__file__).name}", file=sys.stderr)
        return 1
    write_atomically(args.readme, updated)
    print(f"updated {args.readme}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
