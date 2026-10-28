#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import sys
import tempfile


def sql_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def dollar_quote(statement):
    tag = ""
    while f"${tag}$" in statement:
        tag += "quack"
    delimiter = f"${tag}$"
    return f"{delimiter}\n{statement}\n{delimiter}"


def secret_sql(name, credentials, region):
    fields = {
        "KEY_ID": credentials["AccessKeyId"],
        "SECRET": credentials["SecretAccessKey"],
        "SESSION_TOKEN": credentials["SessionToken"],
        "REGION": region,
    }
    options = ",\n".join(f"    {field} {sql_quote(value)}" for field, value in fields.items())
    return (
        f"CREATE OR REPLACE TEMPORARY SECRET {name} (\n"
        "    TYPE aws,\n"
        "    PROVIDER config,\n"
        f"{options}\n);"
    )


def connection_sql(config, stack):
    handle = f"MAP {{'stack_id': {sql_quote(stack['id'])}, 'region': {sql_quote(config.region)}}}"
    return (
        "SET VARIABLE quack_bootstrap_outputs = (\n"
        "    SELECT CASE WHEN status IN ('CREATE_COMPLETE', 'UPDATE_COMPLETE') THEN outputs\n"
        "           ELSE error('Quack stack is not ready') END\n"
        f"    FROM cloudformation_describe_stack({handle})\n);\n"
        "SET VARIABLE quack_bootstrap_uri = getvariable('quack_bootstrap_outputs')['QuackURI'];\n"
        "SET VARIABLE quack_bootstrap_token = json_extract_string(getvariable('quack_bootstrap_outputs')['Token'], '$.\"1\"');\n"
        "SELECT CASE WHEN coalesce(getvariable('quack_bootstrap_uri'), '') <> ''\n"
        "                 AND coalesce(getvariable('quack_bootstrap_token'), '') <> ''\n"
        "            THEN true ELSE error('Quack stack is missing connection outputs') END AS connection_ready;"
    )


def direct_query_sql(statement):
    return (
        "SELECT * FROM quack_query(getvariable('quack_bootstrap_uri'), "
        f"{dollar_quote(statement)}, token := getvariable('quack_bootstrap_token'));"
    )


def connection_option(name, value):
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"{name}='{escaped}'"


def attachment_guard_sql(config, cluster):
    alias = f"redshift_{config.setup_id}"
    option_pattern = r"(?:^| )([a-z_]+=(?:'(?:\\.|[^'\\])*'|[^ ]+))"
    matches = []
    for name, value in (("host", cluster["host"]), ("port", cluster["port"]), ("dbname", cluster["database"])):
        quoted = sql_quote(connection_option(name, value))
        unquoted = sql_quote(f"{name}={value}")
        matches.append(f"(list_contains(options, {quoted}) OR list_contains(options, {unquoted}))")
    libpq_matches = " AND ".join(matches)
    # Expired catalogs cannot answer identity queries; check their stored target before replacing them.
    return (
        "WITH attached AS (\n"
        f"    SELECT type, path, regexp_extract_all(path, {sql_quote(option_pattern)}, 1) AS options\n"
        f"    FROM duckdb_databases() WHERE database_name = {sql_quote(alias)}\n)\n"
        "SELECT CASE WHEN count(*) = 0 THEN true\n"
        "            WHEN count(*) = 1 AND bool_and(type = 'postgres' AND (\n"
        f"                path = {sql_quote(cluster['arn'])} OR path = {sql_quote(cluster['name'])}\n"
        f"                OR ({libpq_matches}))) THEN true\n"
        "            ELSE error('Remote test alias has a different or unverified target; refusing to refresh it')\n"
        "       END AS target_matches FROM attached;"
    )


def identity_sql(config, cluster):
    alias = f"redshift_{config.setup_id}"
    query = "SELECT current_namespace AS namespace_id, current_database() AS database_name"
    return (
        f"SELECT CASE WHEN namespace_id = {sql_quote(cluster['arn'].rsplit(':', 1)[1])}"
        f" AND database_name = {sql_quote(cluster['database'])}"
        " THEN true ELSE error('Redshift attachment identity mismatch') END AS identity_matches\n"
        f"FROM postgres_query({sql_quote(alias)}, {sql_quote(query)});"
    )


def bootstrap_sql(config, cluster, stack, credentials):
    alias = f"redshift_{config.setup_id}"
    attach = (
        f"ATTACH OR REPLACE {sql_quote(cluster['arn'])} AS {alias} (\n"
        "    SECRET quack_redshift_test,\n"
        f"    HOST {sql_quote(cluster['host'])},\n"
        f"    PORT {sql_quote(cluster['port'])},\n"
        f"    DATABASE {sql_quote(cluster['database'])}\n);"
    )
    statements = [
        connection_sql(config, stack),
        direct_query_sql("CALL disable_logging();"),
        direct_query_sql("LOAD httpfs;"),
        direct_query_sql("LOAD aws;"),
        direct_query_sql(attachment_guard_sql(config, cluster)),
        direct_query_sql(secret_sql("quack_redshift_test", credentials, config.region)),
        direct_query_sql(attach),
        direct_query_sql(identity_sql(config, cluster)),
    ]
    return "\n\n".join(statements)


def render_manual_test(config, cluster, stack, credentials):
    alias = f"redshift_{config.setup_id}"
    trace_logging = "CALL enable_logging(level='trace', storage='stdout');"
    remote_query = f"SELECT count(*) AS category_rows FROM {alias}.public.category;"
    attach = (
        f"ATTACH OR REPLACE {sql_quote(cluster['arn'])} AS {alias} (\n"
        "    SECRET quack_redshift_test,\n"
        f"    DATABASE {sql_quote(cluster['database'])}\n);"
    )
    statements = [
        trace_logging,
        "-- Contains temporary AWS credentials. Do not share or commit this file.",
        "-- Python prepared the remote attachment. Run this soon after generation in a fresh session.",
        "CALL disable_logging();",
        "LOAD httpfs;",
        "LOAD aws;",
        "LOAD quack;",
        "",
        secret_sql("quack_auth", credentials, config.region),
        "",
        "-- Optional: creates another billable EC2 instance; configure its Redshift ingress separately.\n"
        "-- CREATE EXTERNAL RESOURCE 'aws:cloudformation:quack-on-ec2' AS remote "
        f"(REGION {sql_quote(config.region)}, TEMPLATE {sql_quote(config.template)});",
        "REGISTER EXTERNAL RESOURCE 'aws:cloudformation:quack-on-ec2' AS existing_quack\n"
        f"FROM MAP {{'stack_id': {sql_quote(stack['id'])}, 'region': {sql_quote(config.region)}}};",
        "ATTACH TO EXTERNAL RESOURCE existing_quack AS quack;",
        "",
        "CALL quack.query('CALL disable_logging();');",
        "CALL quack.query('LOAD httpfs;');",
        "CALL quack.query('LOAD aws;');",
        f"CALL quack.query({dollar_quote(secret_sql('quack_redshift_test', credentials, config.region))});",
        f"CALL quack.query({dollar_quote(attach)});",
        "",
        f"CALL quack.query({dollar_quote(trace_logging)});",
        trace_logging,
        f"SELECT * FROM quack.query({dollar_quote(remote_query)});",
        "SELECT * FROM quack.query('PRAGMA platform');",
        trace_logging,
    ]
    return "\n".join(statements) + "\n"


def write_atomically(path, text):
    path = Path(path)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", text=True)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write(text)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


if __name__ == "__main__":
    from quack_redshift import main

    parser = argparse.ArgumentParser(description="Prepare the saved Quack/Redshift setup and generate private manual-test SQL.")
    parser.add_argument("--force", action="store_true", help="Prepare the remote test attachment and write private SQL; otherwise preview only")
    arguments = parser.parse_args()
    sys.exit(main(["manual-test", *(["--force"] if arguments.force else [])]))
