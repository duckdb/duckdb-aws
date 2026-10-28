#!/usr/bin/env python3

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATE = "https://quack-on-ec2-259911478022.s3.amazonaws.com/quack.yaml"
TEMPLATE_REGIONS = {"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-central-1"}
RESOURCE_TYPE = "aws:cloudformation:quack-on-ec2"
MANAGED_BY = "duckdb-quack-redshift-test"
CREDENTIAL_FIELDS = {
    "AccessKeyId": "AWS_ACCESS_KEY_ID",
    "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
    "SessionToken": "AWS_SESSION_TOKEN",
}
ENV_FIELDS = {
    "AWS_REDSHIFT_CLUSTER_NAME", "AWS_REDSHIFT_ARN", "AWS_REDSHIFT_HOST",
    "AWS_REDSHIFT_DATABASE", "AWS_REGION",
}
STACK_QUERY = (
    "Stacks[0].{id:StackId,name:StackName,status:StackStatus,tags:Tags,"
    "instance:Outputs[?OutputKey==`InstanceId`].OutputValue|[0],"
    "uri:Outputs[?OutputKey==`QuackURI`].OutputValue|[0]}"
)
CLUSTER_QUERY = (
    "Clusters[0].{name:ClusterIdentifier,arn:ClusterNamespaceArn,status:ClusterStatus,"
    "vpc:VpcId,host:Endpoint.Address,port:Endpoint.Port,database:DBName,"
    "groups:VpcSecurityGroups[].VpcSecurityGroupId}"
)


class SetupError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SetupError(message)


def sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def sql_map(values):
    return "MAP {" + ", ".join(f"{sql_literal(k)}: {sql_literal(v)}" for k, v in values.items()) + "}"


def profile_environment(config):
    environment = os.environ.copy()
    for name in (*CREDENTIAL_FIELDS.values(), "AWS_CREDENTIAL_EXPIRATION", "AWS_DEFAULT_PROFILE"):
        environment.pop(name, None)
    environment.update(
        AWS_PROFILE=config.profile, AWS_REGION=config.region, AWS_DEFAULT_REGION=config.region,
        AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off",
    )
    return environment


def run_command(command, environment, timeout, input_text=None, capture=True):
    with subprocess.Popen(
        command, env=environment, text=True, start_new_session=True,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    ) as process:
        try:
            stdout, stderr = process.communicate(input_text, timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def aws(config, arguments, query=None, missing=(), environment=None, timeout=90):
    command = ["aws", "--no-cli-pager", "--region", config.region]
    if environment is None:
        command += ["--profile", config.profile]
    command += list(arguments) + ["--output", "json"]
    if query:
        command += ["--query", query]
    result = run_command(
        command, environment if environment is not None else profile_environment(config), timeout,
    )
    if result.returncode:
        error = re.search(r"\(([A-Za-z0-9_.-]+)\)", result.stderr)
        code = error[1] if error else "CLI error"
        if code in missing:
            return None
        if "StackNotFound" in missing and code == "ValidationError" and "does not exist" in result.stderr:
            return None
        raise SetupError(f"aws {' '.join(arguments[:2])} failed ({code}); check the selected profile and permissions")
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise SetupError(f"aws {' '.join(arguments[:2])} returned invalid JSON") from None


def export_credentials(config):
    credentials = aws(config, ["configure", "export-credentials", "--format", "process"])
    require(isinstance(credentials, dict), "AWS CLI did not export temporary credentials")
    for field in CREDENTIAL_FIELDS:
        require(isinstance(credentials.get(field), str) and credentials[field], f"AWS CLI export is missing {field}")
    environment = profile_environment(config)
    environment.pop("AWS_PROFILE", None)
    environment.update({variable: credentials[field] for field, variable in CREDENTIAL_FIELDS.items()})
    account = aws(config, ["sts", "get-caller-identity"], query="Account", environment=environment)
    require(account == config.account, "Exported credentials belong to a different AWS account")
    return credentials, environment


def read_redshift_env(path):
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"export ([A-Z_]+)=(.*)", line)
        if not match or match[1] not in ENV_FIELDS:
            continue
        try:
            value = shlex.split(match[2])
        except ValueError:
            raise SetupError(f"Invalid assignment for {match[1]} in {path}") from None
        require(len(value) == 1 and match[1] not in values, f"Invalid or duplicate {match[1]} in {path}")
        values[match[1]] = value[0]
    return values


def validate_arn(config, arn, service, resource_prefix):
    parts = str(arn).split(":", 5)
    require(
        len(parts) == 6 and parts[0] == "arn" and parts[2] == service
        and parts[3] == config.region and parts[4] == config.account
        and parts[5].startswith(resource_prefix),
        f"Expected a {service} {resource_prefix} ARN in account {config.account}, region {config.region}",
    )


def validate_env(config, values):
    if values:
        require(values.get("AWS_REGION") == config.region, "Redshift env-file region differs from AWS_REGION")
        require(
            values.get("AWS_REDSHIFT_CLUSTER_NAME") == config.cluster_name,
            "Redshift env-file cluster differs from PREFIX/AWS_REGION; select the matching prefix or another REDSHIFT_ENV_FILE",
        )
        validate_arn(config, values.get("AWS_REDSHIFT_ARN"), "redshift", "namespace:")


def describe_cluster(config):
    return aws(
        config, ["redshift", "describe-clusters", "--cluster-identifier", config.cluster_name],
        query=CLUSTER_QUERY, missing=("ClusterNotFound", "ClusterNotFoundFault"),
    )


def describe_stack(config, reference):
    return aws(
        config, ["cloudformation", "describe-stacks", "--stack-name", reference],
        query=STACK_QUERY, missing=("StackNotFound",),
    )


def describe_role(config, name):
    return aws(
        config, ["iam", "get-role", "--role-name", name],
        query="Role.{name:RoleName,id:RoleId}", missing=("NoSuchEntity",),
    )


def describe_groups(config, ids):
    require(bool(ids), "No security groups found")
    return aws(config, ["ec2", "describe-security-groups", "--group-ids", *ids], query="SecurityGroups")


def managed_redshift_group(config, cluster):
    groups = describe_groups(config, cluster["groups"])
    matches = []
    for group in groups:
        tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
        if tags.get("ManagedBy") == "duckdb-redshift-test" and tags.get("Cluster") == config.cluster_name:
            matches.append(group)
    require(len(matches) == 1, "Expected one Redshift security group managed by scripts/redshift/create_cluster.sh")
    require(matches[0]["VpcId"] == cluster["vpc"], "Redshift security group VPC mismatch")
    return matches[0]


def fresh_state(config):
    return {
        "version": 1, "account": config.account, "region": config.region,
        "prefix": config.prefix, "ingress": [],
    }


def load_state(config):
    if not config.state_path.exists():
        return fresh_state(config)
    try:
        state = json.loads(config.state_path.read_text())
    except (OSError, json.JSONDecodeError):
        raise SetupError(f"Cannot read setup state: {config.state_path}") from None
    require(
        isinstance(state, dict) and state.get("version") == 1 and state.get("account") == config.account
        and state.get("region") == config.region and state.get("prefix") == config.prefix,
        "Setup state belongs to a different account, region, or prefix",
    )
    return state


def save_state(config, state):
    descriptor, name = tempfile.mkstemp(dir=config.state_path.parent, prefix=".state-", text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(state, output, indent=2)
            output.write("\n")
        os.replace(name, config.state_path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def state_lock(config):
    config.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(config.state_path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError("Another command is using this setup state") from None
        yield


def duckdb(config, setup_sql, result_sql, environment, phase, timeout=120):
    commands = [".output /dev/null"]
    for extension in ("httpfs", "aws", "quack", "json"):
        path = config.build_dir / "extension" / extension / f"{extension}.duckdb_extension"
        commands.append(f"LOAD {sql_literal(path)};")
    commands += [
        "CALL disable_logging();",
        "SET http_timeout = 30;",
        "SET http_retries = 0;",
        f"CREATE SECRET setup_aws (TYPE aws, PROVIDER credential_chain, CHAIN 'env', REGION {sql_literal(config.region)});",
        setup_sql,
        ".output stdout",
        result_sql,
    ]
    try:
        result = run_command(
            [str(config.build_dir / "duckdb"), "-no-init", "-no-agent", "-batch", "-bail", "-json", "-unsigned"],
            environment, timeout, input_text="\n".join(commands) + "\n",
        )
    except subprocess.TimeoutExpired:
        raise SetupError(f"DuckDB {phase} timed out; remote work may still be running. Inspect state before retrying") from None
    # DuckDB errors can echo complete SQL, including remote credentials and tokens.
    require(result.returncode == 0, f"DuckDB {phase} failed; SQL and raw output withheld to avoid exposing credentials")
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise SetupError(f"DuckDB {phase} returned unexpected output; raw output withheld") from None
    require(isinstance(rows, list), f"DuckDB {phase} did not return rows")
    return rows


def template_parameters(config):
    return {"maxduration": str(config.max_hours), "machinetype": config.machine_type}


def validate_build(config):
    require((config.build_dir / "duckdb").is_file(), "Build DuckDB before running setup")
    for extension in ("aws", "httpfs", "quack", "json"):
        require((config.build_dir / "extension" / extension / f"{extension}.duckdb_extension").is_file(),
                f"Build the local {extension} extension before running setup")


def preflight(config, state):
    require(config.template != DEFAULT_TEMPLATE or config.region in TEMPLATE_REGIONS,
            "The default Quack AMI template does not support this region; use a compatible QUACK_TEMPLATE_URL")
    validate_build(config)
    values = read_redshift_env(config.env_file)
    validate_env(config, values)
    vpcs = aws(config, ["ec2", "describe-vpcs", "--filters", "Name=isDefault,Values=true"], query="Vpcs[].VpcId")
    require(len(vpcs) == 1, "The bundled Redshift/Quack workflow requires a default VPC")
    config.vpc = vpcs[0]
    require(os.environ.get("REDSHIFT_VPC_ID", config.vpc) == config.vpc,
            "This workflow requires Redshift and Quack in the default VPC")
    groups = aws(
        config, ["ec2", "describe-security-groups", "--filters",
                 f"Name=group-name,Values={config.cluster_name}-client", f"Name=vpc-id,Values={config.vpc}"],
        query="SecurityGroups",
    )
    for group in groups:
        tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
        require(tags.get("ManagedBy") == "duckdb-redshift-test" and tags.get("Cluster") == config.cluster_name,
                "The planned Redshift group name belongs to an unmanaged group")
    stack = describe_stack(config, config.stack_name)
    if stack:
        validate_stack(config, state, stack)
    else:
        require(not state.get("quack", {}).get("id"), "Saved Quack stack is absent; run cleanup before starting another setup")
    cluster = describe_cluster(config)
    if cluster:
        require(cluster["vpc"] == config.vpc, "Existing Redshift cluster is not in the default VPC")
        validate_arn(config, cluster["arn"], "redshift", "namespace:")
        if values:
            require(values["AWS_REDSHIFT_ARN"] == cluster["arn"], "Redshift env file identifies a different cluster")
        if state.get("redshift", {}).get("arn"):
            require(state["redshift"]["arn"] == cluster["arn"], "The saved Redshift cluster was replaced; refusing to adopt it")
        group = managed_redshift_group(config, cluster)
        require(group["GroupName"] == f"{config.cluster_name}-client",
                "Existing Redshift group does not match the companion creation script's naming")
    _, environment = export_credentials(config)
    rows = duckdb(
        config, "",
        f"SELECT capabilities FROM cloudformation_create_stack({sql_literal(config.template)}, "
        f"name := {sql_literal(config.stack_name)}, region := {sql_literal(config.region)}, "
        f"template_parameters := {sql_map(template_parameters(config))}, dry_run := true);",
        environment, "template validation",
    )
    require(len(rows) == 1, "CloudFormation template validation returned no result")
    return cluster


def capture_redshift(config, state):
    resource = state["redshift"]
    cluster = describe_cluster(config)
    if cluster:
        validate_arn(config, cluster["arn"], "redshift", "namespace:")
        require(not resource.get("arn") or resource["arn"] == cluster["arn"], "Redshift cluster was replaced")
        resource["arn"] = cluster["arn"]
    groups = aws(
        config, ["ec2", "describe-security-groups", "--filters",
                 f"Name=group-name,Values={config.cluster_name}-client", f"Name=vpc-id,Values={config.vpc}"],
        query="SecurityGroups",
    )
    if groups:
        require(len(groups) == 1, "Ambiguous Redshift security group")
        group = groups[0]
        tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
        require(tags.get("ManagedBy") == "duckdb-redshift-test" and tags.get("Cluster") == config.cluster_name,
                "Redshift group does not have the creation script's ownership tags")
        require(not resource.get("group_id") or resource["group_id"] == group["GroupId"], "Redshift security group was replaced")
        resource["group_id"] = group["GroupId"]
    role = describe_role(config, config.role_name)
    if role:
        require(not resource.get("role_id") or resource["role_id"] == role["id"], "IAM loader role was replaced")
        resource["role_id"] = role["id"]
    save_state(config, state)
    return cluster


def ensure_redshift(config, state, existing):
    if "redshift" not in state:
        groups = aws(
            config, ["ec2", "describe-security-groups", "--filters",
                     f"Name=group-name,Values={config.cluster_name}-client", f"Name=vpc-id,Values={config.vpc}"],
            query="SecurityGroups[].GroupId",
        )
        role = describe_role(config, config.role_name)
        state["redshift"] = {
            "name": config.cluster_name, "owned": existing is None,
            "role_name": config.role_name, "role_owned": existing is None and role is None,
            "group_owned": existing is None and not groups, "ready": False,
        }
        save_state(config, state)
    resource = state["redshift"]
    if not resource["ready"] or not config.env_file.is_file():
        print(f"Create/reuse Redshift: {config.cluster_name}", flush=True)
        environment = profile_environment(config)
        environment.update(PREFIX=config.prefix, REDSHIFT_ENV_FILE=str(config.env_file), REDSHIFT_VPC_ID=config.vpc)
        config.env_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = run_command(
                ["bash", str(ROOT / "scripts/redshift/create_cluster.sh"), "--force"],
                environment, config.wait_seconds, capture=False,
            )
            require(result.returncode == 0, "Redshift creation script failed; inspect the saved resources before retrying")
        finally:
            capture_redshift(config, state)
        resource["ready"] = True
        save_state(config, state)
    cluster = capture_redshift(config, state)
    require(cluster and cluster["status"] == "available", "Redshift cluster is not available; inspect it before retrying")
    values = read_redshift_env(config.env_file)
    validate_env(config, values)
    require(values.get("AWS_REDSHIFT_ARN") == cluster["arn"], "Redshift env-file ARN does not match the live cluster")
    return cluster


def wait_stack(config, state):
    deadline = time.monotonic() + config.wait_seconds
    while time.monotonic() < deadline:
        stack = describe_stack(config, state["quack"]["id"])
        require(stack is not None, "Quack stack disappeared while waiting")
        status = stack["status"]
        if status in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            require(stack["instance"] and stack["uri"], "Quack stack is missing InstanceId or QuackURI output")
            return stack
        require(not any(word in status for word in ("FAILED", "ROLLBACK", "DELETE")),
                f"Quack stack is {status}; inspect CloudFormation events. It will not be recreated automatically")
        print(f"Quack stack: {status}", flush=True)
        time.sleep(5)
    raise SetupError("Timed out waiting for Quack; the saved stack will be checked again on the next run")


def validate_stack(config, state, stack):
    validate_arn(config, stack["id"], "cloudformation", f"stack/{config.stack_name}/")
    tags = {tag["Key"]: tag["Value"] for tag in stack.get("tags", [])}
    require(tags.get("ManagedBy") == MANAGED_BY and tags.get("SetupId") == config.setup_id,
            "Quack stack name is already used by an unrelated stack")
    saved = state.get("quack", {})
    require(not saved.get("id") or saved["id"] == stack["id"], "Saved Quack stack was replaced; refusing to adopt it")
    require(not saved.get("template") or saved["template"] == config.template,
            "Quack template differs from the saved setup; use another PREFIX")
    require(not saved.get("parameters") or saved["parameters"] == template_parameters(config),
            "Quack parameters differ from the saved setup; use another PREFIX")


def ensure_quack(config, state):
    stack = describe_stack(config, config.stack_name)
    if stack:
        validate_stack(config, state, stack)
        state.setdefault("quack", {"name": config.stack_name, "owned": False})
        state["quack"]["id"] = stack["id"]
        save_state(config, state)
    else:
        require(not state.get("quack", {}).get("id"), "Saved Quack stack is absent; run cleanup before starting another setup")
        state["quack"] = {"name": config.stack_name, "owned": True, "template": config.template,
                          "parameters": template_parameters(config)}
        save_state(config, state)
        tags = {"ManagedBy": MANAGED_BY, "SetupId": config.setup_id,
                "duckdb-external-resource-type": RESOURCE_TYPE}
        _, environment = export_credentials(config)
        print(f"Create Quack stack: {config.stack_name}", flush=True)
        rows = duckdb(
            config, "",
            f"SELECT handle FROM cloudformation_create_stack({sql_literal(config.template)}, "
            f"name := {sql_literal(config.stack_name)}, region := {sql_literal(config.region)}, "
            f"template_parameters := {sql_map(template_parameters(config))}, tags := {sql_map(tags)});",
            environment, "Quack stack creation",
        )
        require(len(rows) == 1 and isinstance(rows[0].get("handle"), dict), "Quack create returned no stack handle")
        handle = rows[0]["handle"]
        validate_arn(config, handle.get("stack_id"), "cloudformation", f"stack/{config.stack_name}/")
        state["quack"]["id"] = handle["stack_id"]
        save_state(config, state)
    return wait_stack(config, state)


def network_targets(config, cluster, stack):
    instances = aws(
        config, ["ec2", "describe-instances", "--instance-ids", stack["instance"]],
        query="Reservations[].Instances[].{id:InstanceId,vpc:VpcId,state:State.Name,groups:SecurityGroups[].GroupId,tags:Tags}",
    )
    require(len(instances) == 1 and instances[0]["state"] == "running", "Quack EC2 instance is not running")
    instance = instances[0]
    tags = {tag["Key"]: tag["Value"] for tag in instance.get("tags", [])}
    require(tags.get("aws:cloudformation:stack-id") == stack["id"], "Quack instance belongs to another stack")
    require(instance["vpc"] == cluster["vpc"], "Quack and Redshift must be in the same VPC")
    groups = describe_groups(config, instance["groups"])
    owned_groups = []
    for group in groups:
        tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
        if tags.get("aws:cloudformation:stack-id") == stack["id"] and tags.get("aws:cloudformation:logical-id") == "QuackSG":
            owned_groups.append(group)
    require(len(owned_groups) == 1, "Expected one QuackSG on the stack's instance")
    target = managed_redshift_group(config, cluster)
    source = owned_groups[0]
    require(source["VpcId"] == target["VpcId"], "Security group VPC mismatch")
    port = cluster["port"]
    require(isinstance(port, int) and 1 <= port <= 65535, "Invalid Redshift endpoint port")
    return target, source["GroupId"], port


def rule_allows(group, source, port):
    for rule in group.get("IpPermissions", []):
        protocol = rule.get("IpProtocol")
        ports_match = protocol == "-1" or (
            protocol == "tcp" and rule.get("FromPort", 65536) <= port <= rule.get("ToPort", -1)
        )
        if ports_match and any(pair.get("GroupId") == source for pair in rule.get("UserIdGroupPairs", [])):
            return True
    return False


def ingress_rules(config, target):
    return aws(
        config, ["ec2", "describe-security-group-rules", "--filters", f"Name=group-id,Values={target}"],
        query="SecurityGroupRules", missing=("InvalidGroup.NotFound",),
    ) or []


def matching_rule(rule, link):
    return (
        not rule.get("IsEgress") and rule.get("GroupId") == link["target"]
        and rule.get("IpProtocol") == "tcp" and rule.get("FromPort") == link["port"]
        and rule.get("ToPort") == link["port"]
        and rule.get("ReferencedGroupInfo", {}).get("GroupId") == link["source"]
    )


def recover_ingress(config, state):
    for link in state["ingress"]:
        if link.get("id"):
            continue
        matches = [rule for rule in ingress_rules(config, link["target"])
                   if matching_rule(rule, link) and rule.get("Description") == f"{MANAGED_BY}:{config.setup_id}"]
        require(len(matches) <= 1, "Ambiguous pending ingress rule")
        if matches:
            link["id"] = matches[0]["SecurityGroupRuleId"]
    save_state(config, state)


def ensure_ingress(config, state, target, source, port):
    recover_ingress(config, state)
    if rule_allows(target, source, port):
        print(f"Ingress already allows {source} to {target['GroupId']} on TCP {port}")
        return
    link = next((entry for entry in state["ingress"]
                 if entry["target"] == target["GroupId"] and entry["source"] == source and entry["port"] == port), None)
    if link is None:
        link = {"target": target["GroupId"], "source": source, "port": port}
        state["ingress"].append(link)
    save_state(config, state)
    permission = [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                   "UserIdGroupPairs": [{"GroupId": source, "Description": f"{MANAGED_BY}:{config.setup_id}"}]}]
    result = aws(config, ["ec2", "authorize-security-group-ingress", "--group-id", target["GroupId"],
                          "--ip-permissions", json.dumps(permission)], missing=("InvalidPermission.Duplicate",))
    if result:
        rules = result.get("SecurityGroupRules", [])
        require(len(rules) == 1 and rules[0].get("SecurityGroupRuleId"), "AWS did not return the new ingress rule ID")
        link["id"] = rules[0]["SecurityGroupRuleId"]
        save_state(config, state)
    recover_ingress(config, state)
    actual = describe_groups(config, [target["GroupId"]])[0]
    require(rule_allows(actual, source, port), "Ingress rule was not visible on readback")
    print(f"Ingress allows {source} to {target['GroupId']} on TCP {port}")


def registration_sql(config, stack):
    handle = {"stack_id": stack["id"], "region": config.region}
    return (
        f"REGISTER EXTERNAL RESOURCE {sql_literal(RESOURCE_TYPE)} AS existing_quack FROM {sql_map(handle)};\n"
        "ATTACH TO EXTERNAL RESOURCE existing_quack AS quack;"
    )


def remote_alias(config):
    return f"redshift_{config.setup_id}"


def smoke_sql(config, stack, cluster, credentials):
    from generate_manual_test_with_secrets import bootstrap_sql

    commands = [bootstrap_sql(config, cluster, stack, credentials), registration_sql(config, stack)]
    remote_check = f"SELECT count(*) AS category_rows FROM {remote_alias(config)}.public.category;"
    return "\n".join(commands), f"SELECT * FROM quack.query({sql_literal(remote_check)});"


def check(config, state, cluster=None, stack=None):
    require(state.get("quack", {}).get("id") and state.get("redshift", {}).get("arn"), "Run setup first")
    cluster = cluster or describe_cluster(config)
    stack = stack or describe_stack(config, state["quack"]["id"])
    require(cluster and cluster["arn"] == state["redshift"]["arn"], "Saved Redshift cluster is absent or replaced")
    require(stack and stack["status"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE"), "Saved Quack stack is not ready")
    require(cluster["status"] == "available", "Redshift cluster is not available")
    validate_arn(config, cluster["arn"], "redshift", "namespace:")
    validate_stack(config, state, stack)
    target, source, port = network_targets(config, cluster, stack)
    require(rule_allows(target, source, port), "The Redshift ingress rule is missing; rerun setup")
    credentials, environment = export_credentials(config)
    setup_sql, result_sql = smoke_sql(config, stack, cluster, credentials)
    rows = duckdb(config, setup_sql, result_sql, environment, "remote Redshift smoke test")
    require(len(rows) == 1 and isinstance(rows[0].get("category_rows"), int) and rows[0]["category_rows"] > 0,
            "Remote TICKIT category query returned no data")
    state["last_check"] = datetime.now(timezone.utc).isoformat()
    save_state(config, state)
    print(f"Remote Redshift query passed: {rows[0]['category_rows']} TICKIT category rows")
    print(f"Remote database alias: {remote_alias(config)}")


def setup(config, state):
    if state.get("cleaned"):
        state.clear()
        state.update(fresh_state(config))
    existing = preflight(config, state)
    cluster = ensure_redshift(config, state, existing)
    stack = ensure_quack(config, state)
    target, source, port = network_targets(config, cluster, stack)
    ensure_ingress(config, state, target, source, port)
    check(config, state, cluster, stack)
    print(f"Redshift ARN: {cluster['arn']}")
    print(f"Quack stack ARN: {stack['id']}")
    print(f"Quack endpoint: {stack['uri']}")
    print(f"Resources retained. State: {config.state_path}")
    generate_manual_test(config, state, cluster, stack, prepared=True)


def generate_manual_test(config, state, cluster=None, stack=None, prepared=False):
    from generate_manual_test_with_secrets import render_manual_test, write_atomically

    require(not state.get("cleaned"), "This setup was cleaned up; run setup before generating manual-test SQL")
    require(state.get("quack", {}).get("id") and state.get("redshift", {}).get("arn"), "Run setup first")
    cluster = cluster or describe_cluster(config)
    stack = stack or describe_stack(config, state["quack"]["id"])
    require(cluster and cluster["arn"] == state["redshift"]["arn"], "Saved Redshift cluster is absent or replaced")
    require(cluster["status"] == "available", "Redshift cluster is not available")
    require(stack and stack["status"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE"), "Saved Quack stack is not ready")
    validate_arn(config, cluster["arn"], "redshift", "namespace:")
    validate_stack(config, state, stack)
    target, source, port = network_targets(config, cluster, stack)
    require(rule_allows(target, source, port), "The Redshift ingress rule is missing; rerun setup")
    require(config.manual_test_file not in (config.state_path, config.env_file), "The manual-test output must not overwrite setup state or the env file")
    require(config.manual_test_file.parent.is_dir(), "The manual-test output directory does not exist")
    require(not config.manual_test_file.is_symlink(), "The manual-test output must not be a symbolic link")
    if config.manual_test_file.exists():
        require(config.manual_test_file.is_file(), "The manual-test output must be a regular file")
    if config.manual_test_file.is_relative_to(ROOT):
        ignored = run_command(
            ["git", "-C", str(ROOT), "check-ignore", "-q", "--", str(config.manual_test_file)],
            profile_environment(config), 30,
        )
        require(ignored.returncode == 0, "The manual-test output must be git-ignored because it contains credentials")
    if not prepared:
        validate_build(config)
        check(config, state, cluster, stack)
    credentials, _ = export_credentials(config)
    write_atomically(config.manual_test_file, render_manual_test(config, cluster, stack, credentials))
    print(f"Wrote private manual-test SQL: {config.manual_test_file} (mode 0600)")
    if credentials.get("Expiration"):
        print(f"Credentials expire: {credentials['Expiration']}")
    print("Remote preparation passed. Generated SQL was not executed; run the private file soon in a fresh session")


def validate_cleanup(config, state):
    cluster = describe_cluster(config) if state.get("redshift") else None
    redshift = state.get("redshift", {})
    if cluster:
        require(redshift.get("arn") == cluster["arn"], "Refusing cleanup: Redshift ARN differs from saved state")
    quack = state.get("quack", {})
    stack = describe_stack(config, quack.get("id", config.stack_name)) if quack else None
    if stack:
        validate_arn(config, stack["id"], "cloudformation", f"stack/{config.stack_name}/")
        tags = {tag["Key"]: tag["Value"] for tag in stack.get("tags", [])}
        require(tags.get("ManagedBy") == MANAGED_BY and tags.get("SetupId") == config.setup_id,
                "Refusing cleanup: Quack stack ownership tags changed")
        require(not quack.get("id") or quack["id"] == stack["id"], "Refusing cleanup: Quack stack was replaced")
        quack["id"] = stack["id"]
        save_state(config, state)
    role = describe_role(config, config.role_name) if redshift.get("role_owned") else None
    if role:
        require(role["id"] == redshift.get("role_id"), "Refusing cleanup: IAM loader role was replaced")
    return cluster, stack, role


def cleanup(config, state):
    if state.get("cleaned"):
        print("Cleanup was already completed; retained resources are unchanged")
        return
    require(state.get("redshift") or state.get("quack"), "No saved resources to clean up")
    cluster, stack, role = validate_cleanup(config, state)
    recover_ingress(config, state)
    for link in state["ingress"]:
        if not link.get("id"):
            continue
        matches = [rule for rule in ingress_rules(config, link["target"]) if rule["SecurityGroupRuleId"] == link["id"]]
        if matches:
            require(matching_rule(matches[0], link), "Refusing cleanup: saved ingress rule changed")
            aws(config, ["ec2", "revoke-security-group-ingress", "--group-id", link["target"], "--security-group-rule-ids", link["id"]])
            print(f"Removed ingress rule {link['id']}")
    if stack and state["quack"].get("owned") and stack["status"] != "DELETE_COMPLETE":
        if stack["status"] != "DELETE_IN_PROGRESS":
            aws(config, ["cloudformation", "delete-stack", "--stack-name", stack["id"]])
        aws(config, ["cloudformation", "wait", "stack-delete-complete", "--stack-name", stack["id"]], timeout=config.wait_seconds)
        print("Deleted owned Quack stack")
    redshift = state.get("redshift", {})
    if cluster and redshift.get("owned"):
        if cluster["status"] != "deleting":
            aws(config, ["redshift", "delete-cluster", "--cluster-identifier", config.cluster_name, "--skip-final-cluster-snapshot"])
        aws(config, ["redshift", "wait", "cluster-deleted", "--cluster-identifier", config.cluster_name], timeout=config.wait_seconds)
        print("Deleted owned Redshift test cluster without a final snapshot")
    if role:
        policies = aws(config, ["iam", "list-role-policies", "--role-name", config.role_name], query="PolicyNames")
        attached = aws(config, ["iam", "list-attached-role-policies", "--role-name", config.role_name], query="AttachedPolicies")
        profiles = aws(config, ["iam", "list-instance-profiles-for-role", "--role-name", config.role_name], query="InstanceProfiles")
        require(set(policies) <= {"tickit-read"} and not attached and not profiles,
                "Loader role has additional policies or instance profiles; leaving it for manual cleanup")
        if "tickit-read" in policies:
            aws(config, ["iam", "delete-role-policy", "--role-name", config.role_name, "--policy-name", "tickit-read"])
        aws(config, ["iam", "delete-role", "--role-name", config.role_name])
        print("Deleted owned TICKIT loader role")
    if redshift.get("group_owned") and redshift.get("group_id"):
        groups = aws(config, ["ec2", "describe-security-groups", "--group-ids", redshift["group_id"]],
                     query="SecurityGroups", missing=("InvalidGroup.NotFound",))
        if groups:
            tags = {tag["Key"]: tag["Value"] for tag in groups[0].get("Tags", [])}
            require(tags.get("ManagedBy") == "duckdb-redshift-test" and tags.get("Cluster") == config.cluster_name,
                    "Refusing cleanup: Redshift security group no longer has its ownership tags")
            aws(config, ["ec2", "delete-security-group", "--group-id", redshift["group_id"]])
            print("Deleted owned Redshift security group")
    state["cleaned"] = datetime.now(timezone.utc).isoformat()
    save_state(config, state)
    print("Cleanup complete. Pre-existing resources were retained")


def make_config(arguments):
    parser = argparse.ArgumentParser(description="Set up a retained CloudFormation/Quack/Redshift test environment.")
    parser.add_argument("action", choices=("setup", "check", "cleanup", "manual-test"))
    parser.add_argument("--force", action="store_true", help="Execute the plan; without this flag no AWS resources are changed")
    config = parser.parse_args(arguments)
    config.profile = os.environ.get("AWS_PROFILE", "")
    config.region = os.environ.get("AWS_REGION", "")
    config.prefix = os.environ.get("PREFIX", getpass.getuser())
    require(config.profile and config.region, "Set AWS_PROFILE and AWS_REGION explicitly")
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,24}", config.prefix), "PREFIX must be 1-25 lowercase letters/digits/hyphens, starting with a letter")
    require(re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", config.region), "Invalid AWS_REGION")
    config.cluster_name = f"{config.prefix}-redshift-{config.region}"
    config.role_name = f"{config.cluster_name}-tickit-loader"
    config.template = os.environ.get("QUACK_TEMPLATE_URL", DEFAULT_TEMPLATE)
    require(config.template.startswith("https://"), "QUACK_TEMPLATE_URL must use HTTPS")
    config.machine_type = os.environ.get("QUACK_MACHINE_TYPE", "t4g.small")
    try:
        config.max_hours = int(os.environ.get("QUACK_MAX_DURATION_HOURS", "0"))
        config.wait_seconds = int(os.environ.get("QUACK_REDSHIFT_WAIT_SECONDS", "1800"))
    except ValueError:
        raise SetupError("Duration and wait settings must be whole numbers") from None
    require(0 <= config.max_hours <= 144 and 0 < config.wait_seconds <= 86400, "Invalid duration or wait settings")
    config.build_dir = Path(os.environ.get("DUCKDB_BUILD_DIR", ROOT / "build/release")).expanduser().resolve()
    config.env_file = Path(os.environ.get("REDSHIFT_ENV_FILE", ROOT / "test/sql/redshift/redshift.env")).expanduser().resolve()
    output_path = Path(os.environ.get("MANUAL_TEST_WITH_SECRETS_FILE", ROOT / "manual_test_with_secrets.sql")).expanduser()
    config.manual_test_file = output_path.parent.resolve() / output_path.name
    require(shutil.which("aws"), "AWS CLI v2 is required")
    config.account = aws(config, ["sts", "get-caller-identity"], query="Account")
    require(isinstance(config.account, str) and re.fullmatch(r"\d{12}", config.account), "Invalid AWS account identity")
    config.setup_id = hashlib.sha256(f"{config.account}:{config.region}:{config.prefix}".encode()).hexdigest()[:12]
    config.stack_name = f"quack-{config.prefix[:10]}-{config.setup_id}"
    state_dir = Path(os.environ.get("QUACK_REDSHIFT_STATE_DIR", ROOT / ".quack-redshift")).expanduser().resolve()
    config.state_path = state_dir / f"{config.account}-{config.region}-{config.prefix}.json"
    return config


def print_plan(config, state):
    print(f"Action: {config.action}; account: {config.account}; region: {config.region}; profile: {config.profile}")
    print(f"Redshift cluster: {config.cluster_name}")
    print(f"Redshift env file: {config.env_file}")
    print(f"Quack stack: {config.stack_name}")
    print(f"State: {config.state_path}")
    if config.action == "setup":
        print(f"Quack template: {config.template}")
        print(f"Quack instance: {config.machine_type}; shutdown after hours: {config.max_hours} (0 disables shutdown)")
        print("Reuse the Redshift creator, create/reuse Quack, allow its group on the Redshift port, then query TICKIT through Quack")
        print("Temporary profile credentials will be sent to Quack over TLS with logging disabled; no credentials enter the state or env file")
        print("Resources remain billable until cleanup. The published Quack template exposes HTTP/HTTPS publicly")
        print(f"After the smoke test, write temporary credentials and manual-test SQL to {config.manual_test_file}")
    elif config.action == "manual-test":
        print(f"Prepare the saved EC2/Quack/Redshift setup, then write private SQL to {config.manual_test_file}")
        print("Refresh and verify the remote test attachment; no infrastructure is created or deleted")
        print("Generated SQL is not executed; run the private file soon after generation")
    elif config.action == "check":
        print("Refresh the remote test attachment before loading Quack catalogs, then query Redshift TICKIT; infrastructure stays unchanged")
    else:
        print("Remove only recorded linking rules and resources owned by this setup; reused resources stay")
        print("Owned Redshift test data is deleted without a final snapshot")
        for kind in ("redshift", "quack"):
            resource = state.get(kind, {})
            print(f"  {kind}: {'delete' if resource.get('owned') else 'retain'} {resource.get('arn', resource.get('id', '(not recorded)'))}")
    if not config.force:
        print("Preview only. Add --force (or FORCE=1 with make) to execute")


def main(arguments=None):
    try:
        config = make_config(arguments)
        state = load_state(config)
        print_plan(config, state)
        if not config.force:
            validate_env(config, read_redshift_env(config.env_file))
            if config.action == "setup":
                require(config.template != DEFAULT_TEMPLATE or config.region in TEMPLATE_REGIONS,
                        "The default Quack template does not support this region")
            return 0
        with state_lock(config):
            state = load_state(config)
            if config.action == "setup":
                setup(config, state)
            elif config.action == "check":
                validate_build(config)
                validate_env(config, read_redshift_env(config.env_file))
                check(config, state)
            elif config.action == "manual-test":
                generate_manual_test(config, state)
            else:
                cleanup(config, state)
        return 0
    except (SetupError, subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as error:
        if isinstance(error, SetupError):
            print(f"error: {error}", file=sys.stderr)
        else:
            print("error: a subprocess failed or timed out; inspect saved resources before retrying", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
