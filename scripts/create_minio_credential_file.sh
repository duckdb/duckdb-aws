#!/bin/bash
# Warning: overwrites your existing aws credentials file!

# Set the file path for the credentials file
credentials_file=~/.aws/credentials

# Set the file path for the config file
config_file=~/.aws/config

# create dir if not already exists
mkdir -p ~/.aws

# Create the credentials configuration
credentials_str="[default]
aws_access_key_id=minio_duckdb_user
aws_secret_access_key=minio_duckdb_user_password

[minio-testing-2]
aws_access_key_id=minio_duckdb_user_2
aws_secret_access_key=minio_duckdb_user_2_password

[minio-testing-invalid]
aws_access_key_id=minio_duckdb_user_invalid
aws_secret_access_key=thispasswordiscompletelywrong
aws_session_token=completelybogussessiontoken

[minio-testing-empty]
aws_access_key_id=
aws_secret_access_key=
aws_session_token=
"

# Write the credentials configuration to the file
echo "$credentials_str" > "$credentials_file"

# Create the credentials configuration
config_str="[default]
region=eu-west-1

[profile minio-testing-2]
region=eu-west-1

[profile minio-testing-invalid]
region=the-moon-123

[profile minio-testing-empty]
region=

[profile assume-role-arn]
source_profile = default
role_arn = arn:aws:iam::840140254803:role/pyiceberg-etl-role
region = us-east-2

[profile assume-role-arn-external-id]
source_profile = default
role_arn = arn:aws:iam::840140254803:role/pyiceberg-etl-role
region = us-east-2
external_id = 128289344
"

# Write the config to the file
echo "$config_str" >"$config_file"

