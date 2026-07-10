#pragma once

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/config/AWSProfileConfigLoaderBase.h>
#include <memory>
#include <string>

namespace duckdb {

//! Build a ClientConfiguration with the detected CA file path applied (if any).
//! Required because libcurl is statically linked from a RHEL-based manylinux
//! image, so its default CA path is /etc/pki/tls/certs/ca-bundle.crt, which
//! does not exist on Debian/Ubuntu/Alpine/etc. Without this, every AWS SDK
//! client that does its own HTTPS fails the TLS handshake.
//! See duckdb/duckdb#20652, duckdb/duckdb-aws#131.
Aws::Client::ClientConfiguration BuildClientConfigWithCa();

//! Build a credentials provider from the same opt-set that
//! CREATE SECRET ... credential_chain understands. Falls back to the SDK's
//! DefaultAWSCredentialsProviderChain when no chain/profile is specified.
//! `chain` is a ';'-separated list of provider names; see
//! DuckDBCustomAWSCredentialsProviderChain in aws_secret.cpp for the grammar.
std::shared_ptr<Aws::Auth::AWSCredentialsProvider>
BuildAwsCredentialsProvider(const std::string &chain, bool require_credentials, const std::string &profile = "",
                            const std::string &assume_role_arn = "", const std::string &external_id = "",
                            const std::string &web_identity_token_file = "", const std::string &session_name = "");

//! Load a named profile from the AWS config file (as located by AWS_CONFIG_FILE). Returns an
//! empty profile when it does not exist, unless `require_profile` is set, in which case it throws.
Aws::Config::Profile GetAwsProfile(const std::string &profile_name, bool require_profile);

} // namespace duckdb
