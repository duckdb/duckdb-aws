#pragma once

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <memory>

namespace duckdb {

//! Build a ClientConfiguration with the detected CA file path applied (if any).
//! Required because libcurl is statically linked from a RHEL-based manylinux
//! image, so its default CA path is /etc/pki/tls/certs/ca-bundle.crt, which
//! does not exist on Debian/Ubuntu/Alpine/etc. Without this, every AWS SDK
//! client that does its own HTTPS fails the TLS handshake.
//! See duckdb/duckdb#20652, duckdb/duckdb-aws#131.
Aws::Client::ClientConfiguration BuildClientConfigWithCa();

//! Build a credentials provider using the SDK's DefaultAWSCredentialsProviderChain.
std::shared_ptr<Aws::Auth::AWSCredentialsProvider> CreateAwsCredentialsProvider();

} // namespace duckdb
