#pragma once

#include "aws_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

namespace duckdb {

class ExtensionLoader;

//! Read a CREATE SECRET named parameter as a string, or "" when it was not passed.
string TryGetStringParam(CreateSecretInput &input, const string &param_name);

//! Create the secret of the credential_chain provider
unique_ptr<BaseSecret> CreateAWSSecretFromCredentialChain(ClientContext &context, CreateSecretInput &input);
//! Create a secret of the input's type, provider and name that holds no credentials
unique_ptr<BaseSecret> CreateAWSSecretWithoutCredentials(const CreateSecretInput &input);

struct CreateAwsSecretFunctions {
public:
	//! Register all CreateSecretFunctions
	static void Register(ExtensionLoader &instance);

	//! WARNING: not thread-safe, to be called on extension initialization once
	static void InitializeCurlCertificates(DatabaseInstance &db);
};

} // namespace duckdb
