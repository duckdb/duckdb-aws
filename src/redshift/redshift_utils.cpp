#include "redshift/redshift_utils.hpp"

#include "aws_client.hpp"
#include "aws_secret.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <aws/redshift/RedshiftClient.h>
#include <aws/redshift/model/GetClusterCredentialsWithIAMRequest.h>

namespace duckdb {

namespace {

struct RedshiftIamCredentials {
	string db_user;
	string db_password;
	string expiration;
};

//! Calls the Redshift `GetClusterCredentialsWithIAM` API and returns the temporary
//! database user/password it mints. The provider supplies (and signs with) the AWS
//! identity resolved from the credential chain; the returned credentials are scoped
//! to the cluster and short-lived (see DurationSeconds, default ~900s).
RedshiftIamCredentials GenerateRedshiftCredentials(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                                   const string &cluster_id, const string &db_name,
                                                   const string &region, int duration_seconds) {
	Aws::Client::ClientConfiguration config = BuildClientConfigWithCa();
	config.region = region;
	Aws::Redshift::RedshiftClient redshift_client(provider, config);

	Aws::Redshift::Model::GetClusterCredentialsWithIAMRequest request;
	request.SetClusterIdentifier(cluster_id.c_str());
	if (!db_name.empty()) {
		request.SetDbName(db_name.c_str());
	}
	if (duration_seconds > 0) {
		request.SetDurationSeconds(duration_seconds);
	}

	auto outcome = redshift_client.GetClusterCredentialsWithIAM(request);
	if (!outcome.IsSuccess()) {
		throw InvalidConfigurationException(
		    "Secret Validation Failure: GetClusterCredentialsWithIAM failed for Redshift cluster '%s': %s", cluster_id,
		    string(outcome.GetError().GetMessage().c_str()));
	}

	auto &api_result = outcome.GetResult();
	RedshiftIamCredentials creds;
	creds.db_user = string(api_result.GetDbUser().c_str());
	creds.db_password = string(api_result.GetDbPassword().c_str());
	creds.expiration = string(api_result.GetExpiration().ToGmtString(Aws::Utils::DateFormat::ISO_8601).c_str());
	return creds;
}

} // namespace

void Redshift::RegisterSecret(ExtensionLoader &loader) {
	SecretType redshift_secret_type;
	redshift_secret_type.name = "redshift";
	redshift_secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	redshift_secret_type.default_provider = "credential_chain";
	loader.RegisterSecretType(redshift_secret_type);
}

void Redshift::AddNamedParameters(CreateSecretFunction &function) {
	function.named_parameters["redshift_cluster_id"] = LogicalType::VARCHAR;
	function.named_parameters["redshift_db_name"] = LogicalType::VARCHAR;
	function.named_parameters["redshift_host"] = LogicalType::VARCHAR;
	function.named_parameters["redshift_port"] = LogicalType::VARCHAR;
	function.named_parameters["redshift_duration_seconds"] = LogicalType::VARCHAR;
}

unique_ptr<BaseSecret> Redshift::CreateSecret(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                              CreateSecretInput &input, const string &region) {
	string cluster_id = TryGetStringParam(input, "redshift_cluster_id");
	string db_name = TryGetStringParam(input, "redshift_db_name");
	string host = TryGetStringParam(input, "redshift_host");
	string port = TryGetStringParam(input, "redshift_port");
	if (cluster_id.empty() || host.empty() || port.empty() || region.empty()) {
		throw InvalidInputException("Invalid Redshift secret parameters, 'REDSHIFT_CLUSTER_ID', 'REDSHIFT_HOST', "
		                            "'REDSHIFT_PORT' and 'REGION' options must be specified");
	}

	int duration_seconds = 0;
	string duration = TryGetStringParam(input, "redshift_duration_seconds");
	if (!duration.empty()) {
		try {
			duration_seconds = std::stoi(duration);
		} catch (const std::exception &) {
			throw InvalidInputException("'REDSHIFT_DURATION_SECONDS' must be an integer, got '%s'", duration);
		}
	}

	auto creds = GenerateRedshiftCredentials(provider, cluster_id, db_name, region, duration_seconds);

	vector<string> scope;
	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	// The minted database password is the sensitive field for a Redshift secret.
	result->redact_keys = {"password"};

	// Connection fields consumed by a Postgres-protocol ATTACH. These must use the
	// libpq parameter names the postgres extension recognizes (host/port/dbname/...),
	// not friendly aliases: e.g. 'database' is silently ignored, so dbname would
	// default to the username. Redshift also requires SSL, so default sslmode=require.
	result->secret_map["host"] = Value(host);
	result->secret_map["port"] = Value(port);
	if (!db_name.empty()) {
		result->secret_map["dbname"] = Value(db_name);
	}
	result->secret_map["user"] = Value(creds.db_user);
	result->secret_map["password"] = Value(creds.db_password);
	result->secret_map["sslmode"] = Value("require");
	result->secret_map["region"] = Value(region);
	if (!creds.expiration.empty()) {
		result->secret_map["expiration"] = Value(creds.expiration);
	}
	return std::move(result);
}

} // namespace duckdb
