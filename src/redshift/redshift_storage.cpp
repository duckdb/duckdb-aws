#include "aws_http_client.hpp"
#include "redshift/redshift_utils.hpp"

#include "aws_client.hpp"
#include "utils/utils.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/transaction_manager.hpp"

namespace duckdb {

namespace {

//! ATTACH options that we consume ourselves. Everything else is forwarded to postgres, or after a hand-off to
//! amazon_redshift, which reject options they do not know.
struct RedshiftAttachOptions {
	string secret_name;
	string region;
	string account_id;
	string resource;
	string resource_type;
	string db_name;
	string host;
	string port;
	int duration_seconds = 0;
};

RedshiftAttachOptions ParseAttachOptions(AttachOptions &options) {
	RedshiftAttachOptions parsed;
	// Consumed options are erased, since postgres throws on any option it does not recognize.
	for (auto it = options.options.begin(); it != options.options.end();) {
		auto key = StringUtil::Lower(it->first);
		auto value = it->second.ToString();
		if (key == "secret") {
			// Left in place: postgres looks the secret up by name, and it must find one. See
			// the note in RedshiftAttach.
			parsed.secret_name = value;
			it++;
			continue;
		}
		if (key == "region") {
			parsed.region = value;
		} else if (key == "account_id") {
			parsed.account_id = value;
		} else if (key == "resource") {
			parsed.resource = value;
		} else if (key == "resource_type") {
			parsed.resource_type = value;
		} else if (key == "database" || key == "dbname") {
			parsed.db_name = value;
		} else if (key == "host") {
			parsed.host = value;
		} else if (key == "port") {
			parsed.port = value;
		} else if (key == "duration_seconds") {
			try {
				parsed.duration_seconds = std::stoi(value);
			} catch (const std::exception &) {
				throw InvalidInputException("'DURATION_SECONDS' must be an integer, got '%s'", value);
			}
		} else {
			it++;
			continue;
		}
		it = options.options.erase(it);
	}
	return parsed;
}

struct RedshiftAttachTarget {
	RedshiftTargetType type = RedshiftTargetType::PROVISIONED_CLUSTER;
	string resource_id;
	string account_id;
	string region;
};

RedshiftAttachTarget GetRedshiftTarget(AttachedDatabase &db, const RedshiftAttachOptions &attach_options,
                                       const string &target_name) {
	const auto &original_path = db.GetOriginalPath();
	auto delegated_from_arn = original_path.has_value() && *original_path != target_name;

	RedshiftAttachTarget target;
	target.resource_id = target_name;
	target.region = attach_options.region;
	if (!delegated_from_arn) {
		if (!attach_options.account_id.empty() || !attach_options.resource.empty() ||
		    !attach_options.resource_type.empty()) {
			throw InvalidInputException("Redshift ARN options cannot be set directly");
		}
		return target;
	}

	if (!attach_options.resource.empty() && !attach_options.resource_type.empty()) {
		throw InvalidInputException("Conflicting Redshift ARN options");
	}

	target.account_id = attach_options.account_id;
	if (!attach_options.resource.empty()) {
		target.type = RedshiftTargetType::PROVISIONED_NAMESPACE;
		target.resource_id = attach_options.resource;
		return target;
	}

	target.type = attach_options.resource_type == "namespace" ? RedshiftTargetType::SERVERLESS_NAMESPACE
	                                                          : RedshiftTargetType::SERVERLESS_WORKGROUP;
	return target;
}

struct RedshiftResolvedConnection {
	string credential_target;
	string host;
	string port;
	string db_name;
	RedshiftIamCredentials credentials;
};

void FillMissingConnectionOptions(RedshiftResolvedConnection &connection, const string &endpoint_address,
                                  int32_t endpoint_port, const string &db_name) {
	connection.host = connection.host.empty() ? endpoint_address : connection.host;
	connection.port = connection.port.empty() ? to_string(endpoint_port) : connection.port;
	connection.db_name = connection.db_name.empty() ? db_name : connection.db_name;
}

RedshiftResolvedConnection ResolveConnection(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &provider,
                                             const RedshiftAttachOptions &attach_options,
                                             const RedshiftAttachTarget &target) {
	RedshiftResolvedConnection connection;
	connection.credential_target = target.resource_id;
	connection.host = attach_options.host;
	connection.port = attach_options.port;
	connection.db_name = attach_options.db_name;

	switch (target.type) {
	case RedshiftTargetType::SERVERLESS_NAMESPACE:
	case RedshiftTargetType::SERVERLESS_WORKGROUP: {
		auto resolved_target = RedshiftServerless::ResolveTarget(provider, target.account_id, target.type,
		                                                         target.resource_id, target.region);
		connection.credential_target = resolved_target.credential_target;
		FillMissingConnectionOptions(connection, resolved_target.endpoint_address, resolved_target.endpoint_port,
		                             resolved_target.db_name);
		connection.credentials = RedshiftServerless::GetCredentials(
		    provider, connection.credential_target, connection.db_name, target.region, attach_options.duration_seconds);
		return connection;
	}
	case RedshiftTargetType::PROVISIONED_NAMESPACE:
		connection.credential_target =
		    Redshift::ClusterIdentifierFromNamespace(provider, target.account_id, target.resource_id, target.region);
		break;
	case RedshiftTargetType::PROVISIONED_CLUSTER:
		break;
	}

	// Anything ATTACH pins explicitly wins over what the cluster reports, so when it pins all of
	// them there is nothing left to discover - skip the call rather than require the caller to
	// hold the redshift:DescribeClusters permission.
	if (connection.host.empty() || connection.port.empty() || connection.db_name.empty()) {
		auto cluster = Redshift::DescribeCluster(provider, connection.credential_target, target.region);
		FillMissingConnectionOptions(connection, cluster.endpoint_address, cluster.endpoint_port, cluster.db_name);
	}

	connection.credentials = Redshift::GetClusterCredentials(provider, connection.credential_target, connection.db_name,
	                                                         target.region, attach_options.duration_seconds);
	return connection;
}

// With amazon_redshift loaded, a Redshift ATTACH is handed to it instead of the postgres extension.

constexpr const char *AMAZON_REDSHIFT_STORAGE_NAME = "amazon_redshift";

//! Null when amazon_redshift is not loaded, by LOAD or by an ATTACH with TYPE amazon_redshift (it is not autoloaded).
optional_ptr<StorageExtension> FindAmazonRedshiftStorageExtension(const DBConfig &config) {
	return StorageExtension::Find(config, AMAZON_REDSHIFT_STORAGE_NAME);
}

//! Whether a path is a `redshift://` URI (any letter case).
bool IsRedshiftUri(const string &path) {
	return StringUtil::StartsWith(StringUtil::Lower(path), "redshift://");
}

//! Whether a host is shaped like the endpoint of the cluster `cluster_id`,
//! `<cluster-id>.<label>.<region>.redshift.amazonaws.com` (any letter case, an optional root dot).
//! amazon_redshift checks the rest of its form.
bool IsClusterEndpointOf(const string &host, const string &cluster_id) {
	auto labels = StringUtil::Split(StringUtil::Lower(host), '.');
	return labels.size() == 6 && labels[0] == StringUtil::Lower(cluster_id) && labels[3] == "redshift" &&
	       labels[4] == "amazonaws" && labels[5] == "com";
}

//! Whether a HOST is shaped like a cluster or Serverless workgroup endpoint, which a lookup can compare with the
//! target's own.
bool IsRedshiftEndpointHost(const string &host) {
	const auto lower = StringUtil::Lower(host);
	return StringUtil::EndsWith(lower, ".redshift.amazonaws.com") ||
	       StringUtil::EndsWith(lower, ".redshift-serverless.amazonaws.com");
}

bool IsServerless(RedshiftTargetType type) {
	return type == RedshiftTargetType::SERVERLESS_NAMESPACE || type == RedshiftTargetType::SERVERLESS_WORKGROUP;
}

//! The path and options of the amazon_redshift ATTACH.
struct AmazonRedshiftAttach {
	string path;
	//! Lowercase keys, as DuckDB's parser leaves ATTACH options
	unordered_map<string, Value> options;
};

//! Postgres-only options, no-ops on Redshift: dropped so postgres ATTACHes keep working. Unlist any
//! that amazon_redshift adds.
const char *const POSTGRES_ONLY_OPTIONS[] = {"schema", "isolation_level", "use_text_protocol", "secret_storage_table",
                                             "connect_display"};

//! Whether an option is one of the postgres-only ones.
bool IsPostgresOnlyOption(const string &key) {
	for (auto name : POSTGRES_ONLY_OPTIONS) {
		if (key == name) {
			return true;
		}
	}
	return false;
}

//! amazon_redshift options TYPE redshift refuses on every path, and why: the hand-off always sends SECRET.
struct RefusedOption {
	const char *name;
	const char *reason;
};
const RefusedOption REFUSED_OPTIONS[] = {
    {"profile", "TYPE redshift takes AWS credentials from an aws or s3 secret; for a profile, create one, e.g. "
                "CREATE SECRET (TYPE aws, PROVIDER credential_chain, PROFILE '<profile>')"},
    {"credential_provider", "TYPE redshift takes AWS credentials from an aws or s3 secret, e.g. "
                            "CREATE SECRET (TYPE aws, PROVIDER credential_chain)"}};

//! Refuses an ATTACH option the hand-off cannot take, saying why (option names in any letter case).
void RefuseOption(const unordered_map<string, Value> &unconsumed, const char *name, const char *reason) {
	for (auto &entry : unconsumed) {
		if (StringUtil::CIEquals(entry.first, name)) {
			throw InvalidInputException("ATTACH option '%s' cannot be set: %s", StringUtil::Upper(name), reason);
		}
	}
}

//! Refuses HOST and PORT, which ParseAttachOptions consumed, saying why.
void RefuseEndpointOptions(const RedshiftAttachOptions &attach_options, const char *reason) {
	if (!attach_options.host.empty()) {
		throw InvalidInputException("ATTACH option 'HOST' cannot be set: %s", reason);
	}
	if (!attach_options.port.empty()) {
		throw InvalidInputException("ATTACH option 'PORT' cannot be set: %s", reason);
	}
}

//! Refuses a direct ACCOUNT_ID, naming where TYPE redshift takes one: the ARN, or the endpoint URI.
void RefuseAccountIdOption(AttachedDatabase &db, const RedshiftAttachOptions &attach_options, const string &path) {
	const auto &original_path = db.GetOriginalPath();
	const bool from_arn = original_path.has_value() && *original_path != path;
	if (from_arn || attach_options.account_id.empty() || !attach_options.resource.empty() ||
	    !attach_options.resource_type.empty()) {
		return;
	}
	throw InvalidInputException("ATTACH option 'ACCOUNT_ID' cannot be set directly: TYPE redshift takes a Serverless "
	                            "workgroup's account from its ARN, e.g. ATTACH "
	                            "'arn:aws:redshift-serverless:<region>:<account>:workgroup/<workgroup-id>' AS db, or "
	                            "from its endpoint, e.g. ATTACH "
	                            "'redshift://<workgroup>.<account>.<region>.redshift-serverless.amazonaws.com' AS db "
	                            "(TYPE redshift), or beside WORKGROUP with an empty path, e.g. ATTACH '' AS db (TYPE "
	                            "redshift, WORKGROUP '<workgroup>', ACCOUNT_ID '<account>')");
}

//! Forwards unconsumed options to amazon_redshift, dropping SECRET and the postgres-only ones.
void ForwardUnconsumedOptions(const unordered_map<string, Value> &unconsumed, AmazonRedshiftAttach &hand_off) {
	for (auto &entry : unconsumed) {
		auto key = StringUtil::Lower(entry.first);
		// SECRET named the secret the hand-off already sends.
		if (key == "secret" || IsPostgresOnlyOption(key)) {
			continue;
		}
		hand_off.options[key] = entry.second;
	}
}

//! The amazon_redshift ATTACH, or null to stay on postgres (a HOST other than the target's endpoint, or for a
//! cluster identifier with PORT and DATABASE, one not shaped like it).
//! An empty or `redshift://` path passes through with no lookup.
unique_ptr<AmazonRedshiftAttach> ResolveHandOffAttach(ClientContext &context,
                                                      const RedshiftAttachOptions &attach_options,
                                                      const RedshiftAttachTarget &target,
                                                      const unordered_map<string, Value> &unconsumed_options) {
	// An empty path names no target and a redshift:// path names an endpoint: both go to amazon_redshift as given.
	// Any other path names a target this extension looks up.
	const bool is_empty_path = target.resource_id.empty();
	const bool is_redshift_uri_path = IsRedshiftUri(target.resource_id);
	// An ARN is parsed into one of the namespace or workgroup types; every other path is typed a cluster.
	const bool is_arn_path = target.type != RedshiftTargetType::PROVISIONED_CLUSTER;
	const bool is_cluster_id_path = !is_empty_path && !is_redshift_uri_path && !is_arn_path;

	// Refusals, before the secret is looked up and before any AWS call.
	for (auto &refused : REFUSED_OPTIONS) {
		RefuseOption(unconsumed_options, refused.name, refused.reason);
	}
	if (is_empty_path) {
		RefuseOption(unconsumed_options, "cluster",
		             "TYPE redshift takes a cluster identifier as the ATTACH path, e.g. ATTACH '<cluster-id>' AS db "
		             "(TYPE redshift)");
		RefuseEndpointOptions(attach_options, "it needs a Redshift cluster identifier or ARN as the ATTACH path, "
		                                      "e.g. ATTACH '<cluster-id>' AS db (TYPE redshift)");
	}
	if (is_redshift_uri_path) {
		RefuseEndpointOptions(attach_options, "the redshift:// path names the endpoint and its port itself");
	}

	auto secret_entry = FindAwsSecret(context, attach_options.secret_name);
	const auto &secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);

	auto hand_off = make_uniq<AmazonRedshiftAttach>();
	auto &options = hand_off->options;

	// SECRET: the one picked, under its own name.
	options["secret"] =
	    Value(attach_options.secret_name.empty() ? secret.GetName().GetIdentifierName() : attach_options.secret_name);

	// DATABASE or DBNAME (ParseAttachOptions reads both), sent as amazon_redshift's DATABASE, which takes no
	// DBNAME. A named target's default database is added below.
	if (!attach_options.db_name.empty()) {
		options["database"] = Value(attach_options.db_name);
	}

	// REGION: the ATTACH's, which amazon_redshift checks against the path; without it, amazon_redshift takes the
	// path's, else the secret's. An ARN's region arrives as REGION.
	if (!attach_options.region.empty()) {
		options["region"] = Value(attach_options.region);
	}

	ForwardUnconsumedOptions(unconsumed_options, *hand_off);

	// ACCOUNT_ID: the empty path's, the ATTACH's own; an ARN never gives an empty path, so its account is not sent.
	if (is_empty_path && !target.account_id.empty()) {
		options["account_id"] = Value(target.account_id);
	}

	// An empty or redshift:// path: passed through as given.
	if (is_empty_path || is_redshift_uri_path) {
		hand_off->path = target.resource_id;
		return hand_off;
	}

	// A HOST not shaped like an endpoint (a tunnel, an IP, a proxy) stays on postgres, with no lookup.
	if (!attach_options.host.empty() && !IsRedshiftEndpointHost(attach_options.host)) {
		return nullptr;
	}

	// HOST, PORT and DATABASE all given leave nothing to look up, so there is no lookup, which would need
	// redshift:DescribeClusters and a region; amazon_redshift reads the region from HOST. The path names the cluster
	// and HOST where to connect: a HOST that is that cluster's own endpoint name is handed off, and any other (a
	// tunnel, an IP, a proxy) only postgres can connect through.
	if (is_cluster_id_path && !attach_options.host.empty() && !attach_options.port.empty() &&
	    !attach_options.db_name.empty()) {
		if (!IsClusterEndpointOf(attach_options.host, target.resource_id)) {
			return nullptr;
		}
		hand_off->path = "redshift://" + attach_options.host + ":" + attach_options.port;
		return hand_off;
	}

	// A named target: look up its endpoint, port and default database. The lookup needs a region: the ATTACH's, else
	// the secret's, else the s3_region setting, the environment or the profile, as upstream finds a cluster's.
	auto region = attach_options.region;
	if (region.empty()) {
		region = GetSecretString(secret, "region");
	}
	if (region.empty()) {
		region = ResolveAwsRegion(context, "", "");
	}
	if (region.empty()) {
		throw InvalidConfigurationException(
		    "No AWS region found for the Redshift cluster. Pass it to ATTACH, e.g. "
		    "ATTACH '<cluster-id>' AS db (TYPE redshift, REGION '<region>'), set it on the secret, "
		    "or configure the AWS_REGION environment variable");
	}

	auto provider = CredentialsProviderFromSecret(secret, "Redshift");
	RedshiftTargetInfo endpoint;
	if (IsServerless(target.type)) {
		endpoint =
		    RedshiftServerless::ResolveTarget(provider, target.account_id, target.type, target.resource_id, region);
	} else {
		const auto cluster_id =
		    target.type == RedshiftTargetType::PROVISIONED_NAMESPACE
		        ? Redshift::ClusterIdentifierFromNamespace(provider, target.account_id, target.resource_id, region)
		        : target.resource_id;
		endpoint = Redshift::DescribeCluster(provider, cluster_id, region);
	}

	// A HOST other than the target's own endpoint stays on postgres.
	if (!attach_options.host.empty() && !StringUtil::CIEquals(attach_options.host, endpoint.endpoint_address)) {
		return nullptr;
	}

	// The path: the target's endpoint and port, or HOST and PORT where given.
	const auto host = attach_options.host.empty() ? endpoint.endpoint_address : attach_options.host;
	const auto port = attach_options.port.empty() ? to_string(endpoint.endpoint_port) : attach_options.port;
	hand_off->path = "redshift://" + host + ":" + port;

	// The target's default database, when the ATTACH gave none.
	if (attach_options.db_name.empty() && !endpoint.db_name.empty()) {
		options["database"] = Value(endpoint.db_name);
	}
	return hand_off;
}

unique_ptr<Catalog> HandOffToAmazonRedshift(StorageExtension &amazon_redshift_extension, AmazonRedshiftAttach &hand_off,
                                            ClientContext &context, AttachedDatabase &db, const string &name,
                                            AttachInfo &info, AttachOptions &options) {
	info.path = hand_off.path;
	options.options = std::move(hand_off.options);
	return amazon_redshift_extension.attach(amazon_redshift_extension.storage_info.get(), context, db, name, info,
	                                        options);
}

//! `ATTACH '<cluster-id>' AS db (TYPE redshift, SECRET <aws-or-s3-secret>)`.
//!
//! The cluster identifier is all the user gives us, so we ask Redshift for the rest:
//! DescribeClusters supplies the endpoint host/port and the default database name, and
//! GetClusterCredentialsWithIAM mints a short-lived database user/password for the AWS identity
//! behind the secret. Those are assembled into a libpq connection string, which we hand to the
//! postgres extension's own attach - Redshift speaks the Postgres wire protocol, so from there
//! on it is an ordinary postgres attach.
//! With amazon_redshift loaded, it is handed off instead (see above).
unique_ptr<Catalog> RedshiftAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                   AttachedDatabase &db, const string &name, AttachInfo &info, AttachOptions &options) {
	if (!Settings::Get<EnableExternalAccessSetting>(context)) {
		throw PermissionException("Attaching Redshift databases is disabled through configuration");
	}
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));

	auto attach_options = ParseAttachOptions(options);
	auto amazon_redshift_extension = FindAmazonRedshiftStorageExtension(DBConfig::GetConfig(db.GetDatabase()));
	// With an empty path, ACCOUNT_ID is amazon_redshift's: an ARN never gives an empty path, so it is not the ARN's
	// account, which upstream refuses directly. It is set aside from that refusal and goes on the target.
	string empty_path_account_id;
	if (amazon_redshift_extension) {
		if (info.path.empty()) {
			empty_path_account_id = attach_options.account_id;
			attach_options.account_id.clear();
		}
		RefuseAccountIdOption(db, attach_options, info.path);
	}
	auto target = GetRedshiftTarget(db, attach_options, info.path);
	if (!empty_path_account_id.empty()) {
		target.account_id = empty_path_account_id;
	}
	if (target.resource_id.empty() && !amazon_redshift_extension) {
		throw BinderException("No Redshift cluster identifier given. Pass it as the ATTACH path, e.g. "
		                      "ATTACH '<cluster-id>' AS db (TYPE redshift)");
	}

	if (amazon_redshift_extension) {
		auto hand_off = ResolveHandOffAttach(context, attach_options, target, options.options);
		if (hand_off) {
			return HandOffToAmazonRedshift(*amazon_redshift_extension, *hand_off, context, db, name, info, options);
		}
	}

	auto secret_entry = FindAwsSecret(context, attach_options.secret_name);
	const auto &secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);

	// An s3 secret's region is the bucket region, which need not be the cluster's, so an explicit
	// ATTACH region wins over it. Past those two, fall back to the sources CREATE SECRET uses.
	if (target.type == RedshiftTargetType::PROVISIONED_CLUSTER) {
		auto explicit_region =
		    attach_options.region.empty() ? GetSecretString(secret, "region") : attach_options.region;
		target.region = ResolveAwsRegion(context, explicit_region, "");
		if (target.region.empty()) {
			throw InvalidConfigurationException(
			    "No AWS region found for the Redshift cluster. Pass it to ATTACH, e.g. "
			    "ATTACH '<cluster-id>' AS db (TYPE redshift, REGION '<region>'), set it on the secret, "
			    "or configure the AWS_REGION environment variable");
		}
	}

	// Resolve the postgres extension before spending API calls on a connection we cannot open.
	auto postgres_extension = RequirePostgresStorageExtension(context, "a Redshift cluster");

	auto provider = CredentialsProviderFromSecret(secret, "Redshift");
	auto connection = ResolveConnection(provider, attach_options, target);
	auto cluster_id = connection.credential_target;
	const auto &host = connection.host;
	const auto &port = connection.port;
	const auto &db_name = connection.db_name;
	const auto &credentials = connection.credentials;

	// Redshift requires SSL.
	string connection_string = "host=" + EscapeConnectionValue(host) + " port=" + EscapeConnectionValue(port) +
	                           " user=" + EscapeConnectionValue(credentials.db_user) +
	                           " password=" + EscapeConnectionValue(credentials.db_password) + " sslmode='require'";
	if (!db_name.empty()) {
		connection_string += " dbname=" + EscapeConnectionValue(db_name);
	}

	// Hand the postgres extension a plain connection string as the attach path.
	info.path = connection_string;

	// The postgres catalog would otherwise identify this connection by the connection string above,
	// which holds the temporary credentials. Label it with the cluster it was attached as instead.
	options.options["connect_display"] = Value(cluster_id);

	// Postgres must be given a secret name it can resolve: with none it falls back to the
	// implicit '__default_postgres' secret, which it probes in the 'local_file' storage - and
	// that throws outright when persistent secrets are disabled. Naming the aws/s3 secret we
	// just used is safe, because postgres only harvests libpq option names (host, port, user,
	// ...) from a secret and an aws/s3 secret holds none of them.
	options.options["secret"] = Value(secret.GetName().GetIdentifierName());

	try {
		return postgres_extension->attach(postgres_extension->storage_info.get(), context, db, name, info, options);
	} catch (std::exception &ex) {
		auto message = PostgresAttachErrorMessage(ex, credentials.db_password);
		throw IOException("Unable to connect to Redshift cluster '%s': %s", cluster_id, message);
	}
}

unique_ptr<TransactionManager> RedshiftCreateTransactionManager(optional_ptr<StorageExtensionInfo> storage_info,
                                                                AttachedDatabase &db, Catalog &catalog) {
	// From the extension whose catalog RedshiftAttach returned, which Attach checked is loaded.
	auto &db_config = DBConfig::GetConfig(db.GetDatabase());
	const bool handed_off = catalog.GetCatalogType() == AMAZON_REDSHIFT_STORAGE_NAME;
	auto extension =
	    handed_off ? FindAmazonRedshiftStorageExtension(db_config) : FindPostgresStorageExtension(db_config);
	if (!extension || !extension->create_transaction_manager) {
		throw InternalException("Redshift attach: the %s storage extension disappeared after attaching",
		                        handed_off ? "amazon_redshift" : "postgres");
	}
	return extension->create_transaction_manager(extension->storage_info.get(), db, catalog);
}

class RedshiftStorageExtension : public StorageExtension {
public:
	RedshiftStorageExtension() {
		attach = RedshiftAttach;
		create_transaction_manager = RedshiftCreateTransactionManager;
	}
};

} // namespace

void Redshift::RegisterStorageExtension(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	StorageExtension::Register(config, "redshift", make_shared_ptr<RedshiftStorageExtension>());
}

} // namespace duckdb
