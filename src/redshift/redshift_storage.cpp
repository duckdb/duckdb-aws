#include "aws_http_client.hpp"
#include "redshift/redshift_utils.hpp"
#include "arn.hpp"

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

//! ATTACH options that we consume ourselves. Everything else is forwarded to the postgres
//! extension, which rejects options it does not know.
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

//! What to attach: a bare cluster identifier, or an ARN that names a provisioned namespace
//! (arn:aws:redshift:<region>:<account>:namespace:<id>) or a Serverless workgroup or namespace
//! (arn:aws:redshift-serverless:<region>:<account>:workgroup/<id> | namespace/<id>). The ARN carries the region and the
//! account, so ATTACH may not set them.
RedshiftAttachTarget GetRedshiftTarget(const RedshiftAttachOptions &attach_options, const string &path) {
	if (!attach_options.account_id.empty() || !attach_options.resource.empty() ||
	    !attach_options.resource_type.empty()) {
		throw InvalidInputException("Redshift ARN options cannot be set directly");
	}
	RedshiftAttachTarget target;
	if (!ParsedArn::IsArn(path)) {
		target.resource_id = path;
		target.region = attach_options.region;
		return target;
	}

	auto arn = ParsedArn::Parse(path);
	if (!attach_options.region.empty()) {
		throw InvalidInputException("ATTACH option 'region' is derived from the ARN and cannot be set explicitly");
	}
	if (arn.service == "redshift") {
		if (arn.region.empty()) {
			throw InvalidInputException("Redshift namespace ARN '%s' does not specify a region", arn.raw);
		}
		if (arn.account_id.empty()) {
			throw InvalidInputException("Redshift namespace ARN '%s' does not specify an account ID", arn.raw);
		}
		static const string prefix = "namespace:";
		if (!StringUtil::StartsWith(arn.resource, prefix) || arn.resource.size() == prefix.size()) {
			throw InvalidInputException(
			    "Expected a Redshift namespace ARN with a resource of the form 'namespace:<namespace-id>', got '%s'",
			    arn.raw);
		}
		target.type = RedshiftTargetType::PROVISIONED_NAMESPACE;
		target.resource_id = arn.resource;
	} else if (arn.service == "redshift-serverless") {
		if (arn.region.empty()) {
			throw InvalidInputException("Redshift Serverless ARN '%s' does not specify a region", arn.raw);
		}
		if (arn.account_id.empty()) {
			throw InvalidInputException("Redshift Serverless ARN '%s' does not specify an account ID", arn.raw);
		}
		auto separator = arn.resource.find('/');
		auto resource_type = separator == string::npos ? string() : arn.resource.substr(0, separator);
		if (separator == string::npos || separator == 0 || separator == arn.resource.size() - 1 ||
		    arn.resource.find('/', separator + 1) != string::npos ||
		    (resource_type != "workgroup" && resource_type != "namespace")) {
			throw InvalidInputException("Expected a Redshift Serverless ARN with a resource of the form "
			                            "'workgroup/<workgroup-id>' or 'namespace/<namespace-id>', got '%s'",
			                            arn.raw);
		}
		target.type = resource_type == "namespace" ? RedshiftTargetType::SERVERLESS_NAMESPACE
		                                           : RedshiftTargetType::SERVERLESS_WORKGROUP;
		target.resource_id = arn.resource.substr(separator + 1);
	} else {
		throw InvalidInputException("Expected a Redshift ARN (service 'redshift' or 'redshift-serverless'), got '%s'",
		                            arn.raw);
	}
	target.account_id = arn.account_id;
	target.region = arn.region;
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

//! `ATTACH '<cluster-id>' AS db (TYPE redshift_postgres, SECRET <aws-or-s3-secret>)`, or with a Redshift ARN as the
//! path. `TYPE redshift` is the redshift extension from aws.amazon.com, see arn_storage.cpp.
//!
//! The cluster identifier is all the user gives us, so we ask Redshift for the rest:
//! DescribeClusters supplies the endpoint host/port and the default database name, and
//! GetClusterCredentialsWithIAM mints a short-lived database user/password for the AWS identity
//! behind the secret. Those are assembled into a libpq connection string, which we hand to the
//! postgres extension's own attach - Redshift speaks the Postgres wire protocol, so from there
//! on it is an ordinary postgres attach.
unique_ptr<Catalog> RedshiftAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                   AttachedDatabase &db, const string &name, AttachInfo &info, AttachOptions &options) {
	if (!Settings::Get<EnableExternalAccessSetting>(context)) {
		throw PermissionException("Attaching Redshift databases is disabled through configuration");
	}
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));

	auto attach_options = ParseAttachOptions(options);
	auto target = GetRedshiftTarget(attach_options, info.path);
	if (target.resource_id.empty()) {
		throw BinderException("No Redshift cluster identifier given. Pass it as the ATTACH path, e.g. "
		                      "ATTACH '<cluster-id>' AS db (TYPE redshift_postgres)");
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
			    "ATTACH '<cluster-id>' AS db (TYPE redshift_postgres, REGION '<region>'), set it on the secret, "
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
	// RedshiftAttach returned a PostgresCatalog, so the transaction manager has to come from the
	// same place. Attach has already established that the postgres extension is loaded.
	auto &db_config = DBConfig::GetConfig(db.GetDatabase());
	auto postgres_extension = FindPostgresStorageExtension(db_config);
	if (!postgres_extension || !postgres_extension->create_transaction_manager) {
		throw InternalException("Redshift attach: the postgres storage extension disappeared after attaching");
	}
	return postgres_extension->create_transaction_manager(postgres_extension->storage_info.get(), db, catalog);
}

class RedshiftStorageExtension : public StorageExtension {
public:
	RedshiftStorageExtension() {
		attach = RedshiftAttach;
		create_transaction_manager = RedshiftCreateTransactionManager;
	}
};

//! Whether the ARN names its target by ID, the forms the redshift extension cannot serve without a lookup:
//! `namespace:<id>` for redshift, `workgroup/<id>` or `namespace/<id>` for redshift-serverless. Only the shape is
//! read here; GetRedshiftTarget checks the rest (region, account, an empty ID). Any other ARN, such as the long-form
//! workgroup ARN `workgroup/<label>/<workgroup-name>`, is left for the redshift extension to serve or refuse.
bool NamesTargetById(const ParsedArn &arn) {
	if (arn.service == "redshift") {
		return StringUtil::StartsWith(arn.resource, "namespace:");
	}
	auto separator = arn.resource.find('/');
	return arn.service == "redshift-serverless" && separator != string::npos &&
	       arn.resource.find('/', separator + 1) == string::npos &&
	       (StringUtil::StartsWith(arn.resource, "workgroup/") || StringUtil::StartsWith(arn.resource, "namespace/"));
}

} // namespace

void Redshift::ResolveArnById(ClientContext &context, const ParsedArn &arn, AttachInfo &info, AttachOptions &options) {
	if (!NamesTargetById(arn)) {
		return;
	}
	// The lookup is an AWS call, which external access governs, as it does for TYPE redshift_postgres
	if (!Settings::Get<EnableExternalAccessSetting>(context)) {
		throw PermissionException("Attaching Redshift databases is disabled through configuration");
	}
	AwsInstanceBinding aws_binding(DatabaseInstance::GetDatabase(context));

	// Only the ARN is read, for its region, account and ID: no ATTACH option is checked here, so every option goes
	// on to the redshift extension as given, and it decides what it takes beside a redshift:// path
	auto target = GetRedshiftTarget(RedshiftAttachOptions(), arn.raw);

	// The AWS identity for the lookup: the secret SECRET names, else the one FindAwsSecret picks, as for
	// TYPE redshift_postgres. SECRET is only read, not removed
	auto secret_option = options.options.find("secret");
	auto secret_name = secret_option == options.options.end() ? string() : secret_option->second.ToString();
	auto secret_entry = FindAwsSecret(context, secret_name);
	const auto &secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);
	auto provider = CredentialsProviderFromSecret(secret, "Redshift");

	// The lookups TYPE redshift_postgres makes, in the ARN's region; no credential call, since the redshift
	// extension's driver gets the database credentials itself. A target that is not found is refused here, with
	// those lookups' messages
	RedshiftTargetInfo resolved;
	if (target.type == RedshiftTargetType::PROVISIONED_NAMESPACE) {
		// DescribeClusters, unfiltered, finds the cluster whose namespace ARN matches; then DescribeClusters for that
		// cluster gives its endpoint, port and database
		auto cluster_id =
		    Redshift::ClusterIdentifierFromNamespace(provider, target.account_id, target.resource_id, target.region);
		resolved = Redshift::DescribeCluster(provider, cluster_id, target.region);
	} else {
		// ListWorkgroups and GetNamespace for a workgroup; ListNamespaces then ListWorkgroups for a namespace
		resolved = RedshiftServerless::ResolveTarget(provider, target.account_id, target.type, target.resource_id,
		                                             target.region);
	}

	// The redshift:// URI the redshift extension takes, pinned to the endpoint found, with the target's own port. It
	// names no database: the database goes on as an option, below or as the user gave it
	info.path = "redshift://" + resolved.endpoint_address + ":" + to_string(resolved.endpoint_port);
	// Without DATABASE or DBNAME, add the target's default database as DATABASE: the redshift extension's driver would
	// otherwise connect to `dev`, which need not be the target's default. A DATABASE or DBNAME the user gave is their
	// choice and wins over the default, as it does for TYPE redshift_postgres (FillMissingConnectionOptions), so it is
	// left as it is
	const bool database_given = options.options.count("database") || options.options.count("dbname");
	if (!database_given && !resolved.db_name.empty()) {
		options.options["database"] = Value(resolved.db_name);
	}
	// Without SECRET, name the secret the lookup used (`__aws_default` included): the redshift extension cannot know
	// which one FindAwsSecret picked, and this way the lookup and the connection use the same AWS identity
	if (secret_name.empty()) {
		options.options["secret"] = Value(secret.GetName().GetIdentifierName());
	}
}

void Redshift::RegisterStorageExtension(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	StorageExtension::Register(config, "redshift_postgres", make_shared_ptr<RedshiftStorageExtension>());
}

} // namespace duckdb
