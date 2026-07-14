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

//! ATTACH options that we consume ourselves. Everything else is forwarded to the postgres
//! extension, which rejects options it does not know.
struct RedshiftAttachOptions {
	string secret_name;
	string region;
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

//! `ATTACH '<cluster-id>' AS db (TYPE redshift, SECRET <aws-or-s3-secret>)`.
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

	auto cluster_id = info.path;
	if (cluster_id.empty()) {
		throw BinderException("No Redshift cluster identifier given. Pass it as the ATTACH path, e.g. "
		                      "ATTACH '<cluster-id>' AS db (TYPE redshift)");
	}

	auto attach_options = ParseAttachOptions(options);
	auto secret_entry = FindAwsSecret(context, attach_options.secret_name);
	const auto &secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);

	// An s3 secret's region is the bucket region, which need not be the cluster's, so an explicit
	// ATTACH region wins over it. Past those two, fall back to the sources CREATE SECRET uses.
	auto explicit_region = attach_options.region.empty() ? GetSecretString(secret, "region") : attach_options.region;
	auto region = ResolveAwsRegion(context, explicit_region, "");
	if (region.empty()) {
		throw InvalidConfigurationException(
		    "No AWS region found for the Redshift cluster. Pass it to ATTACH, e.g. "
		    "ATTACH '<cluster-id>' AS db (TYPE redshift, REGION '<region>'), set it on the secret, "
		    "or configure the AWS_REGION environment variable");
	}

	// Resolve the postgres extension before spending API calls on a connection we cannot open.
	auto postgres_extension = RequirePostgresStorageExtension(context, "a Redshift cluster");

	auto provider = CredentialsProviderFromSecret(secret, "Redshift");

	// Anything ATTACH pins explicitly wins over what the cluster reports, so when it pins all of
	// them there is nothing left to discover - skip the call rather than require the caller to
	// hold the redshift:DescribeClusters permission.
	auto host = attach_options.host;
	auto port = attach_options.port;
	auto db_name = attach_options.db_name;
	if (host.empty() || port.empty() || db_name.empty()) {
		auto cluster = Redshift::DescribeCluster(provider, cluster_id, region);
		host = host.empty() ? cluster.endpoint_address : host;
		port = port.empty() ? to_string(cluster.endpoint_port) : port;
		db_name = db_name.empty() ? cluster.db_name : db_name;
	}

	auto credentials =
	    Redshift::GetClusterCredentials(provider, cluster_id, db_name, region, attach_options.duration_seconds);

	// Redshift requires SSL.
	string connection_string = "host=" + EscapeConnectionValue(host) + " port=" + EscapeConnectionValue(port) +
	                           " user=" + EscapeConnectionValue(credentials.db_user) +
	                           " password=" + EscapeConnectionValue(credentials.db_password) + " sslmode='require'";
	if (!db_name.empty()) {
		connection_string += " dbname=" + EscapeConnectionValue(db_name);
	}

	// Hand the postgres extension a plain connection string as the attach path.
	info.path = connection_string;

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

} // namespace

void Redshift::RegisterStorageExtension(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	StorageExtension::Register(config, "redshift", make_shared_ptr<RedshiftStorageExtension>());
}

} // namespace duckdb
