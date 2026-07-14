#include "rds/rds_utils.hpp"

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
struct RdsAttachOptions {
	string secret_name;
	string region;
	string db_name;
	string host;
	string port;
	string user;
};

RdsAttachOptions ParseAttachOptions(AttachOptions &options) {
	RdsAttachOptions parsed;
	// Consumed options are erased, since postgres throws on any option it does not recognize.
	for (auto it = options.options.begin(); it != options.options.end();) {
		auto key = StringUtil::Lower(it->first);
		auto value = it->second.ToString();
		if (key == "secret") {
			// Left in place: postgres looks the secret up by name, and it must find one. See the
			// note in RdsAttach.
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
		} else if (key == "user") {
			parsed.user = value;
		} else {
			it++;
			continue;
		}
		it = options.options.erase(it);
	}
	return parsed;
}

//! `ATTACH '<db-instance-id>' AS db (TYPE rds, SECRET <aws-or-s3-secret>)`.
//!
//! The DB instance identifier is all the user gives us, so we ask RDS for the rest:
//! DescribeDBInstances - the API behind `aws rds describe-db-instances --db-instance-identifier` -
//! supplies the endpoint host/port, the engine and the default database name, and an IAM auth
//! token signed with the AWS identity behind the secret serves as the database password. Those are
//! assembled into a libpq connection string and handed to the postgres extension's own attach.
//!
//! Only the Postgres-flavored engines can be attached this way; every other engine (MySQL,
//! MariaDB, Oracle, ...) is rejected up front.
unique_ptr<Catalog> RdsAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                              AttachedDatabase &db, const string &name, AttachInfo &info, AttachOptions &options) {
	if (!Settings::Get<EnableExternalAccessSetting>(context)) {
		throw PermissionException("Attaching RDS databases is disabled through configuration");
	}

	auto instance_id = info.path;
	if (instance_id.empty()) {
		throw BinderException("No RDS DB instance identifier given. Pass it as the ATTACH path, e.g. "
		                      "ATTACH '<db-instance-id>' AS db (TYPE rds)");
	}

	auto attach_options = ParseAttachOptions(options);
	auto secret_entry = FindAwsSecret(context, attach_options.secret_name);
	const auto &secret = dynamic_cast<const KeyValueSecret &>(*secret_entry->secret);

	// An s3 secret's region is the bucket region, which need not be the instance's, so an explicit
	// ATTACH region wins over it. Past those two, fall back to the sources CREATE SECRET uses.
	auto explicit_region = attach_options.region.empty() ? GetSecretString(secret, "region") : attach_options.region;
	auto region = ResolveAwsRegion(context, explicit_region, "");
	if (region.empty()) {
		throw InvalidConfigurationException("No AWS region found for the RDS instance. Pass it to ATTACH, e.g. "
		                                    "ATTACH '<db-instance-id>' AS db (TYPE rds, REGION '<region>'), set it on "
		                                    "the secret, or configure the AWS_REGION environment variable");
	}

	auto provider = CredentialsProviderFromSecret(secret, "RDS");
	auto instance = Rds::DescribeDBInstance(provider, instance_id, region);

	// RDS runs engines DuckDB cannot speak to; only the Postgres ones have an extension to hand off
	// to. MySQL/MariaDB instances would need the mysql extension, which does not take a connection
	// string in the shape we build below.
	if (!RdsEngineIsPostgres(instance.engine)) {
		throw NotImplementedException("RDS instance '%s' runs the '%s' engine, which cannot be attached. Only the "
		                              "Postgres engines ('postgres', 'aurora-postgresql') are supported",
		                              instance_id, instance.engine);
	}

	// Resolved after the engine check, so an unsupported engine does not first demand postgres.
	auto postgres_extension = RequirePostgresStorageExtension(context, "an RDS instance");

	// Anything ATTACH pins explicitly wins over what the instance reports.
	auto host = attach_options.host.empty() ? instance.endpoint_address : attach_options.host;
	auto db_name = attach_options.db_name.empty() ? instance.db_name : attach_options.db_name;
	if (db_name.empty()) {
		// An instance created without an initial database reports none, and libpq then defaults
		// dbname to the *user* name, which is never a database that exists here. Every Postgres
		// engine provisions 'postgres', and the engine check above has established this is one.
		db_name = "postgres";
	}

	auto port = instance.endpoint_port;
	if (!attach_options.port.empty()) {
		try {
			port = std::stoi(attach_options.port);
		} catch (const std::exception &) {
			throw InvalidInputException("'PORT' must be an integer, got '%s'", attach_options.port);
		}
	}

	// Unlike Redshift, RDS does not mint the user along with the password: the IAM token is issued
	// *for* a database user that must already exist. The instance's master user is the only one we
	// can guess at, so anything else has to be named explicitly.
	auto user = attach_options.user.empty() ? instance.master_username : attach_options.user;
	if (user.empty()) {
		throw InvalidConfigurationException("No database user to connect to RDS instance '%s' as, and the instance "
		                                    "reports no master username. Pass one to ATTACH, e.g. ATTACH '%s' AS db "
		                                    "(TYPE rds, USER '<db-user>')",
		                                    instance_id, instance_id);
	}

	// The token is only accepted when the instance has IAM database authentication turned on, and
	// the failure it produces otherwise is an opaque password-authentication error.
	if (!instance.iam_auth_enabled) {
		throw InvalidConfigurationException(
		    "RDS instance '%s' does not have IAM database authentication enabled, so its AWS identity cannot be used "
		    "to log in. Enable it on the instance (`aws rds modify-db-instance --db-instance-identifier %s "
		    "--enable-iam-database-authentication`) and grant the 'rds_iam' role to database user '%s'",
		    instance_id, instance_id, user);
	}

	// The token is signed for a specific host/port/user triple, so it has to be minted from the
	// endpoint we are about to connect to rather than the one the instance reported.
	auto token = Rds::GenerateAuthToken(provider, host, port, region, user);

	// RDS rejects an IAM login over an unencrypted connection.
	string connection_string = "host=" + EscapeConnectionValue(host) +
	                           " port=" + EscapeConnectionValue(to_string(port)) +
	                           " user=" + EscapeConnectionValue(user) + " password=" + EscapeConnectionValue(token) +
	                           " sslmode='require'" + " dbname=" + EscapeConnectionValue(db_name);

	// Hand the postgres extension a plain connection string as the attach path.
	info.path = connection_string;

	// Postgres must be given a secret name it can resolve: with none it falls back to the implicit
	// '__default_postgres' secret, which it probes in the 'local_file' storage - and that throws
	// outright when persistent secrets are disabled. Naming the aws/s3 secret we just used is safe,
	// because postgres only harvests libpq option names (host, port, user, ...) from a secret and
	// an aws/s3 secret holds none of them.
	options.options["secret"] = Value(secret.GetName().GetIdentifierName());

	return postgres_extension->attach(postgres_extension->storage_info.get(), context, db, name, info, options);
}

unique_ptr<TransactionManager> RdsCreateTransactionManager(optional_ptr<StorageExtensionInfo> storage_info,
                                                           AttachedDatabase &db, Catalog &catalog) {
	// RdsAttach returned a PostgresCatalog, so the transaction manager has to come from the same
	// place. Attach has already established that the postgres extension is loaded.
	auto &db_config = DBConfig::GetConfig(db.GetDatabase());
	auto postgres_extension = FindPostgresStorageExtension(db_config);
	if (!postgres_extension || !postgres_extension->create_transaction_manager) {
		throw InternalException("RDS attach: the postgres storage extension disappeared after attaching");
	}
	return postgres_extension->create_transaction_manager(postgres_extension->storage_info.get(), db, catalog);
}

class RdsStorageExtension : public StorageExtension {
public:
	RdsStorageExtension() {
		attach = RdsAttach;
		create_transaction_manager = RdsCreateTransactionManager;
	}
};

} // namespace

void Rds::RegisterStorageExtension(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	StorageExtension::Register(config, "rds", make_shared_ptr<RdsStorageExtension>());
}

} // namespace duckdb
