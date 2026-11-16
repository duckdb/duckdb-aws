#include "arn_storage.hpp"

#include "arn.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/extension_load_options.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/transaction_manager.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// ARN storage dispatch
//
// ATTACH 'arn:aws:<service>:...' without a TYPE goes to the storage type that serves the ARN's service, with the
// ARN as its path: the type reads region, account and resource off it. An explicit TYPE bypasses this and names the
// type directly, so `(TYPE redshift_postgres)` is this extension's own Redshift-over-Postgres backend, and
// `(TYPE redshift)` the redshift extension published at aws.amazon.com, which is also the default for the service.
// To add a service, add a row to ArnServices().
//===--------------------------------------------------------------------===//

struct ArnService {
	//! Storage type the ATTACH is handed to, with the ARN as its path
	string type;
	//! Autoload the extension of that name when the type is not registered (core extensions only); the types this
	//! extension registers itself are always there
	bool autoload = false;
	//! Options the type expects on top of the ARN, injected into the ATTACH; setting one explicitly is an error
	case_insensitive_map_t<Value> options;
};

static const case_insensitive_map_t<ArnService> &ArnServices() {
	static const case_insensitive_map_t<ArnService> services {
	    // The iceberg extension takes the full ARN as its warehouse, and reads endpoint_type
	    {"s3tables", ArnService {"iceberg", true, {{"endpoint_type", Value("s3_tables")}}}},
	    {"rds", ArnService {"rds", false, {}}},
	    {"redshift", ArnService {"redshift", false, {}}},
	    {"redshift-serverless", ArnService {"redshift", false, {}}},
	};
	return services;
}

static const ArnService &ResolveArnService(const ParsedArn &arn) {
	auto &services = ArnServices();
	auto entry = services.find(arn.service);
	if (entry == services.end()) {
		vector<string> names;
		for (auto &it : services) {
			names.push_back(it.first);
		}
		std::sort(names.begin(), names.end());
		throw NotImplementedException("ATTACH of AWS ARN service '%s' is not supported. Supported options are: %s",
		                              arn.service, StringUtil::Join(names, ", "));
	}
	return entry->second;
}

static ParsedArn GetArn(AttachedDatabase &db) {
	auto &original_path = db.GetOriginalPath();
	if (!original_path.has_value()) {
		throw InvalidInputException("ATTACH via the aws extension requires an ARN path");
	}
	return ParsedArn::Parse(*original_path);
}

static optional_ptr<StorageExtension> GetBackend(AttachedDatabase &db, const ArnService &service, const string &arn) {
	auto &instance = db.GetDatabase();
	if (service.autoload) {
		ExtensionHelper::AutoLoadExtension(instance, service.type);
	}
	auto backend = StorageExtension::Find(DBConfig::GetConfig(instance), service.type);
	if (!backend) {
		throw InvalidConfigurationException("the '%s' storage type is required to attach '%s'", service.type, arn);
	}
	return backend;
}

//! The ARN determines these options, so setting them in ATTACH is always an error, even to the same value.
//! Keys in info.options preserve the case the user typed, hence the case-insensitive scan.
static void ApplyServiceOptions(AttachInfo &info, AttachOptions &options, const ArnService &service) {
	for (auto &option : service.options) {
		for (auto &existing : info.options) {
			if (StringUtil::CIEquals(existing.first, option.first)) {
				throw InvalidInputException("ATTACH option '%s' is derived from the ARN and cannot be set explicitly",
				                            existing.first);
			}
		}
		info.options[option.first] = option.second;
		options.options[option.first] = option.second;
	}
}

static unique_ptr<Catalog> ArnAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                     AttachedDatabase &db, const string &name, AttachInfo &info,
                                     AttachOptions &options) {
	auto arn = GetArn(db);
	auto &service = ResolveArnService(arn);
	ApplyServiceOptions(info, options, service);
	// core read the type off the 'arn:' prefix and cut it from the path; the type reads the whole ARN
	info.path = arn.raw;

	auto backend = GetBackend(db, service, arn.raw);
	if (!backend->attach) {
		throw InvalidConfigurationException("the '%s' storage type does not support ATTACH", service.type);
	}
	return backend->attach(backend->storage_info.get(), context, db, name, info, options);
}

static unique_ptr<TransactionManager> ArnCreateTransactionManager(optional_ptr<StorageExtensionInfo> storage_info,
                                                                  AttachedDatabase &db, Catalog &catalog) {
	auto arn = GetArn(db);
	auto &service = ResolveArnService(arn);
	auto backend = GetBackend(db, service, arn.raw);
	if (!backend->create_transaction_manager) {
		throw InvalidConfigurationException("the '%s' storage type does not support transactions", service.type);
	}
	return backend->create_transaction_manager(backend->storage_info.get(), db, catalog);
}

class ArnStorageExtension : public StorageExtension {
public:
	ArnStorageExtension() {
		attach = ArnAttach;
		create_transaction_manager = ArnCreateTransactionManager;
	}
};

//===--------------------------------------------------------------------===//
// A storage type served by an extension from a repository host
//
// `TYPE redshift` names the redshift extension that aws.amazon.com publishes. Core's own autoload cannot reach it: a
// bare LOAD never resolves a user-provided repository, since its keys are not core's. So this extension registers
// the type as a stand-in that, when attached, requires the extension to be installed from that host (INSTALL redshift
// FROM aws.amazon.com), loads it from there, and hands the ATTACH to the type the extension registered under the same
// name - registering a type replaces the stand-in, so from then on the extension answers directly.
//===--------------------------------------------------------------------===//

//! What the stand-in stands for: the type it is registered as, the extension that really serves it, and the
//! repository host the extension has to be installed from
struct HostExtensionInfo : public StorageExtensionInfo {
	HostExtensionInfo(string type_name_p, string extension_name_p, string host_p)
	    : type_name(std::move(type_name_p)), extension_name(std::move(extension_name_p)), host(std::move(host_p)) {
	}

	string type_name;
	string extension_name;
	string host;

	//! Whether the registered type is still this stand-in
	bool IsSelf(optional_ptr<StorageExtension> registered) const {
		return registered && registered->storage_info.get() == this;
	}

	//! Whether `INSTALL <extension> FROM <host>` has been run: the installed file sits in the repository's own folder
	bool IsInstalled(DatabaseInstance &db) const {
		auto &fs = FileSystem::GetFileSystem(db);
		for (auto &directory : ExtensionHelper::GetExtensionDirectoryPath(db, fs)) {
			auto path = fs.JoinPath(fs.JoinPath(fs.JoinPath(directory, "repositories"), host),
			                        extension_name + ".duckdb_extension");
			if (fs.FileExists(path)) {
				return true;
			}
		}
		return false;
	}

	//! The type as the extension from the host registers it; loads the extension first when it is only installed
	optional_ptr<StorageExtension> Resolve(ClientContext &context, const string &path) const {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto &config = DBConfig::GetConfig(db);
		auto registered = StorageExtension::Find(config, type_name);
		if (registered && !IsSelf(registered)) {
			return registered;
		}
		if (!IsInstalled(db)) {
			throw MissingExtensionException(
			    "Attaching '%s' requires the '%s' extension from %s, which is not installed. Run `INSTALL %s FROM "
			    "%s;` first (and `CREATE EXTENSION REPOSITORY %s;` if that repository was not added yet), or use TYPE "
			    "%s_postgres for the Postgres-based attach of this extension",
			    path, extension_name, host, extension_name, host, host, extension_name);
		}
		ExtensionLoadOptions load_options;
		load_options.extension_name = extension_name;
		load_options.repository = host;
		ExtensionHelper::LoadExternalExtension(context, load_options);
		registered = StorageExtension::Find(config, type_name);
		if (!registered || IsSelf(registered)) {
			throw InvalidConfigurationException("The '%s' extension from %s was loaded but did not register a '%s' "
			                                    "storage type, so '%s' cannot be attached through it",
			                                    extension_name, host, type_name, path);
		}
		return registered;
	}
};

static unique_ptr<Catalog> HostAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                      AttachedDatabase &db, const string &name, AttachInfo &info,
                                      AttachOptions &options) {
	auto &self = dynamic_cast<HostExtensionInfo &>(*storage_info);
	auto backend = self.Resolve(context, info.path);
	if (!backend->attach) {
		throw InvalidConfigurationException("the '%s' storage type does not support ATTACH", self.type_name);
	}
	return backend->attach(backend->storage_info.get(), context, db, name, info, options);
}

static unique_ptr<TransactionManager> HostCreateTransactionManager(optional_ptr<StorageExtensionInfo> storage_info,
                                                                   AttachedDatabase &db, Catalog &catalog) {
	auto &self = dynamic_cast<HostExtensionInfo &>(*storage_info);
	// the attach loaded the extension, which registered the type: it is the one to answer now
	auto backend = StorageExtension::Find(DBConfig::GetConfig(db.GetDatabase()), self.type_name);
	if (!backend || self.IsSelf(backend) || !backend->create_transaction_manager) {
		throw InternalException("The '%s' storage type disappeared after attaching", self.type_name);
	}
	return backend->create_transaction_manager(backend->storage_info.get(), db, catalog);
}

class HostExtensionStorageExtension : public StorageExtension {
public:
	HostExtensionStorageExtension(string type_name, string extension_name, string host) {
		attach = HostAttach;
		create_transaction_manager = HostCreateTransactionManager;
		storage_info =
		    make_shared_ptr<HostExtensionInfo>(std::move(type_name), std::move(extension_name), std::move(host));
	}
};

void ArnStorage::RegisterStorageExtension(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	// Core derives the db type from the 'arn:' path prefix, so a bare
	// `ATTACH '<arn>'` looks for a storage type named 'arn'. Registering it here
	// serves that form without a core arn->aws extension alias.
	StorageExtension::Register(config, "arn", make_shared_ptr<ArnStorageExtension>());
	// `TYPE redshift`, and the default for redshift ARNs: the redshift extension from aws.amazon.com. Registering a
	// type replaces what is there, so the stand-in only goes in while nothing serves the type yet: when that extension
	// was loaded before this one, its registration stays
	if (!StorageExtension::Find(config, "redshift")) {
		auto redshift = make_shared_ptr<HostExtensionStorageExtension>("redshift", "redshift", "aws.amazon.com");
		StorageExtension::Register(config, "redshift", std::move(redshift));
	}
}

} // namespace duckdb
