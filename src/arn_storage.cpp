#include "arn_storage.hpp"

#include "arn.hpp"
#include "redshift/redshift_utils.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "utils/host_extension.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/transaction_manager.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// ARN storage dispatch
//
// ATTACH 'arn:aws:<service>:...' without a TYPE goes to the storage type that serves the ARN's service, with the
// ARN as its path: the type reads region, account and resource off it. A service may instead resolve the ARN into a
// path its type serves (ArnService::resolve): the redshift ARNs that name their target by ID become the target's
// redshift:// endpoint. An explicit TYPE bypasses this and names the type directly, so `(TYPE redshift_postgres)` is
// this extension's own Redshift-over-Postgres backend, and
// `(TYPE redshift)` the redshift extension published at aws.amazon.com, which is also the default for the service.
// To add a service, add a row to ArnServices().
//===--------------------------------------------------------------------===//

struct ArnService {
	//! Storage type the ATTACH is handed to, with the ARN as its path, or the path `resolve` made of it
	string type;
	//! Autoload the extension of that name when the type is not registered (core extensions only); the types this
	//! extension registers itself are always there
	bool autoload = false;
	//! Options the type expects on top of the ARN, injected into the ATTACH; setting one explicitly is an error
	case_insensitive_map_t<Value> options;
	//! Optional. For an ARN the type cannot serve as given, rewrites the ATTACH's path and options into a form it
	//! serves. ArnAttach calls it after loading the type and before handing the ATTACH on; it leaves any ARN the
	//! type serves itself untouched
	void (*resolve)(ClientContext &context, const ParsedArn &arn, AttachInfo &info, AttachOptions &options) = nullptr;
};

static const case_insensitive_map_t<ArnService> &ArnServices() {
	static const case_insensitive_map_t<ArnService> services {
	    // The iceberg extension takes the full ARN as its warehouse, and reads endpoint_type
	    {"s3tables", ArnService {"iceberg", true, {{"endpoint_type", Value("s3_tables")}}}},
	    {"rds", ArnService {"rds", false, {}}},
	    // The redshift extension makes no AWS call of its own, so it cannot turn a namespace or workgroup ID into
	    // the endpoint it names: for those ARNs, ResolveArnById looks the target up and hands the extension a
	    // redshift:// path to it instead (see redshift_storage.cpp)
	    {"redshift", ArnService {"redshift", false, {}, Redshift::ResolveArnById}},
	    {"redshift-serverless", ArnService {"redshift", false, {}, Redshift::ResolveArnById}},
	    {"athena", ArnService {"athena", false, {}}},
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

//! Loads the extension behind a stand-in type; defined below, after the stand-in (HostExtensionInfo)
static optional_ptr<StorageExtension> LoadHostExtension(ClientContext &context, StorageExtension &backend,
                                                        const string &path);

static unique_ptr<Catalog> ArnAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                     AttachedDatabase &db, const string &name, AttachInfo &info,
                                     AttachOptions &options) {
	auto arn = GetArn(db);
	auto &service = ResolveArnService(arn);
	ApplyServiceOptions(info, options, service);
	// core read the type off the 'arn:' prefix and cut it from the path; the type reads the whole ARN
	info.path = arn.raw;

	auto backend = GetBackend(db, service, arn.raw);
	if (service.resolve) {
		// Load the extension that serves the type before resolving: without it, the ATTACH fails on the missing
		// extension, as it does for every other ARN, before any AWS call is made
		backend = LoadHostExtension(context, *backend, arn.raw);
		service.resolve(context, arn, info, options);
	}
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
// Some types are served by extensions published through an extension repository, which core's autoload cannot reach.
// Each is registered as a stand-in that, when attached, loads the extension from its host and hands the ATTACH to the
// type the extension registered under the same name; from then on the extension answers directly.
//===--------------------------------------------------------------------===//

//! What the stand-in stands for: the type it is registered as, the extension from a host that really serves it, and
//! the other way to proceed, if any, named by the not-installed error
struct HostExtensionInfo : public StorageExtensionInfo {
	HostExtensionInfo(string type_name_p, string extension_name, string host, string alternative_p)
	    : type_name(std::move(type_name_p)), extension(std::move(extension_name), std::move(host)),
	      alternative(std::move(alternative_p)) {
	}

	string type_name;
	HostExtension extension;
	string alternative;

	//! Whether the registered type is still this stand-in
	bool IsSelf(optional_ptr<StorageExtension> registered) const {
		return registered && registered->storage_info.get() == this;
	}

	//! The type as the extension from the host registers it; loads the extension first when it is only installed
	optional_ptr<StorageExtension> Resolve(ClientContext &context, const string &path) const {
		auto &config = DBConfig::GetConfig(DatabaseInstance::GetDatabase(context));
		auto registered = StorageExtension::Find(config, type_name);
		if (registered && !IsSelf(registered)) {
			return registered;
		}
		extension.Load(context, StringUtil::Format("Attaching '%s'", path), alternative);
		registered = StorageExtension::Find(config, type_name);
		if (!registered || IsSelf(registered)) {
			throw InvalidConfigurationException("The '%s' extension from %s was loaded but did not register a '%s' "
			                                    "storage type, so '%s' cannot be attached through it",
			                                    extension.extension_name, extension.host, type_name, path);
		}
		return registered;
	}
};

//! Returns the type that will really serve the ATTACH, loading its extension first if needed.
//!
//! While the redshift extension is not loaded, `TYPE redshift` is the stand-in above: it loads the extension only
//! when HostAttach is handed the ATTACH. ArnAttach needs it loaded earlier, before a resolve function makes its AWS
//! calls: otherwise a user without the extension would pay for the lookup and could see a credentials error instead
//! of the one that says to install the extension. So for the stand-in this loads the extension now (or throws that
//! error) and returns the type the extension registered. Any other backend, including the redshift type once its
//! extension is loaded, is returned as it is.
static optional_ptr<StorageExtension> LoadHostExtension(ClientContext &context, StorageExtension &backend,
                                                        const string &path) {
	auto host = dynamic_cast<HostExtensionInfo *>(backend.storage_info.get());
	return host ? host->Resolve(context, path) : &backend;
}

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
	HostExtensionStorageExtension(string type_name, string extension_name, string host, string alternative) {
		attach = HostAttach;
		create_transaction_manager = HostCreateTransactionManager;
		storage_info = make_shared_ptr<HostExtensionInfo>(std::move(type_name), std::move(extension_name),
		                                                  std::move(host), std::move(alternative));
	}
};

//! Keeps the stand-in alive for as long as the database instance.
//!
//! Core holds the stand-in by raw pointer during an attach, and the type registry is its only owner. The stand-in's
//! attach loads the extension, which registers the real type under the same name and so frees the stand-in while
//! core still has to call create_transaction_manager on it. Holding a second reference here, in the callback
//! registry that lives with the database instance, keeps it valid.
class HostExtensionKeepAlive : public ExtensionCallback {
public:
	explicit HostExtensionKeepAlive(shared_ptr<StorageExtension> stand_in_p) : stand_in(std::move(stand_in_p)) {
	}

private:
	shared_ptr<StorageExtension> stand_in;
};

//! Registers `type` as a stand-in for the extension of the same name from `host`, unless something serves the type
//! already (the extension itself, when loaded before this one)
static void RegisterHostExtensionType(DBConfig &config, const string &type, const string &host,
                                      const string &alternative = string()) {
	if (StorageExtension::Find(config, type)) {
		return;
	}
	shared_ptr<StorageExtension> stand_in =
	    make_shared_ptr<HostExtensionStorageExtension>(type, type, host, alternative);
	ExtensionCallback::Register(config, make_shared_ptr<HostExtensionKeepAlive>(stand_in));
	StorageExtension::Register(config, type, std::move(stand_in));
}

void ArnStorage::RegisterStorageExtension(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	// Core derives the db type from the 'arn:' path prefix, so a bare
	// `ATTACH '<arn>'` looks for a storage type named 'arn'. Registering it here
	// serves that form without a core arn->aws extension alias.
	StorageExtension::Register(config, "arn", make_shared_ptr<ArnStorageExtension>());
	RegisterHostExtensionType(config, "redshift", "aws.amazon.com",
	                          "use TYPE redshift_postgres for the Postgres-based attach of this extension");
	RegisterHostExtensionType(config, "athena", "aws.amazon.com");
}

} // namespace duckdb
