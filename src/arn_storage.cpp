#include "arn_storage.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/exception.hpp"
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
// ATTACH 'arn:aws:<service>:...' dispatches to the storage backend serving the
// ARN's service. To add a service, register a handler in ArnServiceHandlers().
//===--------------------------------------------------------------------===//

//! arn:<partition>:<service>:<region>:<account>:<resource>
struct ParsedArn {
	string raw;
	string partition;
	string service;
	string region;
	string account_id;
	//! Everything after the 5th ':', may itself contain ':' or '/'
	string resource;
};

struct ArnTarget {
	//! Storage extension the ATTACH is dispatched to
	string backend;
	string path;
	//! Injected into AttachInfo::options and the already-bound AttachOptions
	case_insensitive_map_t<Value> options;
	//! False when the backend ships in this same aws extension
	bool autoload = true;
};

using arn_handler_t = ArnTarget (*)(const ParsedArn &);

static ParsedArn ParseArn(const string &arn) {
	string fields[5];
	idx_t field = 0;
	idx_t start = 0;
	//! NOTE: we can't use StringUtil::Split because it doesn't keep empty items
	for (idx_t i = 0; i < arn.size() && field < 5; i++) {
		if (arn[i] == ':') {
			fields[field++] = arn.substr(start, i - start);
			start = i + 1;
		}
	}
	if (field < 5 || fields[0] != "arn") {
		throw InvalidInputException(
		    "Expected an AWS ARN of the form 'arn:<partition>:<service>:<region>:<account>:<resource>', got '%s'", arn);
	}

	ParsedArn result;
	result.raw = arn;
	result.partition = fields[1];
	if (result.partition.empty()) {
		throw InvalidInputException("Invalid PARTITION Section of ARN: '%s'", result.partition);
	}
	// All valid service identifiers are lowercase,
	// let's be helpful and lowercase instead of throwing an error for non-lowercase service components.
	result.service = StringUtil::Lower(fields[2]);
	result.region = fields[3];
	result.account_id = fields[4];
	result.resource = arn.substr(start);
	return result;
}

//! The iceberg extension takes the full ARN as its warehouse, and reads endpoint_type
static ArnTarget S3TablesTarget(const ParsedArn &arn) {
	ArnTarget target;
	target.backend = "iceberg";
	target.path = arn.raw;
	target.options["endpoint_type"] = Value("s3_tables");
	return target;
}

static string RdsInstanceId(const ParsedArn &arn) {
	static const string prefix = "db:";
	if (!StringUtil::StartsWith(arn.resource, prefix) || arn.resource.size() == prefix.size()) {
		throw InvalidInputException("Expected an RDS DB instance ARN with a resource of the form 'db:<instance-id>', "
		                            "got '%s'",
		                            arn.raw);
	}
	return arn.resource.substr(prefix.size());
}

//! RDS owns DB-instance discovery and delegates to the backend for the instance's engine.
static ArnTarget RDSTarget(const ParsedArn &arn) {
	if (arn.region.empty()) {
		throw InvalidInputException("RDS DB instance ARN '%s' does not specify a region", arn.raw);
	}

	ArnTarget target;
	target.backend = "rds";
	target.path = RdsInstanceId(arn);
	target.options["region"] = Value(arn.region);
	target.autoload = false;
	return target;
}

static string RedshiftNamespaceResource(const ParsedArn &arn) {
	static const string prefix = "namespace:";
	if (!StringUtil::StartsWith(arn.resource, prefix) || arn.resource.size() == prefix.size()) {
		throw InvalidInputException(
		    "Expected a Redshift namespace ARN with a resource of the form 'namespace:<namespace-id>', got '%s'",
		    arn.raw);
	}
	return arn.resource;
}

static ArnTarget RedshiftTarget(const ParsedArn &arn) {
	if (arn.region.empty()) {
		throw InvalidInputException("Redshift namespace ARN '%s' does not specify a region", arn.raw);
	}
	if (arn.account_id.empty()) {
		throw InvalidInputException("Redshift namespace ARN '%s' does not specify an account ID", arn.raw);
	}

	ArnTarget target;
	target.backend = "redshift";
	target.path = RedshiftNamespaceResource(arn);
	target.options["region"] = Value(arn.region);
	target.options["account_id"] = Value(arn.account_id);
	target.options["resource"] = Value(arn.resource);
	target.autoload = false;
	return target;
}

static const case_insensitive_map_t<arn_handler_t> &ArnServiceHandlers() {
	static const case_insensitive_map_t<arn_handler_t> handlers {
	    {"s3tables", S3TablesTarget},
	    {"rds", RDSTarget},
	    {"redshift", RedshiftTarget},
	};
	return handlers;
}

static ArnTarget ResolveArnTarget(const ParsedArn &arn) {
	auto &handlers = ArnServiceHandlers();
	auto entry = handlers.find(arn.service);
	if (entry == handlers.end()) {
		vector<string> services;
		for (auto &it : handlers) {
			services.push_back(it.first);
		}
		std::sort(services.begin(), services.end());
		auto supported_options = StringUtil::Join(services, ", ");
		throw NotImplementedException("ATTACH of AWS ARN service '%s' is not supported. Supported options are: %s",
		                              arn.service, supported_options);
	}
	return entry->second(arn);
}

static ParsedArn GetArn(AttachedDatabase &db) {
	auto &original_path = db.GetOriginalPath();
	if (!original_path.has_value()) {
		throw InvalidInputException("ATTACH via the aws extension requires an ARN path");
	}
	return ParseArn(*original_path);
}

static optional_ptr<StorageExtension> GetBackend(AttachedDatabase &db, const ArnTarget &target, const string &arn) {
	auto &instance = db.GetDatabase();
	if (target.autoload) {
		ExtensionHelper::AutoLoadExtension(instance, target.backend);
	}
	auto backend = StorageExtension::Find(DBConfig::GetConfig(instance), target.backend);
	if (!backend) {
		throw InvalidConfigurationException("the '%s' extension is required to attach '%s'", target.backend, arn);
	}
	return backend;
}

//! The ARN determines these options, so setting them in ATTACH is always an error, even to the same value.
//! Keys in info.options preserve the case the user typed, hence the case-insensitive scan.
static void ApplyTargetOptions(AttachInfo &info, AttachOptions &options, const ArnTarget &target) {
	for (auto &option : target.options) {
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
	auto target = ResolveArnTarget(arn);

	info.path = target.path;
	ApplyTargetOptions(info, options, target);

	auto backend = GetBackend(db, target, arn.raw);
	if (!backend->attach) {
		throw InvalidConfigurationException("the '%s' extension does not support ATTACH", target.backend);
	}
	return backend->attach(backend->storage_info.get(), context, db, name, info, options);
}

static unique_ptr<TransactionManager> ArnCreateTransactionManager(optional_ptr<StorageExtensionInfo> storage_info,
                                                                  AttachedDatabase &db, Catalog &catalog) {
	auto arn = GetArn(db);
	auto target = ResolveArnTarget(arn);
	auto backend = GetBackend(db, target, arn.raw);
	if (!backend->create_transaction_manager) {
		throw InvalidConfigurationException("the '%s' extension does not support transactions", target.backend);
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

void ArnStorage::RegisterStorageExtension(ExtensionLoader &loader) {
	auto arn_storage = make_shared_ptr<ArnStorageExtension>();
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	// Core derives the db type from the 'arn:' path prefix, so a bare
	// `ATTACH '<arn>'` looks for a storage type named 'arn'. Registering it here
	// serves that form without a core arn->aws extension alias.
	StorageExtension::Register(config, "arn", arn_storage);
}

} // namespace duckdb
