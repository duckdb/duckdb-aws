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
	//! Injected into AttachInfo::options
	case_insensitive_map_t<Value> options;
	//! False when the backend ships in this same aws extension
	bool autoload = true;
};

using arn_handler_t = ArnTarget (*)(const ParsedArn &);

static ParsedArn ParseArn(const string &arn) {
	string fields[5];
	idx_t field = 0;
	idx_t start = 0;
	for (idx_t i = 0; i < arn.size() && field < 5; i++) {
		if (arn[i] == ':') {
			fields[field++] = arn.substr(start, i - start);
			start = i + 1;
		}
	}
	if (field < 5 || !StringUtil::CIEquals(fields[0], "arn")) {
		throw InvalidInputException(
		    "Expected an AWS ARN of the form 'arn:<partition>:<service>:<region>:<account>:<resource>', got '%s'", arn);
	}
	ParsedArn result;
	result.raw = arn;
	result.partition = fields[1];
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

static const case_insensitive_map_t<arn_handler_t> &ArnServiceHandlers() {
	static const case_insensitive_map_t<arn_handler_t> handlers {
	    {"s3tables", S3TablesTarget},
	};
	return handlers;
}

static ArnTarget ResolveArnTarget(const ParsedArn &arn) {
	auto &handlers = ArnServiceHandlers();
	auto entry = handlers.find(arn.service);
	if (entry == handlers.end()) {
		throw NotImplementedException("ATTACH of AWS ARN service '%s' is not supported", arn.service);
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

static unique_ptr<Catalog> ArnAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                     AttachedDatabase &db, const string &name, AttachInfo &info,
                                     AttachOptions &options) {
	auto arn = GetArn(db);
	auto target = ResolveArnTarget(arn);

	info.path = target.path;
	for (auto &option : target.options) {
		info.options[option.first] = option.second;
	}

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
	// 'aws' is the type name: `ATTACH '<arn>' (TYPE aws)`.
	StorageExtension::Register(config, "aws", arn_storage);
	// Core derives the db type from the 'arn:' path prefix, so a bare
	// `ATTACH '<arn>'` looks for a storage type named 'arn'. Registering it here
	// serves that form without a core arn->aws extension alias.
	StorageExtension::Register(config, "arn", arn_storage);
}

} // namespace duckdb
