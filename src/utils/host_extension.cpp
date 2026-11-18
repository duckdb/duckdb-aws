#include "utils/host_extension.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/extension_install_info.hpp"
#include "duckdb/main/extension_load_options.hpp"
#include "duckdb/main/extension_repository_manager.hpp"

namespace duckdb {

void HostExtension::RequireRepositoryIsTheHost(DatabaseInstance &db, const string &purpose) const {
	ExtensionRepository repository;
	if (!ExtensionRepositoryManager::TryGetRepository(db, FileSystem::GetFileSystem(db), host, repository)) {
		// nothing stored under the name: the install check says what to run
		return;
	}
	if (repository.host != host) {
		throw PermissionException(
		    "%s through the '%s' extension from %s is refused: the extension repository named "
		    "'%s' was added with a prefix ('%s'), not resolved from the host, so its signing keys "
		    "are not the host's. Drop it and run `CREATE EXTENSION REPOSITORY %s;` to add the "
		    "host's own repository",
		    purpose, extension_name, host, host, repository.path, host);
	}
}

bool HostExtension::IsInstalled(DatabaseInstance &db) const {
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

void HostExtension::Load(ClientContext &context, const string &purpose, const string &alternative) const {
	auto &db = DatabaseInstance::GetDatabase(context);
	RequireRepositoryIsTheHost(db, purpose);
	if (!IsInstalled(db)) {
		auto message =
		    StringUtil::Format("%s requires the '%s' extension from %s, which is not installed. Run `INSTALL "
		                       "%s FROM %s;` first (and `CREATE EXTENSION REPOSITORY %s;` if that repository "
		                       "was not added yet)",
		                       purpose, extension_name, host, extension_name, host, host);
		if (!alternative.empty()) {
			message += ", or " + alternative;
		}
		throw MissingExtensionException(message);
	}
	ExtensionLoadOptions load_options;
	load_options.extension_name = extension_name;
	load_options.repository = host;
	ExtensionHelper::LoadExternalExtension(context, load_options);
}

} // namespace duckdb
